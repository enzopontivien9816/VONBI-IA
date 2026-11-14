'use strict';
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieSession = require('cookie-session');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.SESSION_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error('SESSION_SECRET manquant ou trop court (16 caractères minimum).');
  process.exit(1);
}
const SETUP_KEY = process.env.CREATOR_SETUP_KEY || '';
const SIGNUP_CREDITS = 10;
const DAILY_CREDITS = 5;
const DAY_MS = 24 * 60 * 60 * 1000;

const DB_PATH = process.env.DB_PATH ||
  (fs.existsSync('/var/data') ? '/var/data/nova.db' : path.join(__dirname, 'data', 'nova.db'));
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
if (PROD && !DB_PATH.startsWith('/var/data')) {
  console.warn('ATTENTION : base hors disque persistant, les données seront perdues à chaque déploiement.');
}
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  credits INTEGER NOT NULL DEFAULT 0,
  last_daily INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  delta INTEGER NOT NULL,
  reason TEXT NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);`);

const getUser = db.prepare('SELECT * FROM users WHERE id = ?');
const getByName = db.prepare('SELECT * FROM users WHERE username = ?');
const addTx = db.prepare('INSERT INTO transactions(user_id, delta, reason) VALUES(?,?,?)');
const register = db.transaction((name, hash) => {
  const id = db.prepare('INSERT INTO users(username, password_hash, credits) VALUES(?,?,?)')
    .run(name, hash, SIGNUP_CREDITS).lastInsertRowid;
  addTx.run(id, SIGNUP_CREDITS, 'bienvenue');
  return id;
});
const spend = db.transaction((uid) => {
  const r = db.prepare('UPDATE users SET credits = credits - 1 WHERE id = ? AND credits >= 1').run(uid);
  if (!r.changes) return false;
  addTx.run(uid, -1, 'question IA');
  return true;
});
const refund = db.transaction((uid) => {
  db.prepare('UPDATE users SET credits = credits + 1 WHERE id = ?').run(uid);
  addTx.run(uid, 1, 'remboursement');
});
const claimDaily = db.transaction((uid) => {
  const u = getUser.get(uid);
  const wait = u.last_daily + DAY_MS - Date.now();
  if (wait > 0) return { ok: false, wait };
  db.prepare('UPDATE users SET credits = credits + ?, last_daily = ? WHERE id = ?')
    .run(DAILY_CREDITS, Date.now(), uid);
  addTx.run(uid, DAILY_CREDITS, 'bonus quotidien');
  return { ok: true };
});
const adjust = db.transaction((uid, amount) => {
  db.prepare('UPDATE users SET credits = MAX(0, credits + ?) WHERE id = ?').run(amount, uid);
  addTx.run(uid, amount, 'ajustement Créateur');
});

const DUMMY_HASH = bcrypt.hashSync('nova-dummy-password', 12);
const pub = (u) => ({ id: u.id, username: u.username, role: u.role, credits: u.credits });
const safeEq = (a, b) => crypto.timingSafeEqual(
  crypto.createHash('sha256').update(a).digest(),
  crypto.createHash('sha256').update(b).digest());

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { useDefaults: true, directives: { 'upgrade-insecure-requests': PROD ? [] : null } }
}));
app.use(express.json({ limit: '20kb' }));
app.use(cookieSession({
  name: 'nova', keys: [SECRET], httpOnly: true, sameSite: 'lax',
  secure: PROD, maxAge: 7 * DAY_MS
}));
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const o = req.get('origin');
  if (o) {
    try { if (new URL(o).host !== req.get('host')) throw 0; }
    catch { return res.status(403).json({ error: 'Origine refusée.' }); }
  }
  next();
});

const limiter = (windowMs, max) => rateLimit({
  windowMs, max, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Trop de tentatives. Réessayez plus tard.' }
});
const authLimiter = limiter(15 * 60 * 1000, 20);
const setupLimiter = limiter(15 * 60 * 1000, 5);
const askLimiter = limiter(60 * 1000, 15);

function auth(req, res, next) {
  const u = req.session && req.session.uid ? getUser.get(req.session.uid) : null;
  if (!u) { req.session = null; return res.status(401).json({ error: 'Connexion requise.' }); }
  req.user = u;
  next();
}
function creatorOnly(req, res, next) {
  if (req.user.role !== 'creator') return res.status(403).json({ error: 'Accès réservé au Créateur.' });
  next();
}
const readCreds = (body) => ({
  username: String((body && body.username) || '').trim(),
  password: String((body && body.password) || '')
});

app.get('/healthz', (req, res) => res.send('ok'));

app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = readCreds(req.body);
  if (!/^[A-Za-z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ error: 'Pseudo : 3 à 20 caractères (lettres, chiffres, _).' });
  if (password.length < 8 || password.length > 72)
    return res.status(400).json({ error: 'Mot de passe : 8 à 72 caractères.' });
  try {
    const id = register(username, await bcrypt.hash(password, 12));
    req.session = { uid: id };
    res.status(201).json({ user: pub(getUser.get(id)) });
  } catch (e) {
    if (String(e.code).startsWith('SQLITE_CONSTRAINT')) return res.status(409).json({ error: 'Ce pseudo est déjà pris.' });
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = readCreds(req.body);
  const u = getByName.get(username);
  const ok = await bcrypt.compare(password, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok) return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect.' });
  req.session = { uid: u.id };
  res.json({ user: pub(u) });
});

app.post('/api/logout', (req, res) => { req.session = null; res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: pub(req.user) }));

app.post('/api/daily', auth, (req, res) => {
  const r = claimDaily(req.user.id);
  if (!r.ok) {
    const h = Math.ceil(r.wait / 3600000);
    return res.status(429).json({ error: `Bonus déjà pris. Revenez dans environ ${h} h.` });
  }
  res.json({ user: pub(getUser.get(req.user.id)) });
});

async function generateReply(prompt) {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error('IA non configurée : ajoutez ANTHROPIC_API_KEY dans les variables Render.');
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: process.env.AI_MODEL || 'claude-haiku-5-5', max_tokens: 800,
      messages: [{ role: 'user', content: prompt }]
    })
  });
  if (!r.ok) throw new Error('Le service IA a répondu avec une erreur (' + r.status + ').');
  const d = await r.json();
  return d.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
}

app.post('/api/ask', askLimiter, auth, async (req, res) => {
  const prompt = String((req.body && req.body.prompt) || '').trim();
  if (!prompt || prompt.length > 2000) return res.status(400).json({ error: 'Question : 1 à 2000 caractères.' });
  if (!spend(req.user.id)) return res.status(402).json({ error: 'Crédits insuffisants.' });
  try {
    const answer = await generateReply(prompt);
    res.json({ answer, user: pub(getUser.get(req.user.id)) });
  } catch (e) {
    refund(req.user.id);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/creator/setup', setupLimiter, auth, (req, res) => {
  if (!SETUP_KEY) return res.status(503).json({ error: 'CREATOR_SETUP_KEY non configurée sur le serveur.' });
  if (db.prepare("SELECT 1 FROM users WHERE role = 'creator'").get())
    return res.status(409).json({ error: 'Un Créateur existe déjà.' });
  if (!safeEq(String((req.body && req.body.key) || ''), SETUP_KEY))
    return res.status(403).json({ error: 'Clé incorrecte.' });
  db.prepare("UPDATE users SET role = 'creator' WHERE id = ?").run(req.user.id);
  res.json({ user: pub(getUser.get(req.user.id)) });
});

app.get('/api/creator/users', auth, creatorOnly, (req, res) => {
  res.json({
    users: db.prepare('SELECT id, username, role, credits, created_at FROM users ORDER BY id DESC LIMIT 500').all()
  });
});

app.post('/api/creator/credits', auth, creatorOnly, (req, res) => {
  const uid = Number(req.body && req.body.userId);
  const amount = Number(req.body && req.body.amount);
  if (!Number.isInteger(uid) || !Number.isInteger(amount) || amount === 0 || Math.abs(amount) > 100000)
    return res.status(400).json({ error: 'Montant invalide.' });
  if (!getUser.get(uid)) return res.status(404).json({ error: 'Utilisateur introuvable.' });
  adjust(uid, amount);
  res.json({ user: pub(getUser.get(uid)) });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Route introuvable.' }));
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Requête invalide.' });
  console.error(err);
  res.status(500).json({ error: 'Erreur serveur.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`NOVA IA démarré sur le port ${PORT} (base : ${DB_PATH})`));
