const $ = (s) => document.querySelector(s);

function cell(text) { const td = document.createElement('td'); td.textContent = text; return td; }

async function loadPanel() {
  $('#setup').hidden = true;
  $('#panel').hidden = false;
  const { users } = await api('/api/creator/users');
  const rows = $('#rows');
  rows.replaceChildren();
  for (const u of users) {
    const tr = document.createElement('tr');
    tr.append(cell(u.username), cell(u.role), cell(u.credits));
    const td = document.createElement('td');
    const input = document.createElement('input');
    input.type = 'number'; input.step = '1'; input.placeholder = '+10';
    input.setAttribute('aria-label', 'Crédits à ajouter à ' + u.username);
    const btn = document.createElement('button');
    btn.type = 'button'; btn.textContent = 'Appliquer'; btn.className = 'ghost';
    btn.onclick = async () => {
      const m = $('#panelMsg');
      try {
        await api('/api/creator/credits', { userId: u.id, amount: Number(input.value) });
        m.className = 'msg ok'; m.textContent = 'Crédits mis à jour pour ' + u.username + '.';
        await loadPanel();
      } catch (err) { m.className = 'msg'; m.textContent = err.message; }
    };
    td.append(input, ' ', btn);
    tr.append(td);
    rows.append(tr);
  }
}

$('#setupForm').onsubmit = async (e) => {
  e.preventDefault();
  try {
    await api('/api/creator/setup', { key: $('#key').value });
    $('#key').value = '';
    await loadPanel();
  } catch (err) { $('#setupMsg').textContent = err.message; }
};

(async () => {
  let user = null;
  try { user = (await api('/api/me')).user; } catch (_) { /* non connecté */ }
  if (!user) { $('#needLogin').hidden = false; return; }
  if (user.role === 'creator') { await loadPanel(); return; }
  $('#setup').hidden = false;
})();
