'use strict';
// Already logged in? Skip to app.
fetch('/api/auth/me').then(r => { if (r.ok) location.replace('/'); });

document.getElementById('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn    = document.getElementById('loginBtn');
  const errEl  = document.getElementById('loginError');
  btn.disabled = true;
  btn.textContent = '[ authenticating… ]';
  errEl.hidden = true;

  try {
    const resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        remember: document.getElementById('rememberMe').checked,
      }),
    });

    if (resp.ok) {
      location.replace('/');
    } else {
      const data = await resp.json().catch(() => ({}));
      errEl.textContent = '[!] ' + (data.detail || 'Authentication failed');
      errEl.hidden = false;
      btn.disabled = false;
      btn.textContent = '[ authenticate ]';
    }
  } catch (err) {
    errEl.textContent = '[!] Network error — is the server running?';
    errEl.hidden = false;
    btn.disabled = false;
    btn.textContent = '[ authenticate ]';
  }
});
