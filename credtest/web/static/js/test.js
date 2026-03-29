// Attack config form, wordlist upload, launch/abort

function updateWordlistUI(appId) {
  const mode = document.getElementById(`mode-${appId}`)?.value;
  const multi = document.getElementById(`wl-multi-${appId}`);
  const single = document.getElementById(`wl-single-${appId}`);
  if (!multi || !single) return;

  if (mode === 'sniper' || mode === 'battering_ram') {
    multi.classList.add('hidden');
    single.classList.remove('hidden');
  } else {
    multi.classList.remove('hidden');
    single.classList.add('hidden');
  }
}

async function uploadWordlist(input, targetInputId) {
  if (!input.files.length) return;
  const fd = new FormData();
  fd.append('file', input.files[0]);
  try {
    const resp = await fetch('/api/wordlist/upload', { method: 'POST', body: fd });
    const data = await resp.json();
    const pathInput = document.getElementById(targetInputId);
    if (pathInput) pathInput.value = data.path;
    showToast(`✓ Wordlist uploaded: ${data.lines} lines`, 'success');
  } catch (e) {
    showToast(`Upload failed: ${e.message}`, 'error');
  }
}

function useDefault(inputId, type) {
  const el = document.getElementById(inputId);
  if (!el) return;
  el.value = type === 'usernames'
    ? 'credtest/wordlists/top_usernames.txt'
    : 'credtest/wordlists/top_passwords.txt';
}

async function startTest(appId) {
  const mode = document.getElementById(`mode-${appId}`)?.value || 'cluster_bomb';
  const startBtn = document.getElementById(`start-btn-${appId}`);
  const abortBtn = document.getElementById(`abort-btn-${appId}`);

  let body = { attack_mode: mode };

  if (mode === 'sniper' || mode === 'battering_ram') {
    body.wordlist = document.getElementById(`s-path-${appId}`)?.value || '';
  } else {
    body.username_wordlist = document.getElementById(`u-path-${appId}`)?.value || '';
    body.password_wordlist = document.getElementById(`p-path-${appId}`)?.value || '';
  }

  // Use defaults if paths empty
  if (!body.wordlist) body.use_default_passwords = true;
  if (!body.username_wordlist) body.use_default_usernames = true;
  if (!body.password_wordlist) body.use_default_passwords = true;

  try {
    const resp = await fetch(`/api/test/${appId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) {
      showToast(`Error: ${JSON.stringify(data.detail)}`, 'error');
      return;
    }
    // Store run_id for abort
    if (startBtn) { startBtn.disabled = true; startBtn.dataset.runId = data.run_id; }
    if (abortBtn) abortBtn.disabled = false;
    document.getElementById(`progress-${appId}`)?.style.setProperty('display', 'block');
    showToast(`▶ Test started (run #${data.run_id})`, 'info');
  } catch (e) {
    showToast(`Start test failed: ${e.message}`, 'error');
  }
}

async function abortTest(appId) {
  const startBtn = document.getElementById(`start-btn-${appId}`);
  const runId = startBtn?.dataset.runId;
  if (!runId) return;
  try {
    const resp = await fetch(`/api/test/${runId}/abort`, { method: 'POST' });
    const data = await resp.json();
    if (data.aborted) {
      showToast(`■ Test aborted (run #${runId})`, 'warn');
      const abortBtn = document.getElementById(`abort-btn-${appId}`);
      if (startBtn) startBtn.disabled = false;
      if (abortBtn) abortBtn.disabled = true;
    }
  } catch (e) {
    showToast(`Abort failed: ${e.message}`, 'error');
  }
}
