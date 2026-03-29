// WebSocket live result stream

let ws = null;
let wsReconnectDelay = 1000;

function connectWebSocket() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws/live`);

  ws.onopen = () => {
    wsReconnectDelay = 1000;
  };

  ws.onmessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }

    switch (msg.type) {
      case 'status':
        updateBadge(msg.app_id, msg.status);
        updateStatusDot(msg.app_id, msg.status);
        break;

      case 'progress':
        updateProgress(msg.app_id, msg.tested, msg.total, msg.successes);
        break;

      case 'result':
        if (msg.success) appendResultRow(msg.app_id, msg);
        break;

      case 'hold':
        updateBadge(msg.app_id, 'held');
        updateStatusDot(msg.app_id, 'held');
        showToast(`⏸ ${msg.app_id}: Hold — ${msg.reason}`, 'warn');
        break;

      case 'recon_complete':
        updateBadge(msg.app_id, msg.status);
        updateStatusDot(msg.app_id, msg.status);
        refreshExpandedCard(msg.app_id);
        showToast(`✓ Recon complete: app #${msg.app_id} → ${msg.status}`, 'success');
        break;

      case 'run_complete':
        updateBadge(msg.app_id, 'done');
        updateStatusDot(msg.app_id, 'done');
        showToast(`✓ Test done: app #${msg.app_id} — ${msg.successes} success / ${msg.tested} tested`, 'success');
        break;

      case 'error':
        updateBadge(msg.app_id, 'error');
        updateStatusDot(msg.app_id, 'error');
        showToast(`✗ Error app #${msg.app_id}: ${msg.msg}`, 'error');
        break;
    }
  };

  ws.onclose = () => {
    setTimeout(() => {
      wsReconnectDelay = Math.min(wsReconnectDelay * 1.5, 15000);
      connectWebSocket();
    }, wsReconnectDelay);
  };
}

function updateBadge(appId, status) {
  const badge = document.getElementById(`badge-${appId}`);
  if (!badge) return;
  badge.className = `badge badge-${status}`;
  badge.textContent = status.toUpperCase();
}

function updateStatusDot(appId, status) {
  const card = document.getElementById(`card-${appId}`);
  if (!card) return;
  const dot = card.querySelector('.status-dot');
  if (dot) {
    dot.className = `status-dot status-${status}`;
  }
  card.dataset.status = status;
}

function updateProgress(appId, tested, total, successes) {
  const section = document.getElementById(`progress-${appId}`);
  if (!section) return;
  section.style.display = 'block';
  const pct = total > 0 ? Math.round((tested / total) * 100) : 0;
  const fill = document.getElementById(`progress-fill-${appId}`);
  const text = document.getElementById(`progress-text-${appId}`);
  const sText = document.getElementById(`success-text-${appId}`);
  if (fill) fill.style.width = pct + '%';
  if (text) text.textContent = `${tested.toLocaleString()} / ${total.toLocaleString()}`;
  if (sText) sText.textContent = `${successes} found`;
}

function appendResultRow(appId, msg) {
  const tbody = document.getElementById(`results-body-${appId}`);
  if (!tbody) return;
  const row = document.createElement('tr');
  const statusClass = msg.success ? 'result-success' : 'result-failure';
  const statusText = msg.success ? `✅ ${msg.confidence?.toUpperCase() || 'SUCCESS'}` : '❌ FAIL';
  const signals = (msg.signals || []).slice(0, 2).join(', ');
  row.innerHTML = `
    <td>${escHtml(msg.username || '')}</td>
    <td>${escHtml(msg.password || '')}</td>
    <td class="${statusClass}">${statusText}</td>
    <td>${msg.score ?? '—'}</td>
    <td class="muted">${escHtml(signals)}</td>
  `;
  tbody.insertBefore(row, tbody.firstChild);
}

function refreshExpandedCard(appId) {
  const detail = document.getElementById(`detail-${appId}`);
  if (detail && detail.classList.contains('expanded')) {
    loadCardDetail(appId);
  }
}

function escHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

connectWebSocket();
