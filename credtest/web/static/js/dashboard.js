// Card expand/collapse, config upload, recon triggers

let expandedCardId = null;

function toggleCard(appId) {
  const detail = document.getElementById(`detail-${appId}`);
  const chevron = document.getElementById(`chevron-${appId}`);

  if (detail.classList.contains('expanded')) {
    detail.classList.remove('expanded');
    detail.innerHTML = '';
    chevron.classList.remove('open');
    expandedCardId = null;
    return;
  }

  // Collapse any other expanded card
  if (expandedCardId !== null && expandedCardId !== appId) {
    const prev = document.getElementById(`detail-${expandedCardId}`);
    const prevChevron = document.getElementById(`chevron-${expandedCardId}`);
    if (prev) { prev.classList.remove('expanded'); prev.innerHTML = ''; }
    if (prevChevron) prevChevron.classList.remove('open');
  }

  loadCardDetail(appId);
  chevron.classList.add('open');
  expandedCardId = appId;
}

async function loadCardDetail(appId) {
  const detail = document.getElementById(`detail-${appId}`);
  if (!detail) return;
  detail.innerHTML = '<div style="padding:20px;color:var(--muted)">Loading…</div>';
  detail.classList.add('expanded');

  try {
    const resp = await fetch(`/app/${appId}`);
    if (!resp.ok) throw new Error(resp.statusText);
    const html = await resp.text();
    detail.innerHTML = html;
  } catch (e) {
    detail.innerHTML = `<div style="padding:20px;color:var(--red)">Failed to load: ${e.message}</div>`;
  }
}

// Config file upload
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('config-upload-input');
  if (input) {
    input.addEventListener('change', async () => {
      if (!input.files.length) return;
      const fd = new FormData();
      fd.append('file', input.files[0]);
      try {
        const resp = await fetch('/api/config/upload', { method: 'POST', body: fd });
        const data = await resp.json();
        if (!resp.ok) {
          showToast(`Config error: ${JSON.stringify(data.detail)}`, 'error');
        } else {
          showToast(`✓ Loaded ${data.count} target(s)`, 'success');
          setTimeout(() => location.reload(), 800);
        }
      } catch (e) {
        showToast(`Upload failed: ${e.message}`, 'error');
      }
      input.value = '';
    });
  }
});

async function reconOne(appId) {
  try {
    const resp = await fetch(`/api/recon/${appId}`, { method: 'POST' });
    const data = await resp.json();
    showToast(`⟳ Recon started for app #${appId}`, 'info');
  } catch (e) {
    showToast(`Recon failed: ${e.message}`, 'error');
  }
}

async function reconAll() {
  try {
    const resp = await fetch('/api/recon/all', { method: 'POST' });
    const data = await resp.json();
    showToast(`⟳ Recon started for ${data.count} target(s)`, 'info');
  } catch (e) {
    showToast(`Recon all failed: ${e.message}`, 'error');
  }
}

async function releaseHold(appId) {
  try {
    const resp = await fetch(`/api/hold/${appId}/release`, { method: 'POST' });
    const data = await resp.json();
    updateBadge(appId, 'ready');
    updateStatusDot(appId, 'ready');
    showToast(`✓ Hold released for app #${appId}`, 'success');
  } catch (e) {
    showToast(`Release failed: ${e.message}`, 'error');
  }
}

async function testAll() {
  const mode = prompt('Attack mode for all targets? (cluster_bomb / pitchfork / sniper / battering_ram)', 'cluster_bomb');
  if (!mode) return;
  try {
    const resp = await fetch('/api/test/all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_mode: mode, use_default_usernames: true, use_default_passwords: true }),
    });
    const data = await resp.json();
    showToast(`▶▶ Tests started for ${data.count} target(s)`, 'info');
  } catch (e) {
    showToast(`Test all failed: ${e.message}`, 'error');
  }
}

// Filter cards by status
function filterCards(status) {
  document.querySelectorAll('.app-card').forEach(card => {
    if (!status || card.dataset.status === status) {
      card.classList.remove('hidden');
    } else {
      card.classList.add('hidden');
    }
  });
}

// Search cards by name
function searchCards(query) {
  const q = query.toLowerCase();
  document.querySelectorAll('.app-card').forEach(card => {
    const name = (card.dataset.name || '').toLowerCase();
    card.classList.toggle('hidden', q.length > 0 && !name.includes(q));
  });
}
