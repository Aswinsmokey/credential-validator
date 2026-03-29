// CSV / JSONL download triggers

function exportCSV(appId) {
  window.location.href = `/api/export/${appId}/csv`;
}

function exportJSONL(appId) {
  window.location.href = `/api/export/${appId}/jsonl`;
}
