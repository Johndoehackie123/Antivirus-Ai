'use strict';

/* ============ API ============ */
async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (e) {}
    throw new Error(msg);
  }
  return res.json();
}

function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  document.getElementById('toastWrap').appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity 0.3s'; setTimeout(() => el.remove(), 300); }, 3500);
}

/* ============ Tabs ============ */
function goTo(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + tab));
  if (tab === 'dashboard') loadDashboard();
  if (tab === 'processes') refreshProcesses();
  if (tab === 'quarantine') loadQuarantine();
  if (tab === 'signatures') loadSignatures();
}
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => goTo(t.dataset.tab)));

/* ============ Clock ============ */
setInterval(() => {
  const d = new Date();
  document.getElementById('clockPill').textContent = d.toLocaleTimeString('en-US', { hour12: false });
}, 1000);

/* ============ SSE console ============ */
let consolePaused = false;
const consoleBuffer = [];
function connectSSE() {
  const es = new EventSource('/api/logs');
  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    consoleBuffer.push(ev);
    if (consoleBuffer.length > 500) consoleBuffer.shift();
    if (!consolePaused) renderConsole();
    handleEvent(ev);
  };
}
function handleEvent(ev) {
  if (ev.type === 'scan' && activeTab === 'scan') {
    // scan result already handled in flow
  }
  if (ev.type === 'guard') {
    loadDashboard();
    if (activeTab === 'scan') return;
  }
  if (ev.type === 'quarantine') {
    loadDashboard();
    if (activeTab === 'quarantine') loadQuarantine();
  }
  if (ev.type === 'system-scan') {
    pollSystemScan();
  }
  if (ev.type === 'signatures') {
    if (activeTab === 'signatures') loadSignatures();
  }
}
let activeTab = 'dashboard';
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => { activeTab = t.dataset.tab; }));

function renderConsole() {
  const box = document.getElementById('consoleLog');
  if (consolePaused) return;
  const filter = document.getElementById('consoleFilter').value;
  const lines = consoleBuffer
    .filter(e => !filter || e.type === filter)
    .slice(-200);
  box.innerHTML = lines.map(e => {
    const ts = new Date(e.ts).toLocaleTimeString('en-US', { hour12: false });
    let msg = '';
    if (e.type === 'scan') msg = `${e.name} → ${e.verdictLabel} (${e.score})` + (e.signatures && e.signatures.length ? ` · ${e.signatures.join(', ')}` : '');
    else if (e.type === 'guard') msg = `[${e.action}] ${e.file || ''} ${e.verdictLabel ? '→ ' + e.verdictLabel : ''}`;
    else if (e.type === 'quarantine') msg = `${e.action}: ${e.name || ''} (${e.verdictLabel || ''})`;
    else if (e.type === 'system-scan') msg = e.status === 'complete' ? `Scan complete: ${JSON.stringify(e.counts)}` : (e.status === 'progress' ? `${e.scanned}/${e.total} ${e.lastFile ? e.lastFile.path + ' → ' + e.lastFile.verdict : ''}` : JSON.stringify(e));
    else if (e.type === 'watch') msg = `${e.action}: ${e.name}`;
    else if (e.type === 'signatures') msg = `${e.action}: ${e.threat || e.hash}`;
    else if (e.type === 'test-files') msg = `generated ${e.kind}`;
    else msg = JSON.stringify(e).slice(0, 120);
    return `<div class="console-line"><span class="console-ts">${ts}</span><span class="console-type ${e.type}">${e.type}</span><span class="console-msg">${escapeHtml(msg)}</span></div>`;
  }).join('');
  box.scrollTop = box.scrollHeight;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ============ Dashboard ============ */
async function loadDashboard() {
  try {
    const st = await api('/api/stats');
    const grid = document.getElementById('statsGrid');
    const items = [
      ['Total Scans', st.scansTotal, 'blue'],
      ['Threats Blocked', (st.verdictCounts.suspicious || 0) + (st.verdictCounts.malicious || 0), 'red'],
      ['Quarantined', st.quarantined, 'amber'],
      ['Signatures', st.signatures, 'green'],
      ['Heuristic Rules', st.rules, 'blue'],
      ['Malicious (scans)', st.verdictCounts.malicious || 0, 'red'],
      ['Suspicious (scans)', st.verdictCounts.suspicious || 0, 'amber'],
      ['Clean (scans)', st.verdictCounts.clean || 0, 'green']
    ];
    grid.innerHTML = items.map(([label, val, cls]) =>
      `<div class="stat"><div class="stat-value ${cls}">${val}</div><div class="stat-label">${label}</div></div>`).join('');

    const g = st.guard;
    document.getElementById('dashGuardState').textContent = g.enabled ? 'ON' : 'OFF';
    document.getElementById('dashUptime').textContent = formatUptime(st.uptime);
    document.getElementById('shieldStatus').textContent = g.enabled ? 'GUARD ACTIVE' : 'SYSTEM PROTECTED';
    document.getElementById('shieldDetail').textContent = g.enabled
      ? `Real-time file guard is watching ${g.watchFolder} — scanning every ${g.intervalMs / 1000}s. Blocked: ${g.blocked}.`
      : 'Real-time guard is off. Turn it on to monitor the watch folder for new files.';
    document.getElementById('shieldRing').classList.toggle('alert', !g.enabled);

    const scans = await api('/api/scans');
    const box = document.getElementById('recentScans');
    if (!scans.scans.length) {
      box.innerHTML = '<div class="empty">No scans yet. Use “Upload &amp; Scan” or generate an EICAR test file.</div>';
    } else {
      box.innerHTML = `<table><tr><th>Time</th><th>File</th><th>Type</th><th>Verdict</th><th>Score</th><th>Signatures</th></tr>` +
        scans.scans.slice(0, 12).map(s => {
          const t = new Date(s.ts).toLocaleTimeString('en-US', { hour12: false });
          const sigs = s.signatures && s.signatures.length ? s.signatures.map(x => x.threat).join(', ') : '—';
          return `<tr><td class="mono">${t}</td><td>${escapeHtml(s.name)}<div class="scan-item-meta">${s.size || 0} B · ${escapeHtml(s.fileType || '')}</div></td><td class="mono">${s.fileType || '—'}</td><td><span class="badge ${s.verdict}">${s.verdictLabel}</span></td><td class="mono">${s.score}</td><td class="mono">${escapeHtml(sigs)}</td></tr>`;
        }).join('') + '</table>';
    }
  } catch (e) {
    console.error(e);
  }
}
function formatUptime(s) {
  s = Math.floor(s);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${sec}s` : `${sec}s`;
}

/* ============ Guard ============ */
async function toggleGuard() {
  try {
    const st = await api('/api/guard');
    const next = !st.enabled;
    const g = await api('/api/guard', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next })
    });
    document.getElementById('guardToggle').classList.toggle('on', g.enabled);
    document.getElementById('guardToggleText').textContent = g.enabled ? 'Guard ON' : 'Guard OFF';
    loadDashboard();
    toast('Real-time file guard ' + (g.enabled ? 'started — watching /watch' : 'stopped'));
  } catch (e) {
    toast('Guard toggle failed: ' + e.message, 'err');
  }
}

/* ============ Scan ============ */
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => { scanFiles(fileInput.files); fileInput.value = ''; });
['dragenter', 'dragover'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.add('drag'); }));
['dragleave', 'drop'].forEach(ev => dropzone.addEventListener(ev, e => { e.preventDefault(); dropzone.classList.remove('drag'); }));
dropzone.addEventListener('drop', e => scanFiles(e.dataTransfer.files));

async function scanFiles(fileList) {
  for (const file of fileList) {
    const item = createScanItem(file);
    try {
      const buf = await file.arrayBuffer();
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': file.name },
        body: buf
      });
      const result = await res.json();
      if (res.ok) {
        item.done(result);
      } else {
        item.fail(result.error || 'scan failed');
      }
    } catch (e) {
      item.fail(e.message);
    }
  }
}

function createScanItem(file) {
  const el = document.createElement('div');
  el.className = 'scan-item';
  el.innerHTML = `
    <div><div class="scan-item-name">${escapeHtml(file.name)}</div><div class="scan-item-meta">${(file.size / 1024).toFixed(1)} KB · scanning…</div></div>
    <div class="scan-item-status" style="margin-left:auto"><span class="badge low">SCANNING</span></div>`;
  document.getElementById('scanQueue').appendChild(el);
  return {
    done: (result) => {
      el.querySelector('.scan-item-status').innerHTML = `<span class="badge ${result.verdict}">${result.verdictLabel}</span> <button class="btn small" onclick="showResult('${result.scanId}')">Details</button>`;
      el.querySelector('.scan-item-meta').textContent = `${(file.size / 1024).toFixed(1)} KB · ${result.fileType} · ${result.durationMs} ms · ${result.rules.length} rules · score ${result.score}`;
      showResultPanel(result);
      loadDashboard();
    },
    fail: (msg) => {
      el.querySelector('.scan-item-status').innerHTML = `<span class="badge malicious">ERROR</span>`;
      el.querySelector('.scan-item-meta').textContent = msg;
    }
  };
}

async function showResult(scanId) {
  try {
    const s = await api('/api/scans/' + scanId);
    // reconstruct full result from history entry
    showResultPanel({ ...s.detail, ...s, hashes: s.detail ? s.detail.hashes : { md5: s.md5, sha256: s.sha256 } });
  } catch (e) { toast(e.message, 'err'); }
}

function showResultPanel(result) {
  window.lastPanelResult = result;
  document.getElementById('resultCard').style.display = '';
  const box = document.getElementById('resultContent');
  const sigs = (result.signatures || []).map(s =>
    `<div class="meta-cell"><div class="meta-key">${s.type} signature</div><div class="meta-val">${escapeHtml(s.threat)}</div><div class="meta-key">${escapeHtml(s.source || '')}</div></div>`).join('');

  const behaviors = (result.behaviors || []).map(b =>
    `<div class="behavior-chip"><span class="badge sev-${b.severity}">${b.severity}</span><span>${escapeHtml(b.name)}</span><span class="conf">${(b.confidence * 100).toFixed(0)}%</span></div>`).join('');

  const rules = (result.rules || []).map(r =>
    `<tr><td class="mono">${r.id}</td><td>${escapeHtml(r.name)}</td><td>${r.family}</td><td><span class="badge sev-${r.severity}">${r.severity}</span></td><td class="mono">+${r.weight}</td></tr>`).join('');

  const entropy = result.entropy ? result.entropy.toFixed(3) : '—';
  const hashes = result.hashes || {};
  const pe = result.pe || {};
  const elf = result.elf || {};

  box.innerHTML = `
    <div class="verdict-banner verdict-${result.verdict}">
      <span class="verdict-icon">${result.verdict === 'malicious' ? '🚨' : result.verdict === 'suspicious' ? '⚠️' : result.verdict === 'low' ? '🟡' : '✅'}</span>
      <span>${result.verdictLabel}${result.signatures && result.signatures.length ? ' — signature match' : ''}</span>
      <span style="margin-left:auto;font-size:14px;font-weight:600">Threat score: ${result.score}/100</span>
    </div>
    <div class="score-bar"><div class="score-fill" style="width:${result.score}%;background:${result.verdict === 'malicious' ? 'var(--red)' : result.verdict === 'suspicious' ? 'var(--amber)' : result.verdict === 'low' ? 'var(--text-dim)' : 'var(--green)'}"></div></div>

    ${sigs}
    <div class="meta-grid">
      <div class="meta-cell"><div class="meta-key">File</div><div class="meta-val">${escapeHtml(result.name)}</div></div>
      <div class="meta-cell"><div class="meta-key">Type</div><div class="meta-val">${escapeHtml(result.fileType || '—')} ${result.ext ? '.' + result.ext : ''}</div></div>
      <div class="meta-cell"><div class="meta-key">Size</div><div class="meta-val">${result.size} bytes</div></div>
      <div class="meta-cell"><div class="meta-key">Entropy</div><div class="meta-val">${entropy} bits/byte</div></div>
      <div class="meta-cell"><div class="meta-key">MD5</div><div class="meta-val hash-cell">${escapeHtml(hashes.md5 || '—')}</div></div>
      <div class="meta-cell"><div class="meta-key">SHA-256</div><div class="meta-val hash-cell">${escapeHtml(hashes.sha256 || '—')}</div></div>
    </div>

    <h3 style="margin:14px 0 8px;color:var(--accent);font-size:13px;letter-spacing:1px">Behavioral Profile (static analysis)</h3>
    <div class="behaviors">${behaviors || '<div class="empty">No suspicious behaviors detected.</div>'}</div>

    <h3 style="margin:14px 0 8px;color:var(--accent);font-size:13px;letter-spacing:1px">Detection Rules Matched (${(result.rules || []).length})</h3>
    ${rules ? `<table><tr><th>Rule</th><th>Name</th><th>Family</th><th>Severity</th><th>Weight</th></tr>${rules}</table>` : '<div class="empty">No rules matched.</div>'}

    <div style="margin-top:16px;display:flex;gap:10px">
      <button class="btn" onclick="openDetail('${result.scanId || 'panel'}', '${escapeHtml(result.name)}')">🔍 Full Analysis</button>
      ${result.verdict !== 'clean' && result.verdict !== 'low' ? '<span class="badge malicious">⚠ Auto-quarantined</span>' : ''}
      ${result.path ? `<button class="btn secondary" onclick="quarantinePath('${escapeHtml(result.path)}')">🚪 Quarantine</button>` : ''}
    </div>
    ${(result.notes || []).length ? `<div class="hint">${result.notes.map(escapeHtml).join('<br>')}</div>` : ''}
  `;
}

async function quarantinePath(p) {
  try {
    await api('/api/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: p })
    });
    toast('File quarantined: ' + p, 'ok');
    loadDashboard();
  } catch (e) { toast(e.message, 'err'); }
}

/* ============ Modal (full analysis) ============ */
async function openDetail(scanId, name) {
  let result = null;
  if (window.lastPanelResult && scanId === 'panel') {
    result = window.lastPanelResult;
  } else {
    const s = await api('/api/scans/' + scanId);
    result = s.detail ? { ...s.detail, ...s } : s;
  }
  window.lastPanelResult = result;
  const body = document.getElementById('modalBody');
  let html = '';

  html += `<div class="detail-section"><div class="detail-label">Hashes</div>`;
  const h = result.hashes || {};
  for (const k of ['md5', 'sha1', 'sha256', 'sha512']) {
    if (h[k]) html += `<div class="detail-value">${k}: ${escapeHtml(h[k])}</div>`;
  }
  html += '</div>';

  if (result.pe) {
    html += '<h3>PE Header</h3><div class="detail-section">';
    html += `<div class="detail-label">Machine / Subsystem</div><div class="detail-value">${escapeHtml(result.pe.machine)} · ${escapeHtml(result.pe.subsystem)}${result.pe.isDLL ? ' (DLL)' : ''}</div>`;
    html += `<div class="detail-label">Entry point / Image base</div><div class="detail-value">0x${(result.pe.entryPoint || 0).toString(16)} / 0x${(result.pe.imageBase || 0).toString(16)}</div>`;
    html += `<div class="detail-label">Authenticode signature</div><div class="detail-value">${result.pe.hasSignature ? 'present' : 'MISSING — not signed by a trusted publisher'}</div>`;
    html += `<div class="detail-label">Sections (${result.pe.sections.length})</div><div class="detail-value">${result.pe.sections.map(s => `${s.name}[${s.flags.join('')}] ent=${s.entropy != null ? s.entropy.toFixed(2) : '—'}`).join(' · ')}</div>`;
    html += '</div><h3>Imports</h3><div class="detail-section"><div class="detail-label">DLLs &amp; functions</div><div class="strings-box">' +
      result.pe.imports.map(i => `<div class="string-line"><b>${escapeHtml(i.dll)}</b> — ${i.functions.map(escapeHtml).join(', ')}</div>`).join('') +
      '</div></div>';
  }
  if (result.elf) {
    html += '<h3>ELF Header</h3><div class="detail-section">';
    html += `<div class="detail-label">Class / Machine / Type</div><div class="detail-value">${escapeHtml(result.elf.class)} · ${escapeHtml(result.elf.machine)} · ${escapeHtml(result.elf.typeName)}</div>`;
    html += `<div class="detail-label">Interpreter</div><div class="detail-value">${escapeHtml(result.elf.interp || '—')}</div>`;
    html += `<div class="detail-label">Dynamic libraries (${result.elf.needed.length})</div><div class="detail-value">${result.elf.needed.map(escapeHtml).join(', ')}</div>`;
    html += `<div class="detail-label">Sections</div><div class="detail-value">${result.elf.sections.map(s => `${s.name}[${s.flags.join('')}]`).join(' · ')}</div>`;
    html += '</div><h3>Dynamic Symbols</h3><div class="detail-section"><div class="strings-box">' +
      result.elf.symbols.map(s => `<div class="string-line">${escapeHtml(s)}</div>`).join('') +
      '</div></div>';
  }

  const str = result.strings || {};
  html += '<h3>Strings (sample)</h3><div class="detail-section">';
  html += `<div class="detail-label">ASCII: ${str.asciiCount || 0} · UTF-16: ${str.utf16Count || 0}${str.sampled ? ' · sampled' : ''}</div>`;
  html += '<div class="strings-box">' + (str.sample || []).map(s => `<div class="string-line">${escapeHtml(s)}</div>`).join('') + '</div>';
  html += '</div>';

  html += '<h3>Behaviors</h3><div class="detail-section">' +
    (result.behaviors || []).map(b => `<div class="string-line"><b>[${b.severity}]</b> ${escapeHtml(b.name)} — ${escapeHtml(b.description)}${b.evidence && b.evidence.length ? `<br><span style="color:var(--text-dim)">evidence: ${b.evidence.map(escapeHtml).join(' · ')}</span>` : ''}</div>`).join('') +
    '</div>';

  document.getElementById('modalTitle').textContent = 'Analysis: ' + result.name;
  document.getElementById('modalBody').innerHTML = html;
  document.getElementById('modalOverlay').style.display = 'flex';
}
function closeModal() { document.getElementById('modalOverlay').style.display = 'none'; }

/* ============ Test files ============ */
async function generateTestFile(kind) {
  try {
    const r = await api('/api/test-files', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind })
    });
    const f = r.files[0];
    toast(`Generated ${f.name} — click “Choose Files” to scan it, or scan it from the uploads folder`, 'ok');
    if (kind === 'eicar' || kind === 'pe') {
      // auto-scan the generated test file to show the detection immediately
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': f.name },
        body: await (await fetch('/uploads/' + f.name)).arrayBuffer()
      });
      const result = await res.json();
      if (res.ok) showResultPanel(result);
    }
    loadDashboard();
  } catch (e) { toast(e.message, 'err'); }
}

/* ============ System scan ============ */
async function startSystemScan() {
  const roots = document.getElementById('scanRoots').value.split(',').map(s => s.trim()).filter(Boolean);
  if (!roots.length) return toast('Add at least one scan root', 'err');
  document.getElementById('startSysScanBtn').disabled = true;
  document.getElementById('startSysScanBtn').textContent = '⏳ Scanning…';
  try {
    await api('/api/system-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ roots })
    });
    document.getElementById('sysProgressWrap').style.display = '';
    document.getElementById('sysVerdictSummary').style.display = '';
    document.getElementById('sysResults').innerHTML = '<div class="loading">Scanning…</div>';
    pollSystemScan();
  } catch (e) {
    toast(e.message, 'err');
    document.getElementById('startSysScanBtn').disabled = false;
    document.getElementById('startSysScanBtn').textContent = '▶ Start System Scan';
  }
}
let sysPollTimer = null;
function pollSystemScan() {
  if (sysPollTimer) clearTimeout(sysPollTimer);
  sysPollTimer = setTimeout(async () => {
    try {
      const st = await api('/api/system-scan');
      const pct = st.totalResults ? Math.min(100, (st.scanned / (st.scanned + (st.totalResults - st.scanned))) * 100) : 0;
      // estimate progress from counts
      document.getElementById('sysProgressBar').style.width = Math.min(99, Math.max(0, (st.scanned / Math.max(1, st.scanned + 50)) * 100)) + '%';
      document.getElementById('sysProgressLabel').textContent = `Scanned ${st.scanned} files · clean ${st.counts.clean || 0} · low ${st.counts.low || 0} · suspicious ${st.counts.suspicious || 0} · malicious ${st.counts.malicious || 0}`;
      document.getElementById('sysVerdictSummary').innerHTML = `
        <span class="badge clean">Clean ${st.counts.clean || 0}</span>
        <span class="badge low">Low ${st.counts.low || 0}</span>
        <span class="badge suspicious">Suspicious ${st.counts.suspicious || 0}</span>
        <span class="badge malicious">Malicious ${st.counts.malicious || 0}</span>
        ${st.truncated ? '<span class="badge low">Capped at 3,000 files</span>' : ''}`;
      renderSysResults(st);
      if (st.running) pollSystemScan();
      else {
        document.getElementById('startSysScanBtn').disabled = false;
        document.getElementById('startSysScanBtn').textContent = '▶ Start System Scan';
        document.getElementById('sysProgressBar').style.width = '100%';
        loadDashboard();
      }
    } catch (e) {
      document.getElementById('startSysScanBtn').disabled = false;
      document.getElementById('startSysScanBtn').textContent = '▶ Start System Scan';
    }
  }, 800);
}
let sysResultsCache = null;
function renderSysResults(st) {
  if (!st) st = sysResultsCache;
  if (!st) return;
  sysResultsCache = st;
  const filter = document.getElementById('sysFilter').value;
  let results = st.results || [];
  if (filter) results = results.filter(r => r.verdict === filter);
  const box = document.getElementById('sysResults');
  if (!results.length) {
    box.innerHTML = '<div class="empty">No matching results.</div>';
    return;
  }
  box.innerHTML = `<table><tr><th>Verdict</th><th>File</th><th>Path</th><th>Type</th><th>Score</th><th>Rules</th></tr>` +
    results.map(r => `<tr>
      <td><span class="badge ${r.verdict}">${r.verdictLabel}</span></td>
      <td>${escapeHtml(r.name)}</td>
      <td class="path-cell">${escapeHtml(r.path)}</td>
      <td class="mono">${r.fileType}</td>
      <td class="mono">${r.score}</td>
      <td class="mono">${r.rules.map(escapeHtml).join(', ') || '—'}</td>
    </tr>`).join('') + '</table>';
}

/* ============ Processes ============ */
let procTimer = null;
function toggleProcAuto() {
  if (procTimer) { clearInterval(procTimer); procTimer = null; }
  if (document.getElementById('procAutoRefresh').checked) {
    procTimer = setInterval(refreshProcesses, 5000);
  }
}
async function refreshProcesses() {
  try {
    const r = await api('/api/processes');
    const box = document.getElementById('procTable');
    box.innerHTML = `<table><tr><th>PID</th><th>Process</th><th>Path</th><th>Verdict</th><th>Score</th><th>Rules / Behaviors</th></tr>` +
      r.processes.map(p => `<tr>
        <td class="mono">${p.pid}</td>
        <td>${escapeHtml(p.name)}<div class="scan-item-meta">${escapeHtml(p.cmdline || '').slice(0, 80)}</div></td>
        <td class="path-cell">${escapeHtml(p.exePath || '—')}</td>
        <td><span class="badge ${p.label === 'CLEAN' ? 'clean' : p.label === 'SUSPICIOUS' ? 'suspicious' : p.label === 'MALICIOUS' ? 'malicious' : p.label === 'LOW RISK' ? 'low' : 'low'}">${escapeHtml(p.label)}</span></td>
        <td class="mono">${p.score != null ? p.score : '—'}</td>
        <td class="mono">${(p.rules || []).concat(p.behaviors || []).slice(0, 3).map(escapeHtml).join(', ') || (p.status === 'unavailable' ? 'n/a' : '—')}</td>
      </tr>`).join('') + '</table>';
  } catch (e) {
    document.getElementById('procTable').innerHTML = '<div class="empty">' + escapeHtml(e.message) + '</div>';
  }
}

/* ============ Quarantine ============ */
async function loadQuarantine() {
  try {
    const r = await api('/api/quarantine');
    document.getElementById('quarantineCount').textContent = `(${r.entries.length})`;
    const box = document.getElementById('quarantineList');
    if (!r.entries.length) {
      box.innerHTML = '<div class="empty">Quarantine is empty. Flagged files are moved here automatically.</div>';
      return;
    }
    box.innerHTML = r.entries.map(e => `
      <div class="scan-item">
        <div>
          <div class="scan-item-name">${escapeHtml(e.name)}</div>
          <div class="scan-item-meta">${escapeHtml(e.originalPath)} · ${(e.size / 1024).toFixed(1)} KB · ${escapeHtml(e.reason || '')}</div>
          <div class="scan-item-meta mono">${escapeHtml(e.sha256 || '')}</div>
          <div class="scan-item-meta">Rules: ${(e.rules || []).map(x => x.name).join(', ') || '—'}</div>
        </div>
        <div class="scan-item-status" style="margin-left:auto">
          <span class="badge ${e.verdict}">${e.verdictLabel}</span>
          <button class="btn small" onclick="restoreQuarantine('${e.id}')">♻️ Restore</button>
          <button class="btn small" onclick="deleteQuarantine('${e.id}')">🗑️ Delete</button>
        </div>
      </div>`).join('');
  } catch (e) { toast(e.message, 'err'); }
}
async function restoreQuarantine(id) {
  try {
    await api('/api/quarantine/restore', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id })
    });
    toast('File restored to original location', 'ok');
    loadQuarantine();
  } catch (e) { toast(e.message, 'err'); }
}
async function deleteQuarantine(id) {
  try {
    await api('/api/quarantine/delete', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id })
    });
    toast('Quarantined file deleted', 'ok');
    loadQuarantine();
  } catch (e) { toast(e.message, 'err'); }
}

/* ============ Signatures ============ */
let sigData = null;
async function loadSignatures() {
  try {
    if (!sigData) sigData = await api('/api/signatures');
    const db = sigData.db;
    document.getElementById('dbStats').innerHTML = `
      <div class="meta-grid">
        <div class="meta-cell"><div class="meta-key">Version</div><div class="meta-val">${db.version}</div></div>
        <div class="meta-cell"><div class="meta-key">Updated</div><div class="meta-val">${new Date(db.updated).toLocaleString()}</div></div>
        <div class="meta-cell"><div class="meta-key">Hash signatures</div><div class="meta-val">${db.total}</div></div>
        <div class="meta-cell"><div class="meta-key">MD5 / SHA1 / SHA256</div><div class="meta-val">${db.byType.MD5 || 0} / ${db.byType.SHA1 || 0} / ${db.byType.SHA256 || 0}</div></div>
      </div>`;
    document.getElementById('dbSource').textContent = db.description;
    document.getElementById('sigCount').textContent = sigData.signatures.length;
    document.getElementById('signaturesTable').innerHTML = `<table><tr><th>Type</th><th>Hash</th><th>Threat</th><th>Source</th></tr>` +
      sigData.signatures.map(s => `<tr><td class="mono">${s.type}</td><td class="mono" style="font-size:11px">${escapeHtml(s.hash)}</td><td>${escapeHtml(s.threat)}</td><td class="mono" style="font-size:10px">${escapeHtml(s.source)}</td></tr>`).join('') + '</table>';
    renderRules();
  } catch (e) { toast(e.message, 'err'); }
}
async function addSignature() {
  const hash = document.getElementById('sigHashInput').value.trim();
  const threat = document.getElementById('sigThreatInput').value.trim();
  if (!hash) return toast('Enter a hash', 'err');
  try {
    const r = await api('/api/signatures/hash', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ hash, threat })
    });
    toast(`Signature added — DB now has ${r.total} signatures`, 'ok');
    document.getElementById('sigHashInput').value = '';
    document.getElementById('sigThreatInput').value = '';
    sigData = null;
    loadSignatures();
    loadDashboard();
  } catch (e) { toast(e.message, 'err'); }
}
function renderRules() {
  if (!sigData) return;
  const filter = (document.getElementById('ruleFilter').value || '').toLowerCase();
  const rules = sigData.rules.filter(r => !filter || r.id.toLowerCase().includes(filter) || r.name.toLowerCase().includes(filter) || r.family.toLowerCase().includes(filter));
  document.getElementById('rulesTable').innerHTML = `<table><tr><th>Rule</th><th>Name</th><th>Family</th><th>Severity</th><th>Weight</th></tr>` +
    rules.map(r => `<tr><td class="mono">${r.id}</td><td>${escapeHtml(r.name)}<div class="scan-item-meta">${escapeHtml(r.description)}</div></td><td class="mono">${r.family}</td><td><span class="badge sev-${r.severity}">${r.severity}</span></td><td class="mono">+${r.weight}</td></tr>`).join('') + '</table>';
}

/* ============ boot ============ */
loadDashboard();
connectSSE();
loadSignatures();
renderConsole();
document.getElementById('consoleFilter').addEventListener('change', renderConsole);
// initial guard state
api('/api/guard').then(g => {
  document.getElementById('guardToggle').classList.toggle('on', g.enabled);
  document.getElementById('guardToggleText').textContent = g.enabled ? 'Guard ON' : 'Guard OFF';
}).catch(() => {});
