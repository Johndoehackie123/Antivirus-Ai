'use strict';

/**
 * SentinelGuard AI — web platform server.
 * Zero dependencies (Node stdlib). Serves the SPA + REST API + SSE event stream.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { scanFile, scanBuffer } = require('./lib/scanner');
const { analyze } = require('./lib/engine/engine');
const quarantine = require('./lib/quarantine');
const guard = require('./lib/guard');
const procmon = require('./lib/procmon');
const sig = require('./lib/engine/signatures');
const { walk } = require('./lib/fsutil');
const { buildTestPE } = require('./lib/pebuilder');
const { RULES } = require('./lib/engine/rules');

const PORT = process.env.PORT || 8080;
const HOST = '0.0.0.0';
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const UPLOADS_DIR = path.join(ROOT, 'uploads');
const WATCH_DIR = path.join(ROOT, 'watch');
const DATA_DIR = path.join(ROOT, 'data');
const SCANS_FILE = path.join(DATA_DIR, 'scans.json');

fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(WATCH_DIR, { recursive: true });
fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------------- event bus (SSE) ----------------
const EVENT_BUS = (() => {
  const listeners = new Set();
  const history = [];
  const HISTORY_CAP = 300;
  function emit(ev) {
    const event = { ts: Date.now(), ...ev };
    history.push(event);
    if (history.length > HISTORY_CAP) history.shift();
    for (const l of listeners) {
      try {
        l.res.write(`data: ${JSON.stringify(event)}\n\n`);
      } catch (e) {
        listeners.delete(l);
      }
    }
  }
  return { emit, listeners, history };
})();

function logEvent(type, data) {
  EVENT_BUS.emit({ type, ...data });
}

// ---------------- scan history ----------------
function loadScans() {
  try {
    return JSON.parse(fs.readFileSync(SCANS_FILE, 'utf8'));
  } catch (e) {
    return [];
  }
}
function saveScans(scans) {
  fs.writeFileSync(SCANS_FILE, JSON.stringify(scans.slice(0, 500)));
}
function recordScan(result, source) {
  const scans = loadScans();
  // Store a compact snapshot for detail views
  const detail = {
    hashes: result.hashes,
    fileType: result.fileType,
    ext: result.ext,
    size: result.size,
    entropy: result.entropy,
    strings: result.strings,
    pe: result.pe,
    elf: result.elf,
    rules: result.rules.map((r) => ({ id: r.id, name: r.name, severity: r.severity, weight: r.weight })),
    behaviors: result.behaviors.map((b) => ({ id: b.id, name: b.name, severity: b.severity, confidence: b.confidence })),
    notes: result.notes,
    durationMs: result.durationMs
  };
  const entry = {
    id: crypto.randomBytes(6).toString('hex'),
    ts: Date.now(),
    source, // upload | system | guard | process | manual
    name: result.name,
    path: result.path || null,
    fileType: result.fileType,
    ext: result.ext,
    size: result.size,
    sha256: result.hashes ? result.hashes.sha256 : null,
    md5: result.hashes ? result.hashes.md5 : null,
    verdict: result.verdict,
    verdictLabel: result.verdictLabel,
    score: result.score,
    signatures: result.signatures,
    ruleCount: result.rules.length,
    behaviorCount: result.behaviors.length,
    durationMs: result.durationMs,
    detail
  };
  scans.unshift(entry);
  saveScans(scans);
  return entry;
}

// ---------------- system scan ----------------
const SYSTEM_SCAN = {
  running: false,
  startedAt: null,
  roots: [],
  scanned: 0,
  truncated: false,
  counts: { clean: 0, low: 0, suspicious: 0, malicious: 0 },
  results: [],
  lastEventTs: 0
};

async function runSystemScan(roots) {
  if (SYSTEM_SCAN.running) return;
  SYSTEM_SCAN.running = true;
  SYSTEM_SCAN.startedAt = new Date().toISOString();
  SYSTEM_SCAN.roots = roots;
  SYSTEM_SCAN.scanned = 0;
  SYSTEM_SCAN.counts = { clean: 0, low: 0, suspicious: 0, malicious: 0 };
  SYSTEM_SCAN.results = [];
  SYSTEM_SCAN.truncated = false;
  logEvent('system-scan', { status: 'started', roots });

  const { files, truncated } = walk(roots, (ev) => {
    if (ev.type === 'error') logEvent('system-scan', { status: 'error', message: ev.message });
  });
  SYSTEM_SCAN.truncated = truncated;
  const total = files.length;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    try {
      const result = await scanFile(file);
      SYSTEM_SCAN.counts[result.verdict] = (SYSTEM_SCAN.counts[result.verdict] || 0) + 1;
      SYSTEM_SCAN.results.push({
        path: file,
        name: result.name,
        fileType: result.fileType,
        verdict: result.verdict,
        verdictLabel: result.verdictLabel,
        score: result.score,
        entropy: result.entropy,
        sha256: result.hashes ? result.hashes.sha256 : null,
        rules: result.rules.map((r) => r.name).slice(0, 3)
      });
      if (result.verdict !== 'clean') recordScan(result, 'system');
      SYSTEM_SCAN.scanned = i + 1;
      // throttle progress events
      if (SYSTEM_SCAN.scanned % 5 === 0 || result.verdict !== 'clean') {
        logEvent('system-scan', {
          status: 'progress',
          scanned: SYSTEM_SCAN.scanned,
          total,
          counts: SYSTEM_SCAN.counts,
          lastFile: { path: file, verdict: result.verdictLabel, score: result.score }
        });
      }
    } catch (e) {
      // skip
    }
  }

  SYSTEM_SCAN.running = false;
  logEvent('system-scan', { status: 'complete', scanned: SYSTEM_SCAN.scanned, counts: SYSTEM_SCAN.counts });
}

// ---------------- HTTP helpers ----------------
function send(res, code, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(code, {
    'Content-Type': typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8',
    ...headers
  });
  res.end(body);
}

function readJsonBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (c) => {
      total += c.length;
      if (total > limit) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

async function readRawBody(req, limit = 200 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (c) => {
      total += c.length;
      if (total > limit) {
        reject(new Error('upload too large (max 200 MB)'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.json': 'application/json'
};

function serveStatic(req, res, urlPath) {
  // /uploads/* — generated test files / uploads
  if (urlPath.startsWith('/uploads/')) {
    const rel = urlPath.slice('/uploads/'.length);
    const full = path.join(UPLOADS_DIR, rel);
    if (!full.startsWith(UPLOADS_DIR)) return send(res, 403, 'Forbidden');
    fs.readFile(full, (err, data) => {
      if (err) return send(res, 404, 'Not Found');
      res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Cache-Control': 'no-cache' });
      res.end(data);
    });
    return;
  }
  let rel = urlPath === '/' ? 'index.html' : urlPath.slice(1);
  const full = path.join(PUBLIC_DIR, rel);
  if (!full.startsWith(PUBLIC_DIR)) return send(res, 403, 'Forbidden');
  fs.readFile(full, (err, data) => {
    if (err) return send(res, 404, 'Not Found');
    const ext = path.extname(full).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

// ---------------- routes ----------------
async function handleApi(req, res, url) {
  const p = url.pathname;
  const method = req.method;

  // ---- scan upload (raw body + X-Filename) ----
  if (p === '/api/scan' && method === 'POST') {
    try {
      const filename = (req.headers['x-filename'] || 'uploaded_file').slice(0, 200);
      const buf = await readRawBody(req);
      const ext = path.extname(filename).slice(1).toLowerCase();
      const result = scanBuffer(buf, { name: filename, ext });
      const entry = recordScan(result, 'upload');
      logEvent('scan', {
        id: entry.id,
        name: result.name,
        verdict: result.verdict,
        verdictLabel: result.verdictLabel,
        score: result.score,
        signatures: result.signatures.map((s) => s.threat),
        rules: result.rules.map((r) => r.id),
        source: 'upload'
      });
      if (result.verdict === 'malicious' || result.verdict === 'suspicious') {
        // auto-quarantine flagged uploads
        try {
          const store = path.join(UPLOADS_DIR, `${entry.id}__${filename.replace(/[^\w.\-]/g, '_')}`);
          fs.writeFileSync(store, buf);
          quarantine.quarantineFile(store, result);
          logEvent('quarantine', { action: 'auto', name: result.name, verdict: result.verdictLabel });
        } catch (e) {
          // non-fatal
        }
      }
      return send(res, 200, { ...result, scanId: entry.id });
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // ---- scan file by path ----
  if (p === '/api/scan-path' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const target = String(body.path || '');
      // Restrict to safe roots
      const allowed = ['/home/user', '/tmp', '/var/tmp'];
      if (!target || !allowed.some((root) => target.startsWith(root))) {
        return send(res, 403, { error: 'Path outside allowed roots (/home/user, /tmp)' });
      }
      const result = await scanFile(target);
      const entry = recordScan(result, 'manual');
      logEvent('scan', {
        id: entry.id,
        name: result.name,
        verdict: result.verdict,
        verdictLabel: result.verdictLabel,
        score: result.score,
        source: 'manual'
      });
      return send(res, 200, { ...result, scanId: entry.id });
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // ---- scan history ----
  if (p === '/api/scans' && method === 'GET') {
    return send(res, 200, { scans: loadScans() });
  }
  const scanDetail = p.match(/^\/api\/scans\/([a-f0-9]+)$/);
  if (scanDetail && method === 'GET') {
    const scans = loadScans();
    const entry = scans.find((s) => s.id === scanDetail[1]);
    if (!entry) return send(res, 404, { error: 'Not found' });
    return send(res, 200, entry);
  }

  // ---- quarantine ----
  if (p === '/api/quarantine' && method === 'GET') {
    return send(res, 200, { entries: quarantine.listQuarantine() });
  }
  if (p === '/api/quarantine' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const result = await scanFile(body.path);
      const entry = quarantine.quarantineFile(body.path, result);
      recordScan(result, 'quarantine');
      logEvent('quarantine', { action: 'manual', name: result.name, verdict: result.verdictLabel });
      return send(res, 200, entry);
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }
  if (p === '/api/quarantine/restore' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const entry = quarantine.restoreFile(body.id);
      if (!entry) return send(res, 404, { error: 'Not found' });
      logEvent('quarantine', { action: 'restored', name: entry.name });
      return send(res, 200, entry);
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }
  if (p === '/api/quarantine/delete' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const entry = quarantine.deleteQuarantine(body.id);
      if (!entry) return send(res, 404, { error: 'Not found' });
      logEvent('quarantine', { action: 'deleted', name: entry.name });
      return send(res, 200, entry);
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // ---- processes ----
  if (p === '/api/processes' && method === 'GET') {
    const procs = await procmon.monitorSnapshot();
    return send(res, 200, {
      processes: procs.map((p) => ({
        pid: p.pid, name: p.name, comm: p.comm, cmdline: p.cmdline,
        exePath: p.exePath, status: p.status, label: p.label, score: p.score,
        sha256: p.sha256, rules: p.rules, behaviors: p.behaviors, note: p.note
      })),
      count: procs.length
    });
  }
  const procScan = p.match(/^\/api\/processes\/scan\/(\d+)$/);
  if (procScan && method === 'POST') {
    const procs = procmon.listProcesses().filter((x) => x.pid === parseInt(procScan[1], 10));
    if (!procs.length) return send(res, 404, { error: 'Process not found' });
    const result = await procmon.processVerdict(procs[0]);
    if (procs[0].exePath) {
      const analysis = await scanFile(procs[0].exePath);
      recordScan(analysis, 'process');
      return send(res, 200, { process: procs[0], analysis, ...result });
    }
    return send(res, 200, { process: procs[0], ...result });
  }

  // ---- system scan ----
  if (p === '/api/system-scan' && method === 'POST') {
    const body = await readJsonBody(req);
    let roots = body.roots;
    if (!Array.isArray(roots) || !roots.length) {
      roots = ['/home/user', '/tmp'];
    }
    roots = roots.filter((r) => r.startsWith('/'));
    if (SYSTEM_SCAN.running) return send(res, 409, { error: 'A system scan is already running' });
    runSystemScan(roots);
    return send(res, 200, { started: true, roots });
  }
  if (p === '/api/system-scan' && method === 'GET') {
    return send(res, 200, {
      running: SYSTEM_SCAN.running,
      startedAt: SYSTEM_SCAN.startedAt,
      roots: SYSTEM_SCAN.roots,
      scanned: SYSTEM_SCAN.scanned,
      truncated: SYSTEM_SCAN.truncated,
      counts: SYSTEM_SCAN.counts,
      results: SYSTEM_SCAN.results.slice(0, 500),
      totalResults: SYSTEM_SCAN.results.length
    });
  }

  // ---- guard ----
  if (p === '/api/guard' && method === 'GET') {
    return send(res, 200, { ...guard.guardStatus(), watchFiles: fs.readdirSync(WATCH_DIR) });
  }
  if (p === '/api/guard' && method === 'POST') {
    const body = await readJsonBody(req);
    if (body.enabled === true) {
      guard.startGuard((ev) => logEvent('guard', ev));
    } else {
      guard.stopGuard((ev) => logEvent('guard', ev));
    }
    return send(res, 200, guard.guardStatus());
  }
  if (p === '/api/watch-files' && method === 'POST') {
    const body = await readJsonBody(req);
    const name = String(body.name || '').replace(/[^\w.\-]/g, '_').slice(0, 100);
    if (!name) return send(res, 400, { error: 'name required' });
    fs.writeFileSync(path.join(WATCH_DIR, name), body.content || '');
    logEvent('watch', { action: 'file-created', name });
    return send(res, 200, { ok: true, path: path.join(WATCH_DIR, name) });
  }

  // ---- stats ----
  if (p === '/api/stats' && method === 'GET') {
    const scans = loadScans();
    const q = quarantine.listQuarantine();
    const db = sig.dbStats();
    const counts = { clean: 0, low: 0, suspicious: 0, malicious: 0 };
    for (const s of scans) counts[s.verdict] = (counts[s.verdict] || 0) + 1;
    return send(res, 200, {
      scansTotal: scans.length,
      verdictCounts: counts,
      quarantined: q.length,
      signatures: db.total,
      rules: RULES.length,
      guard: guard.guardStatus(),
      uptime: process.uptime(),
      timestamp: Date.now()
    });
  }

  // ---- signatures ----
  if (p === '/api/signatures' && method === 'GET') {
    return send(res, 200, {
      db: sig.dbStats(),
      signatures: sig.dbSignatures(),
      rules: RULES
    });
  }
  if (p === '/api/signatures/hash' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const hash = String(body.hash || '').trim().toLowerCase();
      const threat = String(body.threat || 'Custom signature');
      if (!/^[0-9a-f]{32,128}$/.test(hash)) return send(res, 400, { error: 'Invalid hash format' });
      const db = JSON.parse(fs.readFileSync(sig.DB_PATH, 'utf8'));
      if (!db.signatures.some((s) => s.hash === hash)) {
        db.signatures.push({
          type: hash.length === 32 ? 'MD5' : hash.length === 40 ? 'SHA1' : 'SHA256',
          hash,
          threat,
          source: 'user-added'
        });
        db.stats.total = db.signatures.length;
        db.updated = new Date().toISOString();
        fs.writeFileSync(sig.DB_PATH, JSON.stringify(db, null, 2));
        logEvent('signatures', { action: 'added', hash, threat });
      }
      return send(res, 200, { ok: true, total: db.stats.total });
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // ---- test files ----
  if (p === '/api/test-files' && method === 'POST') {
    try {
      const body = await readJsonBody(req);
      const kind = body.kind || 'eicar';
      const files = [];
      if (kind === 'eicar') {
        const content = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
        const name = 'eicar_test.com';
        fs.writeFileSync(path.join(UPLOADS_DIR, name), content, 'ascii');
        files.push({ name, description: 'EICAR standard antivirus test file (industry-standard, harmless)' });
      } else if (kind === 'suspicious') {
        const name = 'suspicious_demo.ps1';
        const content = `# DEMO FILE - harmless. Shows how SentinelGuard flags PowerShell abuse patterns.
# No real payload; the base64 string is just a sample blob.
$blob = 'SQBFAFgAKAAnAE4AZQB0AC4AVwBlAGIAVABGAAgA8AE4AYQBtAG8AIQAOAAkACAAQABhAG4AIAAoAEcAYQBtAGUAcABhAHIAdAApAD4ACAAPATEAEgBLAEoASwBHAEUAUwBQAFcAWABVAFkAWgBfAHoAIAAnAFcAUQBWAFUAUgBQAFwAUgBQAFQAUwBkAEwAUABNAA0AIAAkAEcAQwBQAE0AYQBuAGQAIAAoACAAJAB5AHIAdAApACAAJABiAGkAZABtAHMAawBpAGMAawBmAGkAZABtAHMAawA='
$cmd = [System.Convert]::FromBase64String($blob)
Invoke-Expression $cmd
`;
        fs.writeFileSync(path.join(UPLOADS_DIR, name), content, 'utf8');
        files.push({ name, description: 'Demo PowerShell script with encoded payload (harmless demo)' });
      } else if (kind === 'pe') {
        const name = 'demo_injection.exe';
        fs.writeFileSync(path.join(UPLOADS_DIR, name), buildTestPE());
        files.push({ name, description: 'Synthetic PE32 test fixture — imports process-injection API set (harmless demo, not real malware)' });
      } else if (kind === 'benign') {
        const name = 'benign_test.txt';
        const content = 'This is a harmless text file used to verify that SentinelGuard reports CLEAN results.\n';
        fs.writeFileSync(path.join(UPLOADS_DIR, name), content, 'utf8');
        files.push({ name, description: 'Harmless text file (should be CLEAN)' });
      } else {
        return send(res, 400, { error: 'unknown test file kind' });
      }
      logEvent('test-files', { action: 'generated', kind });
      return send(res, 200, { files, uploadDir: UPLOADS_DIR });
    } catch (e) {
      return send(res, 400, { error: e.message });
    }
  }

  // ---- SSE log stream ----
  if (p === '/api/logs' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    const sendHistory = (since) => {
      const evs = EVENT_BUS.history.filter((e) => e.ts >= since);
      for (const e of evs) {
        res.write(`data: ${JSON.stringify(e)}\n\n`);
      }
    };
    const since = Date.now() - 60 * 1000;
    sendHistory(since);
    const client = { res };
    EVENT_BUS.listeners.add(client);
    const keepalive = setInterval(() => {
      try {
        res.write(': keepalive\n\n');
      } catch (e) {
        clearInterval(keepalive);
      }
    }, 15000);
    req.on('close', () => {
      clearInterval(keepalive);
      EVENT_BUS.listeners.delete(client);
    });
    return;
  }

  // ---- health ----
  if (p === '/api/health' && method === 'GET') {
    return send(res, 200, { ok: true, engine: 'SentinelGuard AI v1.0.0', uptime: process.uptime() });
  }

  send(res, 404, { error: 'Unknown API route: ' + p });
}

// ---------------- server ----------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
    } else {
      serveStatic(req, res, url.pathname);
    }
  } catch (e) {
    send(res, 500, { error: e.message || 'Internal server error' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`SentinelGuard AI v1.0.0 — listening on http://${HOST}:${PORT}`);
  console.log(`Watch folder: ${WATCH_DIR}`);
  console.log(`Signature DB: ${sig.dbStats().total} signatures, ${RULES.length} heuristic rules`);
});
