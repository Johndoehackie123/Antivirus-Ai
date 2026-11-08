'use strict';

/**
 * Real-time file guard (Sentinel Watch).
 * Polls a watch folder; scans new/changed files; quarantines suspicious ones.
 * Emits events via callback: { type, file, analysis, action }
 */

const fs = require('fs');
const path = require('path');
const { scanFile } = require('./scanner');
const quarantine = require('./quarantine');

const GUARD_STATE = {
  enabled: false,
  watchFolder: path.join(__dirname, '..', 'watch'),
  intervalMs: 2000,
  lastScan: null,
  events: 0,
  blocked: 0
};

let timer = null;
let snapshots = new Map(); // path -> {size, mtime}

function snapshot(dir) {
  const snap = new Map();
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return snap;
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const full = path.join(dir, entry.name);
    try {
      const st = fs.statSync(full);
      snap.set(full, { size: st.size, mtime: st.mtimeMs });
    } catch (e) {
      // skip
    }
  }
  return snap;
}

async function tick(onEvent) {
  const dir = GUARD_STATE.watchFolder;
  const current = snapshot(dir);
  for (const [file, meta] of current) {
    const prev = snapshots.get(file);
    if (!prev || prev.size !== meta.size || prev.mtime !== meta.mtime) {
      // new or changed file — scan it
      try {
        const analysis = await scanFile(file);
        const verdict = analysis.verdict;
        let action = 'checked';
        if (verdict === 'malicious' || verdict === 'suspicious') {
          try {
            quarantine.quarantineFile(file, analysis);
            action = 'quarantined';
            GUARD_STATE.blocked++;
          } catch (e) {
            action = 'quarantine_failed';
          }
        }
        onEvent({
          type: 'guard',
          action,
          file,
          verdict: analysis.verdict,
          verdictLabel: analysis.verdictLabel,
          score: analysis.score,
          signatures: analysis.signatures,
          behaviors: analysis.behaviors.map((b) => b.name)
        });
      } catch (e) {
        onEvent({ type: 'guard', action: 'error', file, message: e.message });
      }
    }
  }
  snapshots = current;
  GUARD_STATE.lastScan = new Date().toISOString();
}

function startGuard(onEvent) {
  if (GUARD_STATE.enabled) return;
  GUARD_STATE.enabled = true;
  fs.mkdirSync(GUARD_STATE.watchFolder, { recursive: true });
  snapshots = snapshot(GUARD_STATE.watchFolder);
  timer = setInterval(() => tick(onEvent).catch(() => {}), GUARD_STATE.intervalMs);
  onEvent({ type: 'guard', action: 'started', watchFolder: GUARD_STATE.watchFolder });
}

function stopGuard(onEvent) {
  GUARD_STATE.enabled = false;
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
  onEvent({ type: 'guard', action: 'stopped' });
}

function guardStatus() {
  return {
    enabled: GUARD_STATE.enabled,
    watchFolder: GUARD_STATE.watchFolder,
    intervalMs: GUARD_STATE.intervalMs,
    lastScan: GUARD_STATE.lastScan,
    blocked: GUARD_STATE.blocked
  };
}

module.exports = { startGuard, stopGuard, guardStatus, GUARD_STATE };
