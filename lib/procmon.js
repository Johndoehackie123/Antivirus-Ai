'use strict';

/**
 * Process monitor: enumerates real processes from /proc, resolves their
 * executable paths, and scans them (with hash caching).
 */

const fs = require('fs');
const path = require('path');
const { hashFile } = require('./hashing');
const { scanFile } = require('./scanner');

function listProcesses() {
  const out = [];
  let pids;
  try {
    pids = fs.readdirSync('/proc').filter((x) => /^\d+$/.test(x));
  } catch (e) {
    return out;
  }
  for (const pid of pids) {
    let cmdline = '';
    let comm = '';
    let exePath = null;
    try {
      cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').replace(/\0/g, ' ').trim();
      comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim();
      try {
        exePath = fs.readlinkSync(`/proc/${pid}/exe`);
      } catch (e) {
        exePath = null;
      }
    } catch (e) {
      continue;
    }
    const name = cmdline ? cmdline.split(/\s+/)[0] : comm;
    out.push({
      pid: parseInt(pid, 10),
      name,
      comm: comm || name,
      cmdline: cmdline.slice(0, 200),
      exePath: exePath && exePath.startsWith('/') ? exePath : null
    });
  }
  return out.sort((a, b) => a.pid - b.pid);
}

const verdictCache = new Map(); // sha256 -> verdict summary

async function processVerdict(proc) {
  if (!proc.exePath) {
    return { status: 'unavailable', label: 'N/A', note: 'Executable path not readable (permissions or kernel thread)' };
  }
  try {
    const hashes = await hashFile(proc.exePath);
    const cached = verdictCache.get(hashes.sha256);
    if (cached) return { status: 'cached', label: cached.verdictLabel, score: cached.score, sha256: hashes.sha256, path: proc.exePath };
    const result = await scanFile(proc.exePath);
    verdictCache.set(hashes.sha256, {
      verdictLabel: result.verdictLabel,
      score: result.score,
      signatures: result.signatures.map((s) => s.threat)
    });
    return {
      status: 'scanned',
      label: result.verdictLabel,
      score: result.score,
      sha256: hashes.sha256,
      path: proc.exePath,
      rules: result.rules.map((r) => r.name).slice(0, 5),
      behaviors: result.behaviors.map((b) => b.name).slice(0, 5)
    };
  } catch (e) {
    return { status: 'error', label: 'ERR', note: e.message };
  }
}

async function monitorSnapshot(onEvent) {
  const procs = listProcesses();
  const results = [];
  for (const p of procs.slice(0, 400)) {
    const v = await processVerdict(p);
    results.push({ ...p, ...v });
  }
  return results;
}

module.exports = { listProcesses, processVerdict, monitorSnapshot };
