'use strict';

/**
 * File scanner: scans files from disk with hash caching, plus buffer scans.
 */

const fs = require('fs');
const path = require('path');
const { analyze } = require('./engine/engine');
const { hashFile } = require('./hashing');

const CACHE_PATH = path.join(__dirname, '..', 'data', 'scan_cache.json');

let cache = null;
function loadCache() {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(CACHE_PATH, 'utf8'));
  } catch (e) {
    cache = {};
  }
  return cache;
}
function saveCache() {
  try {
    fs.mkdirSync(path.dirname(CACHE_PATH), { recursive: true });
    fs.writeFileSync(CACHE_PATH, JSON.stringify(cache));
  } catch (e) {
    // non-fatal
  }
}
function cacheKey(type, hash) {
  return type + ':' + hash;
}

async function scanFile(filePath, opts = {}) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (e) {
    throw new Error('Cannot read file: ' + filePath);
  }
  const name = path.basename(filePath);
  const ext = path.extname(filePath).slice(1).toLowerCase();

  if (opts.cacheOnly) {
    const hashes = await hashFile(filePath);
    const c = loadCache();
    const hit = c[cacheKey('sha256', hashes.sha256)];
    if (hit) {
      return { ...hit, path: filePath, cached: true };
    }
    return null; // needs full scan
  }

  let buf;
  if (stat.size <= 64 * 1024 * 1024) {
    buf = fs.readFileSync(filePath);
  } else {
    // Sampled analysis for huge files
    const head = Buffer.alloc(32 * 1024 * 1024);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, head, 0, 32 * 1024 * 1024, 0);
    const hashes = await hashFile(filePath);
    fs.closeSync(fd);
    const result = analyze(head, { name, ext, path: filePath });
    result.hashes = hashes;
    result.notes.push(`File is ${(stat.size / 1024 / 1024).toFixed(1)} MB — analysis performed on the first 32 MB window.`);
    return result;
  }

  const result = analyze(buf, { name, ext, path: filePath });

  // Cache by sha256
  try {
    const c = loadCache();
    c[cacheKey('sha256', result.hashes.sha256)] = {
      name: result.name,
      ext: result.ext,
      fileType: result.fileType,
      entropy: result.entropy,
      verdict: result.verdict,
      verdictLabel: result.verdictLabel,
      score: result.score,
      signatures: result.signatures,
      rules: result.rules.map((r) => ({ id: r.id, name: r.name, severity: r.severity, weight: r.weight })),
      behaviors: result.behaviors.map((b) => ({ id: b.id, name: b.name, severity: b.severity })),
      sha256: result.hashes.sha256
    };
    saveCache();
  } catch (e) {
    // non-fatal
  }

  return result;
}

function scanBuffer(buf, meta = {}) {
  return analyze(buf, meta);
}

module.exports = { scanFile, scanBuffer, loadCache, saveCache };
