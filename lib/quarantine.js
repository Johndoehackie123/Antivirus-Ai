'use strict';

/**
 * Quarantine manager: moves flagged files into quarantine/ with metadata,
 * supports restore and delete.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const QDIR = path.join(__dirname, '..', 'quarantine');
const INDEX = path.join(QDIR, 'index.json');

function ensureDir() {
  fs.mkdirSync(QDIR, { recursive: true });
}

function loadIndex() {
  try {
    return JSON.parse(fs.readFileSync(INDEX, 'utf8'));
  } catch (e) {
    return [];
  }
}

function saveIndex(entries) {
  fs.writeFileSync(INDEX, JSON.stringify(entries, null, 2));
}

function quarantineFile(originalPath, analysis) {
  ensureDir();
  const entries = loadIndex();
  const id = crypto.randomBytes(8).toString('hex');
  const safeName = path.basename(originalPath).replace(/[^\w.\-]/g, '_').slice(0, 100);
  const target = path.join(QDIR, `${id}__${safeName}`);
  try {
    fs.copyFileSync(originalPath, target);
    fs.unlinkSync(originalPath);
  } catch (e) {
    throw new Error('Failed to move file into quarantine: ' + e.message);
  }
  const entry = {
    id,
    originalPath,
    storedAs: path.basename(target),
    name: analysis.name,
    ext: analysis.ext,
    size: analysis.size,
    sha256: analysis.hashes ? analysis.hashes.sha256 : null,
    verdict: analysis.verdict,
    verdictLabel: analysis.verdictLabel,
    score: analysis.score,
    rules: analysis.rules ? analysis.rules.map((r) => ({ id: r.id, name: r.name, severity: r.severity })) : [],
    behaviors: analysis.behaviors ? analysis.behaviors.map((b) => ({ id: b.id, name: b.name, severity: b.severity })) : [],
    quarantinedAt: new Date().toISOString(),
    reason: analysis.signatures && analysis.signatures.length ? `Signature match: ${analysis.signatures[0].threat}` : `Heuristic score ${analysis.score}`
  };
  entries.unshift(entry);
  saveIndex(entries);
  return entry;
}

function listQuarantine() {
  return loadIndex();
}

function restoreFile(id) {
  const entries = loadIndex();
  const entry = entries.find((e) => e.id === id);
  if (!entry) return null;
  const src = path.join(QDIR, entry.storedAs);
  const dest = entry.originalPath;
  try {
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(src, dest);
    fs.unlinkSync(src);
  } catch (e) {
    throw new Error('Failed to restore: ' + e.message);
  }
  entries.splice(entries.indexOf(entry), 1);
  saveIndex(entries);
  return entry;
}

function deleteQuarantine(id) {
  const entries = loadIndex();
  const entry = entries.find((e) => e.id === id);
  if (!entry) return null;
  try {
    const src = path.join(QDIR, entry.storedAs);
    if (fs.existsSync(src)) fs.unlinkSync(src);
  } catch (e) {
    // keep going
  }
  entries.splice(entries.indexOf(entry), 1);
  saveIndex(entries);
  return entry;
}

module.exports = { quarantineFile, listQuarantine, restoreFile, deleteQuarantine, QDIR };
