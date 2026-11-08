'use strict';
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', '..', 'signatures.json');

let db = null;
let dbModTime = 0;

function loadDb() {
  if (db) {
    try {
      const m = fs.statSync(DB_PATH).mtimeMs;
      if (m > dbModTime) {
        db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
        dbModTime = m;
      }
    } catch (e) {
      // keep existing db on read error
    }
    return db;
  }
  db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  dbModTime = fs.statSync(DB_PATH).mtimeMs;
  return db;
}

/**
 * EICAR structural check (AMTSO standard antivirus test string).
 * The test string is: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
 * Algorithm: must start with "X5O!P%", and every 7th char after index 5
 * must be '('. Content between those chars is free-form.
 */
function checkEicar(buf) {
  try {
    const head = buf.subarray(0, 4096).toString('ascii');
    if (!head.startsWith('X5O!P%')) return false;
    // trimmed content must be <= 128 bytes per spec
    for (let i = 6; i < head.length; i++) {
      if (i >= 128) return false;
      if ((i - 6) % 7 === 0 && head[i] !== '(') return false;
    }
    return true;
  } catch (e) {
    return false;
  }
}

/** Exact hash match against the signature database. */
function matchHash(hashes) {
  const db = loadDb();
  const matches = [];
  for (const sig of db.signatures) {
    const h = hashes[sig.type.toLowerCase()];
    if (h && h === sig.hash) {
      matches.push({
        type: sig.type,
        hash: sig.hash,
        threat: sig.threat,
        source: sig.source
      });
    }
  }
  return matches;
}

function dbStats() {
  const db = loadDb();
  return {
    version: db.dbVersion,
    updated: db.updated,
    total: db.stats.total,
    byType: db.stats.byType,
    description: db.source
  };
}

function dbSignatures() {
  return loadDb().signatures;
}

module.exports = { loadDb, checkEicar, matchHash, dbStats, dbSignatures, DB_PATH };
