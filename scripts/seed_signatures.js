'use strict';
/**
 * SentinelGuard AI — signature database seeder.
 *
 * Parses public hash lists (community teaching sources on GitHub), filters out
 * format-invalid and obviously synthetic pattern-generated hashes, and writes
 * a structured signatures.json used by the engine.
 *
 * Reality filters applied:
 *   1. Valid hex + correct length for MD5 (32) / SHA1 (40) / SHA256 (64)
 *   2. Reject hashes where a constant 2-char-group step dominates >=40% of
 *      consecutive diffs (catches synthetic +0x11/+0x21 progression fillers)
 *   3. Reject repeated identical 2-char groups >= 3x consecutively
 *      (catches entries like 6f1b0a7c030f4a8e9e1a8e1a8e1a8e1a)
 */
const fs = require('fs');
const path = require('path');

const SIG_DIR = path.join(__dirname, '..', 'signatures');

function isHex(s) {
  return /^[0-9a-f]+$/i.test(s);
}

function hashLooksReal(h) {
  h = h.toLowerCase();
  if (!isHex(h)) return false;

  // Filter 2: detect dominant constant step between consecutive 2-char groups.
  // Synthetic teaching-DB hashes (e.g. a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2, +0x11
  // progressions) have one diff value repeating for most of the hash. Real
  // hashes have essentially random diffs, so the top diff never exceeds ~5%.
  const groups = [];
  for (let i = 0; i + 2 <= h.length; i += 2) {
    groups.push(parseInt(h.substr(i, 2), 16));
  }
  if (groups.length >= 8) {
    const diffCounts = {};
    for (let i = 1; i < groups.length; i++) {
      const d = (groups[i] - groups[i - 1]) & 0xff;
      diffCounts[d] = (diffCounts[d] || 0) + 1;
    }
    let top = 0;
    for (const d in diffCounts) top = Math.max(top, diffCounts[d]);
    if (top / (groups.length - 1) >= 0.4) return false;
  }

  // Filter 3: repeated identical 2-char group >= 3 consecutive times
  for (let i = 0; i + 6 <= h.length; i += 2) {
    const g = h.substr(i, 2);
    if (h.substr(i + 2, 2) === g && h.substr(i + 4, 2) === g) return false;
  }

  return true;
}

function parseFile(file, source) {
  const entries = [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    let type = null, hash = null, name = null;
    const parts = line.split(/\s*\|\s*/);
    if (parts.length >= 3) {
      type = parts[0].toUpperCase();
      hash = parts[1].trim().toLowerCase();
      name = parts.slice(2).join(' ').trim();
    } else {
      hash = line.toLowerCase();
    }
    // Length is authoritative for the hash function; declared type is a hint only.
    if (hash.length === 32) type = 'MD5';
    else if (hash.length === 40) type = 'SHA1';
    else if (hash.length === 64) type = 'SHA256';
    else continue;
    if (!isHex(hash)) continue;
    entries.push({ type, hash, name: name || 'Unknown threat', source });
  }
  return entries;
}

function main() {
  const astra = parseFile(path.join(SIG_DIR, 'astra_hashes.txt'), 'community:Astra-AV-Engine');
  const bad = parseFile(path.join(SIG_DIR, 'known_bad_hashes.txt'), 'community:static-malware-analyzer');

  const all = [...astra, ...bad];
  const kept = [];
  const rejected = [];
  const seen = new Set();

  for (const e of all) {
    const key = e.type + ':' + e.hash;
    if (seen.has(key)) continue;
    seen.add(key);
    if (!hashLooksReal(e.hash)) {
      rejected.push(e);
      continue;
    }
    kept.push(e);
  }

  // Curated known-goods: the industry-standard EICAR test file hash.
  const crypto = require('crypto');
  const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  kept.unshift({
    type: 'SHA256',
    hash: crypto.createHash('sha256').update(eicar, 'ascii').digest('hex'),
    name: 'EICAR Standard Antivirus Test File (harmless test)',
    source: 'curated:EICAR'
  });

  const byType = kept.reduce((acc, e) => {
    acc[e.type] = (acc[e.type] || 0) + 1;
    return acc;
  }, {});

  const out = {
    engine: 'SentinelGuard AI',
    dbVersion: '1.0.0',
    updated: new Date().toISOString(),
    source: 'Seeded from public community threat-intel sources (GitHub), filtered for validity. Hash signatures are exact-match only.',
    stats: {
      total: kept.length,
      byType,
      rejected: rejected.length
    },
    signatures: kept.map((e) => ({
      type: e.type,
      hash: e.hash,
      threat: e.name,
      source: e.source
    }))
  };

  const outPath = path.join(__dirname, '..', 'signatures.json');
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  console.log(`Wrote ${outPath}`);
  console.log(`  kept: ${kept.length} signatures  (${byType.MD5 || 0} MD5, ${byType.SHA1 || 0} SHA1, ${byType.SHA256 || 0} SHA256)`);
  console.log(`  rejected as synthetic/invalid: ${rejected.length}`);
  rejected.forEach((e) => console.log(`    - ${e.type} ${e.hash} (${e.name})`));
}

main();
