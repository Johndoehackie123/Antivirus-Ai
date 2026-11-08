'use strict';

/**
 * Directory walker for system scans.
 * Emits progress events via a callback. Respects depth, size and file-count caps.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'quarantine', 'uploads', '__pycache__',
  '.npm', '.cache', '.local', '.vscode', 'dist', 'build', 'target'
]);
const MAX_FILES = 3000;
const MAX_FILE_SIZE = 64 * 1024 * 1024;
const MAX_DEPTH = 12;

function walk(roots, onEvent) {
  const queue = roots.map((r) => ({ dir: r, depth: 0 }));
  const files = [];
  let scanned = 0;
  let truncated = false;

  const seen = new Set();

  function handleError(p, err) {
    onEvent({ type: 'error', path: p, message: err.message });
  }

  function processDir(item) {
    let entries;
    try {
      entries = fs.readdirSync(item.dir, { withFileTypes: true });
    } catch (e) {
      handleError(item.dir, e);
      return;
    }
    for (const entry of entries) {
      const full = path.join(item.dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name) && item.depth < MAX_DEPTH) {
          queue.push({ dir: full, depth: item.depth + 1 });
        }
      } else if (entry.isFile()) {
        if (seen.has(full)) continue;
        seen.add(full);
        try {
          const st = fs.statSync(full);
          if (!st.isFile()) continue;
          if (st.size > MAX_FILE_SIZE) {
            onEvent({ type: 'skip', path: full, reason: 'too large', size: st.size });
            continue;
          }
          files.push(full);
          if (files.length >= MAX_FILES) {
            truncated = true;
            break;
          }
        } catch (e) {
          // skip unreadable
        }
      }
    }
  }

  while (queue.length > 0 && files.length < MAX_FILES) {
    const item = queue.shift();
    if (item.depth >= MAX_DEPTH) continue;
    processDir(item);
    if (truncated) break;
  }

  return { files, truncated, scanned };
}

module.exports = { walk, SKIP_DIRS, MAX_FILES, MAX_FILE_SIZE, MAX_DEPTH };
