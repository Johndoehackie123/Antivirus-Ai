'use strict';

/**
 * Extract printable strings from a buffer.
 * Returns ASCII and UTF-16LE strings. For files > MAX_STRING_SCAN bytes,
 * only the first window + a middle window are scanned (documented in UI).
 */
const MAX_STRING_SCAN = 48 * 1024 * 1024;

function extractStrings(buf, minLen = 5, cap = 30000) {
  let data = buf;
  let sampled = false;
  if (buf.length > MAX_STRING_SCAN) {
    const head = buf.subarray(0, 24 * 1024 * 1024);
    const midStart = Math.floor(buf.length / 2) - 12 * 1024 * 1024;
    const mid = buf.subarray(Math.max(0, midStart), Math.min(buf.length, midStart + 24 * 1024 * 1024));
    data = Buffer.concat([head, mid]);
    sampled = true;
  }

  const ascii = [];
  const utf16 = [];
  let start = -1;
  const n = data.length;

  // ASCII strings
  for (let i = 0; i < n; i++) {
    const b = data[i];
    if (b >= 0x20 && b < 0x7f) {
      if (start < 0) start = i;
    } else {
      if (start >= 0 && i - start >= minLen) {
        ascii.push(data.toString('ascii', start, i));
        if (ascii.length >= cap) break;
      }
      start = -1;
    }
  }
  if (start >= 0 && n - start >= minLen) {
    ascii.push(data.toString('ascii', start, n));
  }

  // UTF-16LE strings (char + 0x00 pairs)
  start = -1;
  const limit = ascii.length >= cap ? ascii.length : 0; // if ascii capped, skip utf16 to bound time
  if (limit === 0) {
    for (let i = 0; i + 1 < n; i += 1) {
      const b = data[i];
      const z = data[i + 1];
      if (b >= 0x20 && b < 0x7f && z === 0) {
        if (start < 0) start = i;
      } else {
        if (start >= 0 && (i - start) / 2 >= minLen) {
          utf16.push(data.toString('utf16le', start, i));
          if (utf16.length >= cap) break;
        }
        start = -1;
      }
    }
    if (start >= 0 && (n - start) / 2 >= minLen) {
      utf16.push(data.toString('utf16le', start, n));
    }
  }

  return {
    ascii: ascii.slice(0, cap),
    utf16: utf16.slice(0, cap),
    asciiCount: ascii.length,
    utf16Count: utf16.length,
    sampled
  };
}

module.exports = { extractStrings, MAX_STRING_SCAN };
