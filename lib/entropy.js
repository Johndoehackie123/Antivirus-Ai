'use strict';

/** Shannon entropy (bits/byte) of a buffer. */
function entropy(buf) {
  if (buf.length === 0) return 0;
  const counts = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let e = 0;
  const n = buf.length;
  for (let i = 0; i < 256; i++) {
    if (counts[i] > 0) {
      const p = counts[i] / n;
      e -= p * Math.log2(p);
    }
  }
  return e;
}

/** Entropy over evenly spread samples (used for large files). */
function entropySample(buf, sampleSize = 1024 * 1024, chunkCount = 8) {
  if (buf.length <= sampleSize) return entropy(buf);
  const chunk = Math.floor(sampleSize / chunkCount);
  const step = Math.floor(buf.length / (chunkCount * 8));
  const parts = [];
  for (let i = 0; i < buf.length && parts.length < chunkCount; i += Math.max(1, step)) {
    parts.push(buf.subarray(i, Math.min(i + chunk, buf.length)));
  }
  return entropy(Buffer.concat(parts));
}

module.exports = { entropy, entropySample };
