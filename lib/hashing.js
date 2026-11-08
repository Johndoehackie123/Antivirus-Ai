'use strict';
const crypto = require('crypto');
const fs = require('fs');

function hashBuffer(buf) {
  return {
    md5: crypto.createHash('md5').update(buf).digest('hex'),
    sha1: crypto.createHash('sha1').update(buf).digest('hex'),
    sha256: crypto.createHash('sha256').update(buf).digest('hex'),
    sha512: crypto.createHash('sha512').update(buf).digest('hex'),
    quick: crypto.createHash('sha256').update(buf.subarray(0, 65536)).digest('hex')
  };
}

/** Async streaming hash of a file on disk. */
function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const md5 = crypto.createHash('md5');
    const sha1 = crypto.createHash('sha1');
    const sha256 = crypto.createHash('sha256');
    const sha512 = crypto.createHash('sha512');
    const quick = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath, { highWaterMark: 1024 * 1024 });
    let quickBytes = 0;
    stream.on('data', (chunk) => {
      md5.update(chunk);
      sha1.update(chunk);
      sha256.update(chunk);
      sha512.update(chunk);
      if (quickBytes < 65536) {
        const take = Math.min(chunk.length, 65536 - quickBytes);
        quick.update(chunk.subarray(0, take));
        quickBytes += take;
      }
    });
    stream.on('end', () => {
      resolve({
        md5: md5.digest('hex'),
        sha1: sha1.digest('hex'),
        sha256: sha256.digest('hex'),
        sha512: sha512.digest('hex'),
        quick: quick.digest('hex')
      });
    });
    stream.on('error', reject);
  });
}

module.exports = { hashBuffer, hashFile };
