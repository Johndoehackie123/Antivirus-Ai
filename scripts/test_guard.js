'use strict';
// Write the exact EICAR test string into the watch folder to verify the guard.
const fs = require('fs');
const path = require('path');

// Correct EICAR string: single backslash before PZX54
const eicar = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
console.log('EICAR length:', eicar.length, '(expected 68)');
console.log('content:', JSON.stringify(eicar));

const watchDir = path.join(__dirname, '..', 'watch');
fs.mkdirSync(watchDir, { recursive: true });
const target = path.join(watchDir, 'eicar_dropped.com');
fs.writeFileSync(target, eicar, 'ascii');
console.log('Wrote', target, fs.statSync(target).size, 'bytes');
