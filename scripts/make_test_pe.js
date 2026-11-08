'use strict';
/**
 * Builds a minimal but REAL PE32 executable (synthetic, for testing the
 * SentinelGuard engine). It imports the classic process-injection API set
 * from kernel32/user32 and contains suspicious strings. It is NOT a real
 * malware sample — it's a static analysis test fixture.
 */
const fs = require('fs');
const path = require('path');

const { buildTestPE } = require('../lib/pebuilder');

const buf = buildTestPE();
const outDir = path.join(__dirname, '..', 'uploads');
fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, 'demo_injection.exe');
fs.writeFileSync(outPath, buf);
console.log('Wrote ' + outPath + ' (' + buf.length + ' bytes)');

// Verify with our own parser
const { parsePE } = require('../lib/pe');
const parsed = parsePE(buf);
console.log('Parsed PE: machine=' + parsed.machine + ' subsystem=' + parsed.subsystem);
console.log('DLLs: ' + parsed.imports.map((i) => i.dll).join(', '));
console.log('kernel32 functions: ' + parsed.imports[0].functions.join(', '));
console.log('user32 functions: ' + parsed.imports[1].functions.join(', '));
