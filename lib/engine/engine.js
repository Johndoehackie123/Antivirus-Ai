'use strict';

/**
 * SentinelGuard AI — analysis engine.
 * Orchestrates: file type detection (magic), hashes, entropy, strings,
 * PE/ELF parsing, section entropy, heuristic rules, behavior profiling,
 * scoring and verdict.
 */

const { hashBuffer } = require('../hashing');
const { entropy, entropySample } = require('../entropy');
const { extractStrings } = require('../strings');
const { parsePE } = require('../pe');
const { parseELF } = require('../elf');
const { RULES } = require('./rules');
const { buildBehaviors } = require('./behavior');
const sig = require('./signatures');

const MAX_ANALYZE_SIZE = 64 * 1024 * 1024; // full analysis limit
const MAGIC = {
  '4d5a': 'PE',      // MZ
  '7f454c46': 'ELF',
  'd0cf11e0a1b11ae1': 'OLE', // CFB / Office
  '25504446': 'PDF',
  '504b0304': 'ZIP/DOCX',
  '377abcaf': '7z',
  '1f8b': 'GZIP',
  'fd377a585a00': 'XZ',
  '425a68': 'BZIP2',
  '78da': 'ZLIB',
  '27054c56': 'VBS/JSE (test marker)'
};

function detectType(buf) {
  const head = buf.subarray(0, 16);
  const h = head.toString('hex');
  for (const [magic, name] of Object.entries(MAGIC)) {
    if (h.startsWith(magic)) return name;
  }
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'ELF';
  if (buf.length >= 2 && buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) return 'MACHO';
  if (buf.length >= 4 && buf.readUInt32BE(0) === 0xfeedfacf) return 'MACHO';
  return 'OTHER';
}

function makeContext(buf, meta) {
  const head = buf.subarray(0, 0x1000);
  const fileType = detectType(buf);
  const strings = extractStrings(buf);
  strings.all = [...strings.ascii, ...strings.utf16];

  const ctx = {
    fileType,
    ext: meta.ext || '',
    size: buf.length,
    head,
    entropy: entropySample(buf),
    strings,
    hasAnyStr: (s) => strings.all.some((x) => x.toLowerCase().includes(s.toLowerCase())),
    regexAscii: (re) => {
      const text = strings.ascii.join('\n');
      return re.test(text);
    },
    pe: null,
    elf: null,
    imports: new Set(),
    importsHas: (n) => ctx.imports.has(n),
    importsAny: (names) => names.some((n) => ctx.imports.has(n))
  };

  // PE / ELF parse
  if (fileType === 'PE') {
    const pe = parsePE(buf);
    if (pe) {
      ctx.pe = pe;
      // Section entropy
      for (const s of pe.sections) {
        if (s.rawptr >= 0 && s.rawptr + s.rawsize <= buf.length && s.rawsize > 0) {
          s.entropy = entropy(buf.subarray(s.rawptr, s.rawptr + Math.min(s.rawsize, 2 * 1024 * 1024)));
        }
      }
      for (const imp of pe.imports) {
        for (const fn of imp.functions) ctx.imports.add(fn);
      }
    }
  } else if (fileType === 'ELF') {
    const elf = parseELF(buf);
    if (elf) {
      ctx.elf = elf;
      for (const sym of elf.symbols) ctx.imports.add(sym);
    }
  }

  return ctx;
}

function analyze(buf, meta = {}) {
  const t0 = Date.now();
  const size = buf.length;
  const result = {
    engine: 'SentinelGuard AI v1.0.0',
    analyzedAt: new Date().toISOString(),
    durationMs: 0,
    size,
    name: meta.name || 'unknown',
    ext: meta.ext || '',
    path: meta.path || null,
    fileType: 'OTHER',
    hashes: hashBuffer(buf),
    entropy: 0,
    strings: null,
    pe: null,
    elf: null,
    rules: [],
    behaviors: [],
    score: 0,
    verdict: 'clean',
    verdictLabel: 'CLEAN',
    signatures: [],
    notes: []
  };

  if (size > MAX_ANALYZE_SIZE) {
    result.notes.push(`File exceeds ${MAX_ANALYZE_SIZE / 1024 / 1024} MB full-analysis limit; header, hashes and heuristics computed on sampled content.`);
  }

  const ctx = makeContext(buf, meta);
  result.fileType = ctx.fileType;
  result.entropy = ctx.entropy;
  result.strings = {
    asciiCount: ctx.strings.asciiCount,
    utf16Count: ctx.strings.utf16Count,
    sample: ctx.strings.ascii.slice(0, 300),
    utf16Sample: ctx.strings.utf16.slice(0, 120),
    sampled: ctx.strings.sampled
  };

  if (ctx.pe) {
    result.pe = {
      machine: ctx.pe.machine,
      is64: ctx.pe.is64,
      subsystem: ctx.pe.subsystem,
      entryPoint: ctx.pe.entryPoint,
      imageBase: ctx.pe.imageBase,
      isDLL: ctx.pe.isDLL,
      sections: ctx.pe.sections.map((s) => ({
        name: s.name,
        flags: s.flags,
        size: s.rawsize,
        entropy: s.entropy != null ? Math.round(s.entropy * 100) / 100 : null
      })),
      imports: ctx.pe.imports.map((i) => ({ dll: i.dll, functions: i.functions.slice(0, 400) })),
      importCount: ctx.pe.allImports.length,
      dllCount: ctx.pe.imports.length,
      hasSignature: ctx.pe.hasSignature,
      hasTLS: ctx.pe.hasTLS,
      overlaySize: ctx.pe.overlaySize
    };
  }
  if (ctx.elf) {
    result.elf = {
      class: ctx.elf.class,
      endianness: ctx.elf.endianness,
      typeName: ctx.elf.typeName,
      machine: ctx.elf.machine,
      entry: ctx.elf.entry,
      interp: ctx.elf.interp,
      sections: ctx.elf.sections.map((s, i) => ({
        name: s.name,
        flags: ctx.elf.sectionFlags[i],
        size: s.size,
        type: s.type
      })),
      needed: ctx.elf.needed,
      symbols: ctx.elf.symbols.slice(0, 400),
      symbolCount: ctx.elf.symbolCount,
      overlaySize: ctx.elf.overlaySize
    };
  }

  // Signature matching (EICAR + exact hash DB)
  const sigMatches = [];
  if (sig.checkEicar(buf)) {
    sigMatches.push({
      type: 'EICAR',
      hash: result.hashes.sha256,
      threat: 'EICAR Standard Antivirus Test File',
      source: 'AMTSO industry-standard test',
      note: 'This is a deliberately harmless test string used to verify antivirus engines. It is not malware.'
    });
  }
  const hashMatches = sig.matchHash(result.hashes);
  sigMatches.push(...hashMatches);
  result.signatures = sigMatches;

  // Heuristic rules
  const hits = [];
  for (const r of RULES) {
    try {
      if (r.match(ctx)) {
        hits.push({
          id: r.id,
          name: r.name,
          family: r.family,
          severity: r.severity,
          weight: r.weight,
          description: r.description,
          evidence: r.evidence ? r.evidence(ctx) : []
        });
      }
    } catch (e) {
      // skip broken rule
    }
  }
  result.rules = hits;

  // Behavior profile
  result.behaviors = buildBehaviors(hits, ctx);

  // Scoring & verdict
  let score = hits.reduce((acc, h) => acc + h.weight, 0);
  if (sigMatches.length > 0) score = 100;
  score = Math.min(100, score);
  result.score = score;

  if (sigMatches.length > 0) {
    result.verdict = 'malicious';
    result.verdictLabel = 'MALICIOUS';
  } else if (score >= 70) {
    result.verdict = 'malicious';
    result.verdictLabel = 'MALICIOUS';
  } else if (score >= 45) {
    result.verdict = 'suspicious';
    result.verdictLabel = 'SUSPICIOUS';
  } else if (score >= 20) {
    result.verdict = 'low';
    result.verdictLabel = 'LOW RISK';
  } else {
    result.verdict = 'clean';
    result.verdictLabel = 'CLEAN';
  }

  // Notes
  if (ctx.pe && !ctx.pe.hasSignature) result.notes.push('No Authenticode signature present — not signed by a trusted publisher.');
  if (ctx.elf && ctx.elf.typeName === 'DYN') result.notes.push('PIE/shared object — relocatable code (common for Linux libraries and binaries).');
  if (ctx.strings.sampled) result.notes.push('Strings extracted from sampled windows of a large file.');

  result.durationMs = Date.now() - t0;
  return result;
}

module.exports = { analyze, detectType, MAX_ANALYZE_SIZE };
