'use strict';

/**
 * Minimal but real PE/COFF parser.
 * Reads: machine, subsystem, entry point, image base, sections (with flags),
 * import table (DLL + function names), export presence, Authenticode flag,
 * overlay size, compile timestamp.
 */

const MACHINE_NAMES = {
  0x14c: 'i386', 0x8664: 'x86-64', 0x1c0: 'ARM', 0xaa64: 'ARM64',
  0x1c4: 'ARM Thumb-2', 0x200: 'IA64', 0x9041: 'MIPS R4000'
};

const SUBSYSTEM_NAMES = {
  0: 'UNKNOWN', 1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI',
  7: 'POSIX_CUI', 9: 'WINDOWS_CE_GUI', 10: 'EFI_APPLICATION',
  11: 'EFI_BOOT_SERVICE_DRIVER', 12: 'EFI_RUNTIME_DRIVER', 13: 'EFI_ROM',
  14: 'XBOX', 16: 'WINDOWS_BOOT_APPLICATION'
};

function parsePE(buf) {
  if (buf.length < 0x40) return null;
  if (buf.readUInt16LE(0) !== 0x5a4d) return null; // 'MZ'

  const e_lfanew = buf.readUInt32LE(0x3c);
  if (e_lfanew + 24 > buf.length) return null;
  if (buf.readUInt32LE(e_lfanew) !== 0x00004550) return null; // 'PE\0\0'

  const coff = e_lfanew + 4;
  const machine = buf.readUInt16LE(coff);
  const sectionCount = buf.readUInt16LE(coff + 2);
  const timeDateStamp = buf.readUInt32LE(coff + 4);
  const characteristics = buf.readUInt16LE(coff + 18);
  const opt = coff + 20;
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) return null;
  const is64 = magic === 0x20b;

  const imageBase = is64 ? buf.readBigUInt64LE(opt + 8) : buf.readUInt32LE(opt + 4);
  const subsystem = buf.readUInt16LE(is64 ? opt + 84 : opt + 68);
  const entryPoint = buf.readUInt32LE(opt + 16);
  const isDLL = (characteristics & 0x2000) !== 0;
  const isStripped = (characteristics & 0x0200) !== 0; // no debug info

  // Data directories
  const numDataDirs = buf.readUInt32LE(opt + (is64 ? 108 : 92));
  const ddBase = opt + (is64 ? 112 : 96);
  const dataDirs = [];
  for (let i = 0; i < Math.min(numDataDirs, 16); i++) {
    const o = ddBase + i * 8;
    if (o + 8 > buf.length) break;
    dataDirs.push({ rva: buf.readUInt32LE(o), size: buf.readUInt32LE(o + 4) });
  }

  // Section table
  const secTable = opt + buf.readUInt16LE(coff + 16);
  const sections = [];
  for (let i = 0; i < sectionCount; i++) {
    const o = secTable + i * 40;
    if (o + 40 > buf.length) break;
    const name = buf.toString('ascii', o, o + 8).replace(/\0.*$/, '');
    const vsize = buf.readUInt32LE(o + 8);
    const vaddr = buf.readUInt32LE(o + 12);
    const rawsize = buf.readUInt32LE(o + 16);
    const rawptr = buf.readUInt32LE(o + 20);
    const chars = buf.readUInt32LE(o + 36);
    const flags = [];
    if (chars & 0x20000000) flags.push('X');
    if (chars & 0x40000000) flags.push('R');
    if (chars & 0x80000000) flags.push('W');
    sections.push({
      name, vsize, vaddr, rawsize, rawptr, chars, flags,
      entropy: null // filled by scanner
    });
  }

  const rvaToOffset = (rva) => {
    for (const s of sections) {
      if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) {
        return s.rawptr + (rva - s.vaddr);
      }
    }
    return -1;
  };

  // Import directory (DataDirectory index 1)
  const importDir = dataDirs[1];
  const imports = [];
  if (importDir && importDir.rva) {
    const baseOff = rvaToOffset(importDir.rva);
    if (baseOff >= 0) {
      const thunkSize = is64 ? 8 : 4;
      const ordMask = is64 ? 0x8000000000000000n : 0x80000000n;
      for (let i = 0; i < 1024; i++) {
        const d = baseOff + i * 20;
        if (d + 20 > buf.length) break;
        const firstThunk = buf.readUInt32LE(d + 16);
        const nameRva = buf.readUInt32LE(d + 12);
        if (!firstThunk && !nameRva) break;
        const nameOff = rvaToOffset(nameRva);
        const dllName = nameOff >= 0 && nameOff < buf.length
          ? buf.toString('ascii', nameOff).replace(/\0.*$/, '')
          : '?';
        const functions = [];
        let ft = firstThunk ? rvaToOffset(firstThunk) : -1;
        let limit = 0;
        while (ft > 0 && ft + thunkSize <= buf.length && limit < 4096) {
          const val = is64 ? buf.readBigUInt64LE(ft) : BigInt(buf.readUInt32LE(ft));
          if (val === 0n) break;
          if ((val & ordMask) === 0n) {
            const hintOff = rvaToOffset(Number(val & 0x7fffffffn));
            if (hintOff >= 0 && hintOff + 2 < buf.length) {
              const fn = buf.toString('ascii', hintOff + 2).replace(/\0.*$/, '');
              if (fn && !functions.includes(fn)) functions.push(fn);
            }
          }
          ft += thunkSize;
          limit++;
        }
        imports.push({ dll: dllName, functions });
      }
    }
  }

  // Export directory (index 0) — presence only
  const hasExports = !!(dataDirs[0] && dataDirs[0].rva);
  // Resource directory (index 2)
  const hasResources = !!(dataDirs[2] && dataDirs[2].rva);
  // TLS directory (index 13) — presence of TLS callbacks
  const hasTLS = !!(dataDirs[13] && dataDirs[13].rva);
  // Debug directory (index 6)
  const hasDebug = !!(dataDirs[6] && dataDirs[6].rva);
  // Security directory (index 4) — Authenticode signature
  const securityDir = dataDirs[4];
  const hasSignature = !!(securityDir && securityDir.size > 0);

  // Overlay: bytes after the last section's raw data
  let maxRawEnd = 0;
  for (const s of sections) {
    if (s.rawptr + s.rawsize > maxRawEnd) maxRawEnd = s.rawptr + s.rawsize;
  }
  const overlaySize = maxRawEnd < buf.length ? buf.length - maxRawEnd : 0;

  // All imported function names (flattened)
  const allImports = [];
  for (const imp of imports) {
    for (const f of imp.functions) allImports.push(imp.dll + '!' + f);
  }

  return {
    type: 'PE',
    machine: MACHINE_NAMES[machine] || ('0x' + machine.toString(16)),
    is64,
    imageBase: Number(imageBase),
    subsystem: SUBSYSTEM_NAMES[subsystem] || ('0x' + subsystem.toString(16)),
    entryPoint,
    isDLL,
    isStripped,
    timeDateStamp: timeDateStamp || null,
    characteristics,
    sections,
    imports,
    allImports,
    hasExports,
    hasResources,
    hasTLS,
    hasDebug,
    hasSignature,
    overlaySize,
    size: buf.length
  };
}

module.exports = { parsePE, MACHINE_NAMES, SUBSYSTEM_NAMES };
