'use strict';

/**
 * Minimal but real ELF parser.
 * Reads: class/endianness/type/machine, entry point, program headers (PT_INTERP),
 * section headers (names via shstrtab), SHT_DYNAMIC (DT_NEEDED libraries),
 * SHT_DYNSYM dynamic symbols (the "imports" of ELF binaries).
 */

const ELF_TYPE_NAMES = { 0: 'NONE', 1: 'RELOC', 2: 'EXEC', 3: 'DYN', 4: 'CORE' };
const ELF_MACHINE_NAMES = {
  0x03: 'x86', 0x3e: 'x86-64', 0x28: 'ARM', 0xb7: 'AArch64',
  0x08: 'MIPS', 0x14: 'PowerPC', 0x15: 'PowerPC64', 0x16: 'S390',
  0x01: 'SPARC', 0xf3: 'RISC-V'
};

function parseELF(buf) {
  if (buf.length < 64) return null;
  if (buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) return null;
  const is64 = buf[4] === 2;
  const isBE = buf[5] === 2;

  const rU16 = (o) => (isBE ? buf.readUIntBE(o, 2) : buf.readUIntLE(o, 2));
  const rU32 = (o) => (isBE ? buf.readUIntBE(o, 4) : buf.readUIntLE(o, 4));
  const rU64 = (o) => (isBE ? buf.readBigUInt64BE(o) : buf.readBigUInt64LE(o));
  const rNum = (o, n) => (n === 8 ? rU64(o) : rU32(o));

  const type = rU16(16);
  const machine = rU16(18);
  const entry = rNum(24, is64 ? 8 : 4);
  const phoff = Number(rNum(is64 ? 32 : 28, is64 ? 8 : 4));
  const phentsize = rU16(is64 ? 54 : 42);
  const phnum = rU16(is64 ? 56 : 44);
  const shoff = Number(rNum(is64 ? 40 : 32, is64 ? 8 : 4));
  const shentsize = rU16(is64 ? 58 : 46);
  const shnum = rU16(is64 ? 60 : 48);
  const shstrndx = rU16(is64 ? 62 : 50);

  // Program headers: PT_INTERP (3) => interpreter path
  let interp = null;
  const phTypes = [];
  for (let i = 0; i < phnum && phoff + i * phentsize + phentsize <= buf.length; i++) {
    const o = phoff + i * phentsize;
    const pType = rU32(o);
    phTypes.push(pType);
    if (pType === 3) { // PT_INTERP
      const offset = Number(rNum(is64 ? o + 8 : o + 4, is64 ? 8 : 4));
      const filesz = Number(rNum(is64 ? o + 32 : o + 16, is64 ? 8 : 4));
      if (offset >= 0 && offset + filesz <= buf.length) {
        interp = buf.toString('ascii', offset, offset + filesz).replace(/\0.*$/, '');
      }
    }
  }

  // Section headers
  const sections = [];
  for (let i = 0; i < shnum && shoff + i * shentsize + shentsize <= buf.length; i++) {
    const o = shoff + i * shentsize;
    const shName = rU32(o);
    const shType = rU32(o + 4);
    const shFlags = Number(rNum(is64 ? o + 8 : o + 8, is64 ? 8 : 4));
    const shAddr = Number(rNum(is64 ? o + 16 : o + 16, is64 ? 8 : 4));
    const shOffset = Number(rNum(is64 ? o + 24 : o + 16, is64 ? 8 : 4));
    const shSize = Number(rNum(is64 ? o + 32 : o + 20, is64 ? 8 : 4));
    const shLink = rU32(o + 40);
    sections.push({ nameOff: shName, type: shType, flags: shFlags, addr: shAddr, offset: shOffset, size: shSize, link: shLink });
  }

  // Section name string table
  let shstr = null;
  if (shstrndx < sections.length && sections[shstrndx]) {
    const s = sections[shstrndx];
    if (s.offset >= 0 && s.offset + s.size <= buf.length) {
      shstr = buf.toString('ascii', s.offset, s.offset + s.size).split('\0');
    }
  }
  const secName = (i) => (shstr && sections[i] && sections[i].nameOff < shstr.length ? shstr[sections[i].nameOff] : '');
  const sectionInfo = sections.map((s, i) => ({
    name: secName(i),
    type: s.type,
    flags: s.flags,
    addr: s.addr,
    size: s.size,
    offset: s.offset
  }));

  // Flag meanings
  const SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4;
  const sectionFlags = sectionInfo.map((s) => {
    const f = [];
    if (s.flags & SHF_WRITE) f.push('W');
    if (s.flags & SHF_ALLOC) f.push('A');
    if (s.flags & SHF_EXECINSTR) f.push('X');
    return f;
  });

  // SHT_DYNAMIC (6): DT_NEEDED (1) -> shared library dependencies
  const needed = [];
  for (let i = 0; i < sections.length; i++) {
    const s = sections[i];
    if (s.type !== 6 || !s.size) continue;
    const strtabIdx = s.link;
    if (strtabIdx >= sections.length) continue;
    const strtab = sections[strtabIdx];
    if (strtab.offset < 0 || strtab.offset + strtab.size > buf.length) continue;
    const strdata = buf.toString('ascii', strtab.offset, strtab.offset + strtab.size);
    const end = s.offset + s.size;
    let o = s.offset;
    while (o + (is64 ? 16 : 8) <= end) {
      const dTag = rU32(o);
      const dVal = Number(rNum(is64 ? o + 8 : o + 4, is64 ? 8 : 4));
      if (dTag === 0) break;
      if (dTag === 1) {
        const n = strdata.substring(dVal).split('\0')[0];
        if (n && !needed.includes(n)) needed.push(n);
      }
      o += is64 ? 16 : 8;
    }
  }

  // SHT_DYNSYM (11): dynamic symbols — ELF "imports"/"exports"
  const symbols = [];
  for (let i = 0; i < sections.length; i++) {
    const s = sections[i];
    if (s.type !== 11 || !s.size) continue;
    const strtabIdx = s.link;
    if (strtabIdx >= sections.length) continue;
    const strtab = sections[strtabIdx];
    if (strtab.offset < 0 || strtab.offset + strtab.size > buf.length) continue;
    const strdata = buf.toString('ascii', strtab.offset, strtab.offset + strtab.size);
    const es = is64 ? 24 : 16;
    const end = s.offset + s.size;
    let o = s.offset;
    let count = 0;
    while (o + es <= end && count < 20000) {
      const stName = rU32(o);
      const stInfo = buf[o + 4];
      const stType = stInfo & 0xf;
      const stValue = rNum(is64 ? o + 8 : o + 8, is64 ? 8 : 4);
      const stSize = rNum(is64 ? o + 16 : o + 12, is64 ? 8 : 4);
      // STT_NOTYPE=0, STT_OBJECT=1, STT_FUNC=2, STT_TLS=19
      if (stType === 1 || stType === 2 || stType === 19 || stType === 0) {
        const nm = strdata.substring(stName).split('\0')[0];
        if (nm && nm.length <= 120 && stName !== 0) symbols.push(nm);
      }
      o += es;
      count++;
    }
  }

  // Overlay: data after the last section's file range
  let maxEnd = 0;
  for (const s of sections) {
    if (s.offset >= 0 && s.offset + s.size > maxEnd) maxEnd = s.offset + s.size;
  }
  const overlaySize = maxEnd < buf.length ? buf.length - maxEnd : 0;

  return {
    type: 'ELF',
    class: is64 ? 'ELF64' : 'ELF32',
    endianness: isBE ? 'big' : 'little',
    typeName: ELF_TYPE_NAMES[type] || ('0x' + type.toString(16)),
    machine: ELF_MACHINE_NAMES[machine] || ('0x' + machine.toString(16)),
    entry: Number(entry),
    interp,
    programHeaders: phTypes,
    sections: sectionInfo,
    sectionFlags,
    needed,
    symbols,
    symbolCount: symbols.length,
    overlaySize,
    size: buf.length
  };
}

module.exports = { parseELF, ELF_TYPE_NAMES, ELF_MACHINE_NAMES };
