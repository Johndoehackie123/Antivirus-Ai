'use strict';
/**
 * Builds a minimal but REAL PE32 executable (synthetic, for testing the
 * SentinelGuard engine). It imports the classic process-injection API set
 * from kernel32/user32 and contains suspicious strings. It is NOT a real
 * malware sample — it's a static analysis test fixture.
 */
const FILE_ALIGN = 0x200;
const SEC_ALIGN = 0x1000;

const kernel32Fns = ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread', 'GetProcAddress', 'LoadLibraryA', 'VirtualAlloc', 'VirtualProtect', 'CreateThread', 'IsDebuggerPresent'];
const user32Fns = ['SetWindowsHookExA', 'GetAsyncKeyState'];

function buildTestPE() {
  const buf = Buffer.alloc(0x800);

  // ---- DOS header ----
  buf.writeUInt16LE(0x5a4d, 0); // MZ
  buf.writeUInt32LE(0x80, 0x3c); // e_lfanew

  // ---- PE signature ----
  buf.writeUInt32LE(0x00004550, 0x80); // PE\0\0

  // ---- COFF header (0x84) ----
  buf.writeUInt16LE(0x14c, 0x84); // Machine i386
  buf.writeUInt16LE(2, 0x86); // NumberOfSections
  buf.writeUInt32LE(0, 0x88); // TimeDateStamp
  buf.writeUInt32LE(0, 0x8c); // PointerToSymbolTable
  buf.writeUInt32LE(0, 0x90); // NumberOfSymbols
  buf.writeUInt16LE(0xe0, 0x94); // SizeOfOptionalHeader
  buf.writeUInt16LE(0x0102, 0x96); // Characteristics

  // ---- Optional header (0x98) ----
  const opt = 0x98;
  buf.writeUInt16LE(0x10b, opt); // Magic PE32
  buf.writeUInt16LE(12, opt + 2); // MajorLinkerVersion
  buf.writeUInt32LE(0x200, opt + 4); // SizeOfCode
  buf.writeUInt32LE(0x400, opt + 8); // SizeOfInitializedData
  buf.writeUInt32LE(0x1000, opt + 16); // AddressOfEntryPoint
  buf.writeUInt32LE(0x1000, opt + 20); // BaseOfCode
  buf.writeUInt32LE(0x2000, opt + 24); // BaseOfData
  buf.writeUInt32LE(0x400000, opt + 28); // ImageBase
  buf.writeUInt32LE(SEC_ALIGN, opt + 32); // SectionAlignment
  buf.writeUInt32LE(FILE_ALIGN, opt + 36); // FileAlignment
  buf.writeUInt16LE(6, opt + 40); // MajorOSVersion
  buf.writeUInt16LE(0, opt + 42);
  buf.writeUInt16LE(6, opt + 48); // MajorSubsystemVersion
  buf.writeUInt32LE(0x3000, opt + 56); // SizeOfImage
  buf.writeUInt32LE(FILE_ALIGN, opt + 60); // SizeOfHeaders
  buf.writeUInt16LE(3, opt + 68); // Subsystem = CUI
  buf.writeUInt32LE(0x100000, opt + 72); // SizeOfStackReserve
  buf.writeUInt32LE(0x1000, opt + 76);
  buf.writeUInt32LE(0x100000, opt + 80);
  buf.writeUInt32LE(0x1000, opt + 84);
  buf.writeUInt32LE(16, opt + 92); // NumberOfRvaAndSizes
  // DataDirectory[1] = Import at RVA 0x2000 size 0x100
  buf.writeUInt32LE(0x2000, opt + 96 + 8);
  buf.writeUInt32LE(0x100, opt + 96 + 12);

  // ---- Section table (0x178) ----
  // .text: RVA 0x1000, raw 0x200
  buf.write('.text', 0x178, 'ascii');
  buf.writeUInt32LE(0x200, 0x178 + 8); // VirtualSize
  buf.writeUInt32LE(0x1000, 0x178 + 12); // VirtualAddress
  buf.writeUInt32LE(0x200, 0x178 + 16); // SizeOfRawData
  buf.writeUInt32LE(0x200, 0x178 + 20); // PointerToRawData
  buf.writeUInt32LE(0x60000020, 0x178 + 36); // CODE|EXECUTE|READ
  // .rdata: RVA 0x2000, raw 0x400
  buf.write('.rdata', 0x178 + 40, 'ascii');
  buf.writeUInt32LE(0x400, 0x178 + 48); // VirtualSize
  buf.writeUInt32LE(0x2000, 0x178 + 52); // VirtualAddress
  buf.writeUInt32LE(0x400, 0x178 + 56); // SizeOfRawData
  buf.writeUInt32LE(0x400, 0x178 + 60); // PointerToRawData
  buf.writeUInt32LE(0x40000040, 0x178 + 76); // INITIALIZED_DATA|READ

  // ---- .text content: ret + suspicious strings ----
  buf.writeUInt8(0xc3, 0x200); // ret
  buf.write('cmd.exe /c', 0x210, 'ascii');
  buf.write('powershell', 0x230, 'ascii');
  buf.write('CurrentVersion\\Run', 0x250, 'ascii');

  // ---- .rdata content: import table ----
  const rdata = 0x400; // file offset of .rdata; RVA base 0x2000
  const rva = (off) => 0x2000 + off;

  // Import descriptors
  // desc0: kernel32
  buf.writeUInt32LE(rva(0x100), rdata + 0x00); // OriginalFirstThunk
  buf.writeUInt32LE(0, rdata + 0x04);
  buf.writeUInt32LE(0, rdata + 0x08);
  buf.writeUInt32LE(rva(0x220), rdata + 0x0c); // Name
  buf.writeUInt32LE(rva(0x140), rdata + 0x10); // FirstThunk
  // desc1: user32
  buf.writeUInt32LE(rva(0x180), rdata + 0x14); // OriginalFirstThunk
  buf.writeUInt32LE(0, rdata + 0x18);
  buf.writeUInt32LE(0, rdata + 0x1c);
  buf.writeUInt32LE(rva(0x240), rdata + 0x20); // Name
  buf.writeUInt32LE(rva(0x1c0), rdata + 0x24); // FirstThunk
  // desc2: null
  buf.writeUInt32LE(0, rdata + 0x28);
  buf.writeUInt32LE(0, rdata + 0x2c);
  buf.writeUInt32LE(0, rdata + 0x30);
  buf.writeUInt32LE(0, rdata + 0x34);

  // ILT1 (kernel32 thunks) at rdata+0x100
  let hint = 0x280; // hint/name section offset within rdata
  const ilt1 = rdata + 0x100;
  for (let i = 0; i < kernel32Fns.length; i++) {
    buf.writeUInt32LE(rva(hint), ilt1 + i * 4);
    hint += kernel32Fns[i].length + 3;
    if (hint % 2) hint++;
  }
  buf.writeUInt32LE(0, ilt1 + kernel32Fns.length * 4);

  // IAT1 (FirstThunk) at rdata+0x140 — same values (static binding)
  for (let i = 0; i <= kernel32Fns.length; i++) {
    buf.writeUInt32LE(buf.readUInt32LE(ilt1 + i * 4), rdata + 0x140 + i * 4);
  }

  // ILT2 (user32 thunks) at rdata+0x180
  const ilt2 = rdata + 0x180;
  for (let i = 0; i < user32Fns.length; i++) {
    buf.writeUInt32LE(rva(hint), ilt2 + i * 4);
    hint += user32Fns[i].length + 3;
    if (hint % 2) hint++;
  }
  buf.writeUInt32LE(0, ilt2 + user32Fns.length * 4);

  // IAT2 at rdata+0x1c0
  for (let i = 0; i <= user32Fns.length; i++) {
    buf.writeUInt32LE(buf.readUInt32LE(ilt2 + i * 4), rdata + 0x1c0 + i * 4);
  }

  // hint/name entries at rdata+0x280
  let hn = 0x280;
  for (const fn of kernel32Fns) {
    buf.writeUInt16LE(0, rdata + hn); // hint
    buf.write(fn + '\0', rdata + hn + 2, 'ascii');
    hn += fn.length + 3;
    if (hn % 2) hn++;
  }
  for (const fn of user32Fns) {
    buf.writeUInt16LE(0, rdata + hn);
    buf.write(fn + '\0', rdata + hn + 2, 'ascii');
    hn += fn.length + 3;
    if (hn % 2) hn++;
  }

  // DLL names
  buf.write('kernel32.dll\0', rdata + 0x220, 'ascii');
  buf.write('user32.dll\0', rdata + 0x240, 'ascii');

  return buf;
}

module.exports = { buildTestPE };
