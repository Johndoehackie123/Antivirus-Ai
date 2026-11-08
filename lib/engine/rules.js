'use strict';

/**
 * SentinelGuard AI heuristic detection rule database.
 * Each rule: id, name, family, severity, weight, description, match(ctx), evidence(ctx).
 * Weights are tuned so verdicts land in realistic ranges (score = sum of weights, cap 100).
 *
 * ctx = {
 *   fileType, ext, size, entropy, head (Buffer),
 *   strings: { ascii, utf16, all },
 *   hasAny(s), hasAscii(s), hasUtf16(s), regexAscii(re),
 *   pe: PE info | null, elf: ELF info | null,
 *   imports: Set<string> (PE import names, or ELF symbols),
 *   importsHas(name), importsAny([...])
 * }
 */

const S = {
  ascii: (ctx) => ctx.strings.ascii,
  utf16: (ctx) => ctx.strings.utf16,
  all: (ctx) => ctx.strings.all
};

const hasAll = (ctx, needles) =>
  needles.every((s) => ctx.strings.all.some((x) => x.toLowerCase().includes(s.toLowerCase())));

const hasAnyStr = (ctx, needles) =>
  needles.some((s) => ctx.strings.all.some((x) => x.toLowerCase().includes(s.toLowerCase())));

const anyImport = (ctx, names) => names.some((n) => ctx.imports.has(n));

const hasToken = (ctx, tokens) => {
  const text = ctx.strings.all.join('\n').toLowerCase();
  return tokens.some((t) => new RegExp('(^|\\W)' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(\\W|$)').test(text));
};

const allImports = (ctx, names) => names.every((n) => ctx.imports.has(n));

const rule = (r) => r;

const RULES = [
  // ============================ PE / Win32 behavioral ============================
  rule({
    id: 'SG-PE-INJ-001',
    name: 'Process Injection (CreateRemoteThread)',
    family: 'Injection',
    severity: 'critical',
    weight: 45,
    description: 'Imports VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — the classic cross-process code injection sequence.',
    match: (ctx) => ctx.pe && allImports(ctx, ['VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread']),
    evidence: (ctx) => ['Imports VirtualAllocEx', 'Imports WriteProcessMemory', 'Imports CreateRemoteThread']
  }),
  rule({
    id: 'SG-PE-INJ-002',
    name: 'Process Injection (QueueUserAPC)',
    family: 'Injection',
    severity: 'critical',
    weight: 45,
    description: 'Imports VirtualAllocEx + WriteProcessMemory + QueueUserAPC — APC-based injection into another process.',
    match: (ctx) => ctx.pe && allImports(ctx, ['VirtualAllocEx', 'WriteProcessMemory', 'QueueUserAPC']),
    evidence: (ctx) => ['Imports VirtualAllocEx', 'Imports WriteProcessMemory', 'Imports QueueUserAPC']
  }),
  rule({
    id: 'SG-PE-INJ-003',
    name: 'Process Injection (NtCreateThreadEx)',
    family: 'Injection',
    severity: 'critical',
    weight: 43,
    description: 'Imports VirtualAllocEx + WriteProcessMemory + NtCreateThreadEx — modern injection primitive used by fileless malware.',
    match: (ctx) => ctx.pe && allImports(ctx, ['VirtualAllocEx', 'WriteProcessMemory', 'NtCreateThreadEx']),
    evidence: (ctx) => ['Imports VirtualAllocEx', 'Imports WriteProcessMemory', 'Imports NtCreateThreadEx']
  }),
  rule({
    id: 'SG-PE-HOLE-001',
    name: 'Process Hollowing',
    family: 'Injection',
    severity: 'critical',
    weight: 45,
    description: 'Imports VirtualAllocEx + WriteProcessMemory + SetThreadContext + ResumeThread — process hollowing / hollowed-process injection pattern.',
    match: (ctx) => ctx.pe && allImports(ctx, ['VirtualAllocEx', 'WriteProcessMemory', 'SetThreadContext', 'ResumeThread']),
    evidence: (ctx) => ['Imports VirtualAllocEx', 'Imports WriteProcessMemory', 'Imports SetThreadContext', 'Imports ResumeThread']
  }),
  rule({
    id: 'SG-PE-KEYLOG-001',
    name: 'Keylogging (GetAsyncKeyState)',
    family: 'Keylogging',
    severity: 'critical',
    weight: 42,
    description: 'Imports GetAsyncKeyState with hooking primitives — keystroke capture capability.',
    match: (ctx) => ctx.pe && ctx.imports.has('GetAsyncKeyState') && anyImport(ctx, ['SetWindowsHookExA', 'SetWindowsHookExW', 'keybd_event', 'GetKeyState', 'GetForegroundWindow']),
    evidence: (ctx) => ['Imports GetAsyncKeyState']
  }),
  rule({
    id: 'SG-PE-KEYLOG-002',
    name: 'Keylogging (Keyboard Hook)',
    family: 'Keylogging',
    severity: 'high',
    weight: 35,
    description: 'Imports SetWindowsHookEx — global keyboard hook installation (used by spyware).',
    match: (ctx) => ctx.pe && anyImport(ctx, ['SetWindowsHookExA', 'SetWindowsHookExW']) && anyImport(ctx, ['GetAsyncKeyState', 'GetForegroundWindow', 'GetWindowTextA', 'GetWindowTextW']),
    evidence: (ctx) => ['Imports SetWindowsHookExA/W', 'Hooks keyboard/window events']
  }),
  rule({
    id: 'SG-PE-PERS-001',
    name: 'Registry Run Key Persistence',
    family: 'Persistence',
    severity: 'high',
    weight: 32,
    description: 'References HKCU/HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run — autostart persistence.',
    match: (ctx) => hasAnyStr(ctx, ['CurrentVersion\\Run', 'CurrentVersion\\RunOnce', 'CurrentVersion\\Explorer\\Run']),
    evidence: (ctx) => ['Found "CurrentVersion\\Run" in strings']
  }),
  rule({
    id: 'SG-PE-PERS-002',
    name: 'Scheduled Task Persistence',
    family: 'Persistence',
    severity: 'high',
    weight: 30,
    description: 'References schtasks command — persistence via scheduled tasks.',
    match: (ctx) => hasAnyStr(ctx, ['schtasks /create', 'schtasks /sc create', 'schtasks /tr']),
    evidence: (ctx) => ['Found schtasks command in strings']
  }),
  rule({
    id: 'SG-PE-PERS-003',
    name: 'Service Persistence',
    family: 'Persistence',
    severity: 'high',
    weight: 33,
    description: 'Imports CreateService + references service installation — persistence as a Windows service.',
    match: (ctx) => ctx.pe && ctx.imports.has('CreateServiceA') && hasAnyStr(ctx, ['SERVICE_AUTO_START', 'create service', 'sc.exe create']),
    evidence: (ctx) => ['Imports CreateServiceA', 'References service creation strings']
  }),
  rule({
    id: 'SG-PE-PERS-004',
    name: 'Startup Folder Persistence',
    family: 'Persistence',
    severity: 'medium',
    weight: 22,
    description: 'References the Startup folder path — persistence via Startup items.',
    match: (ctx) => hasAnyStr(ctx, ['Start Menu\\Programs\\Startup', 'Microsoft\\Windows\\Start Menu\\Programs\\Startup']),
    evidence: (ctx) => ['Found Startup folder path in strings']
  }),
  rule({
    id: 'SG-PE-ANTVM-001',
    name: 'Anti-VM Detection',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 26,
    description: 'References VMware/VirtualBox/Hyper-V/QEMU/Xen — virtual environment detection, common in malware.',
    match: (ctx) => hasToken(ctx, ['vmware', 'virtualbox', 'vbox', 'hyper-v', 'qemu', 'xen', 'virtual machine']),
    evidence: (ctx) => ['Contains VM-vendor strings']
  }),
  rule({
    id: 'SG-PE-ANTDBG-001',
    name: 'Anti-Debugger (IsDebuggerPresent)',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 24,
    description: 'Imports IsDebuggerPresent alongside timing/memory primitives — debugger evasion.',
    match: (ctx) => ctx.pe && ctx.imports.has('IsDebuggerPresent') && anyImport(ctx, ['VirtualAlloc', 'VirtualProtect', 'GetTickCount', 'QueryPerformanceCounter', 'NtQueryInformationProcess', 'Sleep']),
    evidence: (ctx) => ['Imports IsDebuggerPresent']
  }),
  rule({
    id: 'SG-PE-ANTDBG-002',
    name: 'Anti-Debugger (NtQueryInformationProcess)',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 26,
    description: 'Imports NtQueryInformationProcess with debug-port queries — direct debugger detection.',
    match: (ctx) => ctx.pe && ctx.imports.has('NtQueryInformationProcess') && hasAnyStr(ctx, ['ProcessDebugPort', 'ProcessDebugFlags', 'ProcessDebugObjectHandle']),
    evidence: (ctx) => ['Imports NtQueryInformationProcess', 'Queries ProcessDebug* information classes']
  }),
  rule({
    id: 'SG-PE-ANTSB-001',
    name: 'Anti-Sandbox Detection',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 24,
    description: 'References sandbox/analysis tooling (Sandboxie, Cuckoo, Wireshark, Process Hacker, GMER).',
    match: (ctx) => hasAnyStr(ctx, ['Sandboxie', 'Cuckoo', 'Wireshark', 'ProcessHacker', 'GMER', 'AVMDebugger']),
    evidence: (ctx) => ['Contains anti-analysis tool strings']
  }),
  rule({
    id: 'SG-PE-RANS-001',
    name: 'Ransomware Extortion Text',
    family: 'Ransomware',
    severity: 'critical',
    weight: 45,
    description: 'Contains ransom notes / extortion text — "files encrypted", BITLOCKER, payment instructions.',
    match: (ctx) => hasAnyStr(ctx, ['Your files have been encrypted', 'files have been encrypted', 'decrypt all your files', 'BITLOCKER', 'contact us to decrypt', 'your files are encrypted', 'ransomware note']),
    evidence: (ctx) => ['Found ransomware extortion text']
  }),
  rule({
    id: 'SG-PE-RANS-002',
    name: 'Ransomware File-Change Monitoring',
    family: 'Ransomware',
    severity: 'high',
    weight: 35,
    description: 'Imports FindFirstChangeNotification — file-change watching used by ransomware to find and encrypt documents.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['FindFirstChangeNotificationA', 'FindFirstChangeNotificationW']) && hasAnyStr(ctx, ['encrypt', '.docx', '.pdf', '.jpg', '.zip']),
    evidence: (ctx) => ['Imports FindFirstChangeNotification', 'References document extensions in strings']
  }),
  rule({
    id: 'SG-PE-RANS-003',
    name: 'Ransomware Indicators (.onion + payment)',
    family: 'Ransomware',
    severity: 'high',
    weight: 35,
    description: 'References a .onion address and payment/contact language — dark-web ransomware contact channel.',
    match: (ctx) => hasAnyStr(ctx, ['.onion']) && hasAnyStr(ctx, ['payment', 'contact', 'decrypt', 'bitcoin', 'wallet']),
    evidence: (ctx) => ['Found .onion URL', 'Found payment/contact text']
  }),
  rule({
    id: 'SG-PE-CRYPT-001',
    name: 'Encryption Capability (CryptEncrypt)',
    family: 'Ransomware',
    severity: 'high',
    weight: 34,
    description: 'Imports CryptEncrypt + CryptCreateHash — file-encryption capability (ransomware building block).',
    match: (ctx) => ctx.pe && ctx.imports.has('CryptEncrypt') && anyImport(ctx, ['CryptCreateHash', 'CryptDeriveKey', 'CryptEncrypt', 'BCryptEncrypt']),
    evidence: (ctx) => ['Imports CryptEncrypt', 'Imports cryptographic hash/key APIs']
  }),
  rule({
    id: 'SG-PE-MINER-001',
    name: 'Cryptomining Indicators',
    family: 'Cryptomining',
    severity: 'high',
    weight: 35,
    description: 'Contains stratum pool URLs / xmrig / coinhive — cryptocurrency mining.',
    match: (ctx) => hasAnyStr(ctx, ['stratum+tcp://', 'stratum+ssl://', 'xmrig', 'coinhive', 'mining pool', 'cryptonight', 'monero']),
    evidence: (ctx) => ['Found mining pool / miner strings']
  }),
  rule({
    id: 'SG-PE-CRED-001',
    name: 'Credential Access (LSASS / SAM)',
    family: 'Credential Access',
    severity: 'critical',
    weight: 42,
    description: 'References LSASS/SAM registry hives — credential dumping (e.g. Mimikatz-style).',
    match: (ctx) => hasAnyStr(ctx, ['lsass', 'SAM\\domain', 'reg save', '\\SAM', 'LOCAL_MACHINE\\SAM']) && ctx.pe,
    evidence: (ctx) => ['Found LSASS/SAM references']
  }),
  rule({
    id: 'SG-PE-CRED-002',
    name: 'Credential Access (DPAPI / Credential Manager)',
    family: 'Credential Access',
    severity: 'high',
    weight: 30,
    description: 'Imports CryptUnprotectData — DPAPI decryption used to steal stored passwords.',
    match: (ctx) => ctx.pe && ctx.imports.has('CryptUnprotectData') && hasAnyStr(ctx, ['password', 'cred', 'secret', 'Login Data', 'Cookies']),
    evidence: (ctx) => ['Imports CryptUnprotectData', 'References password/cookie strings']
  }),
  rule({
    id: 'SG-PE-CRED-003',
    name: 'Browser Credential Theft',
    family: 'Credential Access',
    severity: 'high',
    weight: 33,
    description: 'References browser profile paths (Chrome/Firefox Login Data, Cookies) — credential/cookie theft.',
    match: (ctx) => hasAnyStr(ctx, ['User Data\\Default\\Login Data', 'logins.json', 'signons.sqlite', 'Cookies', 'Network\\Cookies']),
    evidence: (ctx) => ['Found browser profile paths']
  }),
  rule({
    id: 'SG-PE-PS-001',
    name: 'PowerShell Encoded Command',
    family: 'PowerShell Abuse',
    severity: 'high',
    weight: 35,
    description: 'Contains PowerShell -EncodedCommand / -enc payload — obfuscated script execution.',
    match: (ctx) => hasAnyStr(ctx, ['powershell -enc', 'powershell -e ', '-EncodedCommand', 'powershell.exe -enc', 'pwsh -enc']),
    evidence: (ctx) => ['Found encoded PowerShell command']
  }),
  rule({
    id: 'SG-PE-PS-002',
    name: 'PowerShell Download Cradle',
    family: 'PowerShell Abuse',
    severity: 'high',
    weight: 34,
    description: 'PowerShell + IEX/Net.WebClient/DownloadString — classic download-and-execute cradle.',
    match: (ctx) => hasAnyStr(ctx, ['powershell', 'pwsh']) && hasAnyStr(ctx, ['Invoke-Expression', 'IEX(', 'Net.WebClient', 'Invoke-WebRequest', 'DownloadString']) && hasAnyStr(ctx, ['http', 'download']),
    evidence: (ctx) => ['Found download-and-execute PowerShell constructs']
  }),
  rule({
    id: 'SG-PE-DL-001',
    name: 'Dropper (URLDownloadToFile)',
    family: 'Downloader',
    severity: 'high',
    weight: 32,
    description: 'Imports URLDownloadToFile — downloads and executes remote payloads.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['URLDownloadToFileA', 'URLDownloadToFileW']),
    evidence: (ctx) => ['Imports URLDownloadToFile']
  }),
  rule({
    id: 'SG-PE-DL-002',
    name: 'Dropper (InternetReadFile + WriteFile)',
    family: 'Downloader',
    severity: 'high',
    weight: 30,
    description: 'InternetReadFile + CreateFile/WriteFile combination — downloads payload and writes to disk.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['InternetReadFile', 'InternetOpenA', 'InternetOpenW']) && anyImport(ctx, ['WriteFile', 'CreateFileA', 'CreateFileW']),
    evidence: (ctx) => ['Imports InternetReadFile', 'Imports file-write APIs']
  }),
  rule({
    id: 'SG-PE-CMD-001',
    name: 'Suspicious Shell Execution',
    family: 'System Modification',
    severity: 'medium',
    weight: 26,
    description: 'cmd.exe /c with PowerShell/certutil/bitsadmin/mshta/regsvr32 — command-line abuse chain.',
    match: (ctx) => hasAnyStr(ctx, ['cmd.exe /c', 'cmd /c', 'cmd.exe /k']) && hasAnyStr(ctx, ['powershell', 'certutil', 'bitsadmin', 'mshta', 'regsvr32', 'curl', 'wget']),
    evidence: (ctx) => ['Found cmd.exe /c with suspicious child commands']
  }),
  rule({
    id: 'SG-PE-CMD-002',
    name: 'Certutil Decode',
    family: 'System Modification',
    severity: 'medium',
    weight: 24,
    description: 'certutil -decode — frequently used to decode encoded payloads.',
    match: (ctx) => hasAnyStr(ctx, ['certutil -decode', 'certutil.exe -decode']),
    evidence: (ctx) => ['Found certutil -decode command']
  }),
  rule({
    id: 'SG-PE-CMD-003',
    name: 'BITS Job Abuse',
    family: 'System Modification',
    severity: 'medium',
    weight: 24,
    description: 'bitsadmin usage — BITS job abuse for stealthy downloads.',
    match: (ctx) => hasAnyStr(ctx, ['bitsadmin /transfer', 'bitsadmin.exe /transfer']),
    evidence: (ctx) => ['Found bitsadmin /transfer command']
  }),
  rule({
    id: 'SG-PE-CMD-004',
    name: 'MSHTA Invocation',
    family: 'System Modification',
    severity: 'medium',
    weight: 24,
    description: 'mshta invocation — executes remote HTA/VBScript (fileless malware vector).',
    match: (ctx) => hasAnyStr(ctx, ['mshta http', 'mshta vbscript', 'mshta.exe http']),
    evidence: (ctx) => ['Found mshta remote invocation']
  }),
  rule({
    id: 'SG-PE-C2-001',
    name: 'C2 / Botnet Indicators',
    family: 'C2 Communication',
    severity: 'high',
    weight: 33,
    description: 'HTTP imports + bot/backdoor/shell language — command-and-control capability.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['InternetOpenA', 'InternetOpenW', 'HttpSendRequestA', 'HttpSendRequestW', 'WSAStartup']) && hasAnyStr(ctx, ['bot', 'c2', 'backdoor', 'shell', 'malware', 'reverse']),
    evidence: (ctx) => ['Imports HTTP/winsock APIs', 'Contains C2/bot strings']
  }),
  rule({
    id: 'SG-PE-C2-002',
    name: 'Suspicious TLD Domains',
    family: 'C2 Communication',
    severity: 'medium',
    weight: 26,
    description: 'References high-risk TLDs commonly abused by malware infrastructure.',
    match: (ctx) => /https?:\/\/[a-z0-9.-]+\.(top|xyz|club|click|loan|date|download|stream|review|gq|tk|ml|ga|cf|pw|biz|online|site|space|fun|live|cc|su|cm|kim|win|bid|red|world)\b/i.test(ctx.strings.all.join('\n')),
    evidence: (ctx) => ['Found domain with high-risk TLD in strings']
  }),
  rule({
    id: 'SG-PE-C2-003',
    name: 'Raw IP Address C2',
    family: 'C2 Communication',
    severity: 'medium',
    weight: 22,
    description: 'Contains raw IPv4 address + bot/shell language — direct C2 server reference.',
    match: (ctx) => /(?:^|\D)(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|[1-9]?\d?\.){3}(?:1?\d{1,3}|2[0-4]\d|25[0-5])(?:\D|$)/.test(ctx.strings.all.join('\n')) && hasAnyStr(ctx, ['bot', 'c2', 'shell', 'backdoor', 'connect']),
    evidence: (ctx) => ['Found IPv4 address', 'Found C2/bot language']
  }),
  rule({
    id: 'SG-PE-SC-001',
    name: 'Screen Capture Capability',
    family: 'Surveillance',
    severity: 'medium',
    weight: 20,
    description: 'Imports BitBlt/GetDIBits/CreateCompatibleDC — screen capture capability.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['BitBlt', 'GetDIBits', 'CreateCompatibleDC']),
    evidence: (ctx) => ['Imports GDI screen-capture APIs']
  }),
  rule({
    id: 'SG-PE-SC-002',
    name: 'Clipboard Monitoring',
    family: 'Surveillance',
    severity: 'low',
    weight: 12,
    description: 'Imports OpenClipboard/GetClipboardData — clipboard access (crypto-stealer pattern).',
    match: (ctx) => ctx.pe && anyImport(ctx, ['OpenClipboard', 'GetClipboardData']),
    evidence: (ctx) => ['Imports clipboard APIs']
  }),
  rule({
    id: 'SG-PE-TLS-001',
    name: 'TLS Callbacks Present',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 18,
    description: 'Binary registers TLS callbacks — code runs before the main entry point (evasion technique).',
    match: (ctx) => ctx.pe && ctx.pe.hasTLS,
    evidence: (ctx) => ['TLS directory present (code executes pre-entry)']
  }),
  rule({
    id: 'SG-PE-DYN-001',
    name: 'Dynamic API Resolution',
    family: 'Anti-Analysis',
    severity: 'medium',
    weight: 22,
    description: 'Heavy GetProcAddress/LoadLibrary use — resolves APIs at runtime to evade static signatures.',
    match: (ctx) => ctx.pe && ctx.imports.has('GetProcAddress') && anyImport(ctx, ['LoadLibraryA', 'LoadLibraryW']) && ctx.pe.allImports.filter((x) => x.includes('!GetProcAddress')).length > 0,
    evidence: (ctx) => ['Imports GetProcAddress + LoadLibrary', 'Resolves APIs dynamically']
  }),
  rule({
    id: 'SG-PE-PK-001',
    name: 'High-Entropy Packed Binary',
    family: 'Packer',
    severity: 'medium',
    weight: 25,
    description: 'File entropy above 7.2 bits/byte with small size — packed or self-extracting payload.',
    match: (ctx) => ctx.entropy > 7.2 && ctx.size < 2 * 1024 * 1024 && ctx.fileType === 'PE',
    evidence: (ctx) => [`Entropy ${ctx.entropy.toFixed(2)} > 7.20`, 'Small size with maximally-random bytes']
  }),
  rule({
    id: 'SG-PE-PK-002',
    name: 'High-Entropy Section',
    family: 'Packer',
    severity: 'medium',
    weight: 22,
    description: 'Individual section entropy above 7.4 — packed/encrypted section.',
    match: (ctx) => ctx.pe && ctx.pe.sections.some((s) => s.entropy != null && s.entropy > 7.4),
    evidence: (ctx) => ctx.pe.sections.filter((s) => s.entropy > 7.4).map((s) => `Section ${s.name} entropy ${s.entropy.toFixed(2)}`)
  }),
  rule({
    id: 'SG-PE-PK-003',
    name: 'UPX Packer',
    family: 'Packer',
    severity: 'medium',
    weight: 25,
    description: 'UPX0/UPX1 sections — packed with UPX (common in malware to shrink binaries).',
    match: (ctx) => ctx.pe && (ctx.pe.sections.some((s) => s.name === 'UPX0' || s.name === 'UPX1') || hasAnyStr(ctx, ['UPX!'])),
    evidence: (ctx) => ['UPX section names present']
  }),
  rule({
    id: 'SG-PE-PK-004',
    name: 'W+X Section Violation',
    family: 'Packer',
    severity: 'medium',
    weight: 25,
    description: 'More than one section is both writable and executable — W^X violation, common in shellcode/loaders.',
    match: (ctx) => ctx.pe && ctx.pe.sections.filter((s) => s.flags.includes('W') && s.flags.includes('X')).length > 1,
    evidence: (ctx) => ctx.pe.sections.filter((s) => s.flags.includes('W') && s.flags.includes('X')).map((s) => `Section ${s.name} is W+X`)
  }),
  rule({
    id: 'SG-PE-PK-005',
    name: 'No Import Directory',
    family: 'Packer',
    severity: 'medium',
    weight: 20,
    description: 'PE file without an import directory — typically packed or obfuscated (imports resolved at runtime).',
    match: (ctx) => ctx.pe && !ctx.pe.hasImportDir && ctx.size > 100 * 1024,
    evidence: (ctx) => ['No import table present']
  }),
  rule({
    id: 'SG-PE-SHELL-001',
    name: 'Suspected Shellcode (tiny + high entropy)',
    family: 'Shellcode',
    severity: 'critical',
    weight: 42,
    description: 'Tiny binary with high entropy and shellcode-execution imports (VirtualAlloc + CreateThread) — likely position-independent shellcode.',
    match: (ctx) => ctx.pe && ctx.size < 40 * 1024 && ctx.entropy > 6.5 && anyImport(ctx, ['VirtualAlloc', 'VirtualProtect', 'CreateThread', 'CallWindowProcW', 'CallWindowProcA']),
    evidence: (ctx) => [`Size ${ctx.size} bytes`, `Entropy ${ctx.entropy.toFixed(2)}`, 'Imports VirtualAlloc/CreateThread']
  }),
  rule({
    id: 'SG-PE-OVL-001',
    name: 'Large Overlay Data',
    family: 'Payload Embedding',
    severity: 'medium',
    weight: 20,
    description: 'Large data appended after the last section (>1 MB) — embedded payload, configuration, or archive.',
    match: (ctx) => (ctx.pe && ctx.pe.overlaySize > 1024 * 1024) || (ctx.elf && ctx.elf.overlaySize > 1024 * 1024),
    evidence: (ctx) => [`Overlay size ${ctx.pe ? ctx.pe.overlaySize : ctx.elf.overlaySize} bytes`]
  }),
  rule({
    id: 'SG-PE-EXEC-001',
    name: 'CreateProcess Execution',
    family: 'System Modification',
    severity: 'low',
    weight: 14,
    description: 'Imports CreateProcess — launches external processes.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['CreateProcessA', 'CreateProcessW', 'WinExec', 'ShellExecuteA', 'ShellExecuteW']),
    evidence: (ctx) => ['Imports process-creation APIs']
  }),
  rule({
    id: 'SG-PE-NET-001',
    name: 'Network Communication',
    family: 'Network',
    severity: 'low',
    weight: 10,
    description: 'Imports Winsock/Internet APIs — network communication capability.',
    match: (ctx) => ctx.pe && anyImport(ctx, ['WSAStartup', 'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW']),
    evidence: (ctx) => ['Imports network APIs']
  }),
  rule({
    id: 'SG-PE-WIN-001',
    name: 'Window/GUI Capability',
    family: 'Behavior',
    severity: 'info',
    weight: 0,
    description: 'GUI-capable Windows executable (subsystem 2).',
    match: (ctx) => ctx.pe && ctx.pe.subsystem === 'WINDOWS_GUI',
    evidence: (ctx) => ['Windows GUI subsystem']
  }),

  // ============================ ELF / Linux ============================
  rule({
    id: 'SG-ELF-001',
    name: 'Shared Library (ELF DYN)',
    family: 'Behavior',
    severity: 'info',
    weight: 0,
    description: 'ELF shared object (PIE library) — contains exported symbols and dependencies.',
    match: (ctx) => ctx.elf && ctx.elf.typeName === 'DYN',
    evidence: (ctx) => [`Type DYN (${ctx.elf.machine})`]
  }),
  rule({
    id: 'SG-ELF-002',
    name: 'Rootkit-Suspicious Capability (ptrace/process hiding)',
    family: 'System Modification',
    severity: 'high',
    weight: 33,
    description: 'ELF binary referencing ptrace/process manipulation — process-hiding/rootkit capability.',
    match: (ctx) => ctx.elf && hasToken(ctx, ['ptrace']) && ctx.elf.symbols.some((s) => /(^|\W)ptrace(\W|$)|hid_process|hide_process|process_hide/i.test(s)),
    evidence: (ctx) => ['References ptrace / process hiding symbols']
  }),
  rule({
    id: 'SG-ELF-003',
    name: 'ELF Reverse-Shell Strings',
    family: 'C2 Communication',
    severity: 'high',
    weight: 33,
    description: 'Contains reverse-shell constructs — /dev/tcp, nc -e, bash -i.',
    match: (ctx) => hasAnyStr(ctx, ['bash -i >& /dev/tcp/', 'nc -e /bin', 'nc -e /', 'python -c import socket', 'socat.*-,listen']),
    evidence: (ctx) => ['Found reverse-shell strings']
  }),

  // ============================ Scripts / documents ============================
  rule({
    id: 'SG-SC-PS-001',
    name: 'PowerShell Encoded Payload (script)',
    family: 'PowerShell Abuse',
    severity: 'high',
    weight: 33,
    description: 'PowerShell script with encoded payload / FromBase64String + Invoke — obfuscated execution.',
    match: (ctx) => ['ps1', 'psm1', 'psd1', 'ps1xml'].includes(ctx.ext) && hasAnyStr(ctx, ['-EncodedCommand', 'FromBase64String', 'powershell -enc']),
    evidence: (ctx) => ['Found Base64-encoded PowerShell payload']
  }),
  rule({
    id: 'SG-SC-PS-002',
    name: 'PowerShell Download Cradle (script)',
    family: 'PowerShell Abuse',
    severity: 'high',
    weight: 33,
    description: 'PowerShell script with download-and-execute cradle (IEX + WebClient/Invoke-WebRequest).',
    match: (ctx) => ['ps1', 'psm1'].includes(ctx.ext) && hasAnyStr(ctx, ['Invoke-Expression', 'IEX(', 'Net.WebClient', 'Invoke-WebRequest', 'DownloadString']) && hasAnyStr(ctx, ['http']),
    evidence: (ctx) => ['Found download cradle in PowerShell script']
  }),
  rule({
    id: 'SG-SC-JS-001',
    name: 'JavaScript Obfuscation (eval+atob)',
    family: 'Script',
    severity: 'high',
    weight: 30,
    description: 'JavaScript eval(atob(...)) pattern — base64-obfuscated payload execution.',
    match: (ctx) => ['js', 'mjs', 'cjs'].includes(ctx.ext) && hasAnyStr(ctx, ['eval(atob', 'eval(decodeURIComponent', 'Function(atob', 'eval(Buffer.from']),
    evidence: (ctx) => ['Found eval(atob(...)) obfuscation']
  }),
  rule({
    id: 'SG-SC-JS-002',
    name: 'JavaScript Shell Execution',
    family: 'Script',
    severity: 'high',
    weight: 33,
    description: 'JavaScript child_process exec with download/shell commands — host execution capability.',
    match: (ctx) => ['js', 'mjs', 'cjs'].includes(ctx.ext) && hasAnyStr(ctx, ['child_process', 'exec(']) && hasAnyStr(ctx, ['curl ', 'wget ', 'powershell', 'cmd.exe', 'nc -e']),
    evidence: (ctx) => ['Found child_process + external commands']
  }),
  rule({
    id: 'SG-SC-VBS-001',
    name: 'VBScript Downloader',
    family: 'Script',
    severity: 'high',
    weight: 30,
    description: 'VBScript with WScript.Shell + URL download — script-based dropper.',
    match: (ctx) => ['vbs', 'vbe'].includes(ctx.ext) && hasAnyStr(ctx, ['WScript.Shell', 'CreateObject']) && hasAnyStr(ctx, ['http', 'download', 'execute']),
    evidence: (ctx) => ['Found WScript.Shell + download constructs']
  }),
  rule({
    id: 'SG-SC-BAT-001',
    name: 'Batch Dropper',
    family: 'Downloader',
    severity: 'medium',
    weight: 26,
    description: 'Batch file with curl/certutil/powershell download chains.',
    match: (ctx) => ['bat', 'cmd'].includes(ctx.ext) && hasAnyStr(ctx, ['curl ', 'certutil -decode', 'powershell -enc', 'bitsadmin']),
    evidence: (ctx) => ['Found download/decode chain in batch script']
  }),
  rule({
    id: 'SG-SC-SH-001',
    name: 'Shell Reverse Shell',
    family: 'C2 Communication',
    severity: 'critical',
    weight: 35,
    description: 'Shell script with reverse-shell construct (nc -e / /dev/tcp) — backdoor shell.',
    match: (ctx) => ['sh', 'bash'].includes(ctx.ext) && hasAnyStr(ctx, ['nc -e', 'bash -i >& /dev/tcp/', '0.0.0.0']),
    evidence: (ctx) => ['Found reverse-shell construct in shell script']
  }),
  rule({
    id: 'SG-SC-PY-001',
    name: 'Python Reverse-Shell / Socket',
    family: 'C2 Communication',
    severity: 'high',
    weight: 32,
    description: 'Python script with socket bind/connect + shell spawning — remote shell capability.',
    match: (ctx) => ctx.ext === 'py' && hasAnyStr(ctx, ['socket.socket', 'subprocess.Popen', 'os.system']) && hasAnyStr(ctx, ['/bin/sh', 'cmd.exe', 'pty.spawn']),
    evidence: (ctx) => ['Found socket + shell spawning in Python script']
  }),
  rule({
    id: 'SG-SC-MACRO-001',
    name: 'Office Document with Macros',
    family: 'Macro',
    severity: 'medium',
    weight: 28,
    description: 'OLE compound document containing VBA macro markers — macro-enabled document.',
    match: (ctx) => ctx.head.length >= 8 && ctx.head.toString('hex', 0, 8) === 'd0cf11e0a1b11ae1' && hasAnyStr(ctx, ['AutoOpen', 'Document_Open', 'Shell', 'DownloadFile', 'CreateObject']),
    evidence: (ctx) => ['OLE/CFB magic', 'Found macro markers in document strings']
  }),
  rule({
    id: 'SG-SC-GEN-001',
    name: 'Suspicious Script Obfuscation',
    family: 'Script',
    severity: 'medium',
    weight: 22,
    description: 'Script with heavy base64/hex-encoded blobs — obfuscated payload.',
    match: (ctx) => ['js', 'vbs', 'ps1', 'py', 'bat', 'cmd', 'sh'].includes(ctx.ext) && /[A-Za-z0-9+/]{80,}={0,2}/.test(ctx.strings.all.join('\n')) && ctx.strings.all.join('\n').length > 200,
    evidence: (ctx) => ['Found long base64 blob in script']
  }),
  rule({
    id: 'SG-ANY-ONION-001',
    name: 'Dark-Web C2 / Payment Reference',
    family: 'C2 Communication',
    severity: 'high',
    weight: 33,
    description: 'References .onion URLs together with payment/contact language.',
    match: (ctx) => hasAnyStr(ctx, ['.onion']) && hasAnyStr(ctx, ['payment', 'contact', 'decrypt', 'bitcoin', 'wallet']),
    evidence: (ctx) => ['Found .onion reference + payment language']
  }),
  rule({
    id: 'SG-ANY-ENC-001',
    name: 'Suspicious TLD + Bot Language',
    family: 'C2 Communication',
    severity: 'medium',
    weight: 24,
    description: 'High-risk TLD domain plus bot/backdoor language.',
    match: (ctx) => /[a-z0-9-]+\.(top|xyz|club|click|loan|tk|ml|ga|cf|pw|biz|online|site|space)\b/i.test(ctx.strings.all.join('\n')) && hasAnyStr(ctx, ['bot', 'c2', 'backdoor', 'malware', 'shell']),
    evidence: (ctx) => ['Found high-risk TLD domain', 'Found bot/malware language']
  })
];

module.exports = { RULES };
