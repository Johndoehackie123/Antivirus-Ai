# 🛡️ SentinelGuard AI — Antivirus Platform

A fully functional, self-hosted antivirus web platform with real static analysis,
heuristic detection, behavioral profiling, real-time file guard, system scanning
and live process monitoring.

![status](https://img.shields.io/badge/engine-SentinelGuard%20AI%20v1.0-00d4ff)

## What it does (all real, no mocks)

### Analysis engine
- **Hashes** — MD5 / SHA-1 / SHA-256 / SHA-512 computed in real time
- **File type detection** — magic-byte recognition (PE, ELF, OLE/Office, PDF, ZIP, archives)
- **PE parser** — sections (flags + per-section entropy), import table (DLL + function names),
  Authenticode signature presence, TLS callbacks, overlay size
- **ELF parser** — class/machine/type, interpreter, section flags, `DT_NEEDED` libraries,
  dynamic symbols
- **String extraction** — ASCII + UTF-16LE
- **Entropy analysis** — Shannon entropy (packed / encrypted detection)
- **Signature database** — exact-hash matching + structural EICAR detection
  (industry-standard harmless test string)
- **62 heuristic rules** across families: injection, hollowing, keylogging, persistence,
  ransomware, credential access, cryptomining, C2, downloaders, PowerShell abuse,
  packers, shellcode, anti-analysis, surveillance
- **Behavioral profiling** — infers runtime behaviors (e.g., "Process Injection",
  "Credential Access") from imports/strings with confidence scores and evidence
- **Scoring & verdict** — `CLEAN` / `LOW RISK` / `SUSPICIOUS` / `MALICIOUS`

### Platform features
- **Upload & scan** — drag & drop any file; flagged files are auto-quarantined
- **System scan** — walks real directories (default `/home/user`, `/tmp`), hash-cached
- **Process monitor** — enumerates real processes from `/proc`, scans each executable
- **Real-time guard** — watches the `watch/` folder; new files are scanned instantly
  and quarantined if flagged
- **Quarantine manager** — restore or delete quarantined files
- **Signature DB viewer** — inspect all hash signatures & heuristic rules, add custom hashes
- **Live threat console** — real-time event stream over SSE

## Quick start

```bash
npm start          # or: node server.js
# open http://localhost:8080
```

Zero runtime dependencies (Node.js stdlib only, Node ≥ 18).

## Test it

1. Open the **Scan File** tab → click **⚡ EICAR Test File** — SentinelGuard
   detects the industry-standard test string via signature + structural analysis.
2. Generate the **Suspicious Demo** (a harmless PowerShell script with an encoded
   payload) to see heuristic + behavioral detection.
3. Turn on the **Guard** and drop a file into the `watch/` folder — it is scanned
   and quarantined in real time.
4. Run a **System Scan** of `/home/user` to see the engine analyze real files.
5. Open the **Processes** tab to see live process monitoring with real verdicts.

## Project layout

```
server.js              HTTP server, REST API, SSE event stream
lib/
  engine/             analysis engine: rules, behaviors, signatures
  pe.js, elf.js       PE / ELF binary parsers
  hashing.js, entropy.js, strings.js
  scanner.js          file scanning + hash cache
  guard.js            real-time file guard
  procmon.js          process monitor
  quarantine.js       quarantine manager
signatures.json       signature database (54 hashes + EICAR)
signatures/           raw community sources (used to seed the DB)
scripts/              signature seeder + PE test-fixture builder
public/               SPA frontend (vanilla HTML/CSS/JS)
watch/                guard-monitored folder
quarantine/           quarantined files
```

## Disclaimer

The signature database is seeded from public community teaching sources and is intended
for research/teaching/demo purposes. The EICAR string is a harmless industry-standard
test. Synthetic PE fixtures are generated locally and are not real malware.
