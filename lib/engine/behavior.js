'use strict';

/**
 * Behavioral profiling engine.
 * Combines rule hits and structural features into a behavior profile:
 * what the file would do at runtime, inferred from static evidence
 * (imports, strings, sections). Each behavior has severity, confidence,
 * and the concrete evidence behind it.
 */

const BEHAVIOR_DEFS = {
  process_injection: {
    name: 'Process Injection',
    severity: 'critical',
    description: 'Attempts to inject code into other processes (classic malware technique for privilege escalation and persistence).'
  },
  process_hollowing: {
    name: 'Process Hollowing',
    severity: 'critical',
    description: 'Creates a suspended process and replaces its memory with attacker-controlled code.'
  },
  keylogging: {
    name: 'Keystroke Capture',
    severity: 'critical',
    description: 'Captures keyboard input — credential theft.'
  },
  credential_access: {
    name: 'Credential Access',
    severity: 'critical',
    description: 'Reads or decrypts stored credentials (LSASS, DPAPI, browser profiles).'
  },
  persistence: {
    name: 'Persistence',
    severity: 'high',
    description: 'Installs mechanisms to survive reboots (registry Run keys, scheduled tasks, services, startup folder).'
  },
  ransomware: {
    name: 'Ransomware Behavior',
    severity: 'critical',
    description: 'Extortion behavior: file encryption capability, ransom notes, payment channel.'
  },
  file_encryption: {
    name: 'File Encryption Capability',
    severity: 'high',
    description: 'Uses crypto APIs to encrypt files — potential ransomware building block.'
  },
  cryptomining: {
    name: 'Cryptocurrency Mining',
    severity: 'high',
    description: 'Connects to mining pools or runs miner binaries.'
  },
  c2: {
    name: 'C2 Communication',
    severity: 'high',
    description: 'Command-and-control capability: bot language, suspicious infrastructure, reverse shells.'
  },
  downloader: {
    name: 'Downloader / Dropper',
    severity: 'high',
    description: 'Downloads additional payloads from remote sources and executes them.'
  },
  powershell_abuse: {
    name: 'PowerShell Abuse',
    severity: 'high',
    description: 'Uses encoded or download-cradle PowerShell for fileless execution.'
  },
  command_execution: {
    name: 'Command Execution',
    severity: 'medium',
    description: 'Spawns shells or external commands (cmd, powershell, curl, certutil).'
  },
  anti_analysis: {
    name: 'Anti-Analysis',
    severity: 'medium',
    description: 'Evades debuggers, VMs, and sandboxes.'
  },
  screen_capture: {
    name: 'Screen Capture',
    severity: 'medium',
    description: 'Captures screen content (surveillance).'
  },
  clipboard_monitoring: {
    name: 'Clipboard Monitoring',
    severity: 'low',
    description: 'Accesses the clipboard (crypto-wallet theft pattern).'
  },
  packed: {
    name: 'Packed / Obfuscated',
    severity: 'medium',
    description: 'Binary is packed or obfuscated to hide its true content.'
  },
  dynamic_resolution: {
    name: 'Dynamic API Resolution',
    severity: 'medium',
    description: 'Resolves APIs at runtime to evade static detection.'
  },
  shellcode: {
    name: 'Shellcode Execution',
    severity: 'critical',
    description: 'Position-independent payload designed to be injected/executed in memory.'
  },
  macro_execution: {
    name: 'Macro Execution',
    severity: 'medium',
    description: 'Office document with macros capable of running code on open.'
  },
  script_execution: {
    name: 'Script Execution',
    severity: 'low',
    description: 'Interpreted script capable of host execution (child processes, network, files).'
  },
  network_communication: {
    name: 'Network Communication',
    severity: 'low',
    description: 'Opens network connections.'
  },
  system_modification: {
    name: 'System Modification',
    severity: 'medium',
    description: 'Modifies system state: processes, services, scheduled tasks, BITS jobs.'
  },
  file_change_monitoring: {
    name: 'File Change Monitoring',
    severity: 'medium',
    description: 'Watches the filesystem for changes (ransomware targeting behavior).'
  },
  payload_embedding: {
    name: 'Embedded Payload Data',
    severity: 'medium',
    description: 'Contains large data appended after the executable sections — embedded payload, configuration or archive.'
  },
  behavior_normal: {
    name: 'No Suspicious Behavior',
    severity: 'info',
    description: 'No dangerous behavior patterns detected by the static analysis engine.'
  }
};

const RULE_TO_BEHAVIOR = {
  'SG-PE-INJ-001': 'process_injection',
  'SG-PE-INJ-002': 'process_injection',
  'SG-PE-INJ-003': 'process_injection',
  'SG-PE-HOLE-001': 'process_hollowing',
  'SG-PE-KEYLOG-001': 'keylogging',
  'SG-PE-KEYLOG-002': 'keylogging',
  'SG-PE-PERS-001': 'persistence',
  'SG-PE-PERS-002': 'persistence',
  'SG-PE-PERS-003': 'persistence',
  'SG-PE-PERS-004': 'persistence',
  'SG-PE-RANS-001': 'ransomware',
  'SG-PE-RANS-002': 'ransomware',
  'SG-PE-RANS-003': 'ransomware',
  'SG-PE-CRYPT-001': 'file_encryption',
  'SG-PE-MINER-001': 'cryptomining',
  'SG-PE-CRED-001': 'credential_access',
  'SG-PE-CRED-002': 'credential_access',
  'SG-PE-CRED-003': 'credential_access',
  'SG-PE-PS-001': 'powershell_abuse',
  'SG-PE-PS-002': 'powershell_abuse',
  'SG-PE-DL-001': 'downloader',
  'SG-PE-DL-002': 'downloader',
  'SG-PE-CMD-001': 'command_execution',
  'SG-PE-CMD-002': 'command_execution',
  'SG-PE-CMD-003': 'command_execution',
  'SG-PE-CMD-004': 'command_execution',
  'SG-PE-C2-001': 'c2',
  'SG-PE-C2-002': 'c2',
  'SG-PE-C2-003': 'c2',
  'SG-PE-SC-001': 'screen_capture',
  'SG-PE-SC-002': 'clipboard_monitoring',
  'SG-PE-TLS-001': 'anti_analysis',
  'SG-PE-ANTVM-001': 'anti_analysis',
  'SG-PE-ANTDBG-001': 'anti_analysis',
  'SG-PE-ANTDBG-002': 'anti_analysis',
  'SG-PE-ANTSB-001': 'anti_analysis',
  'SG-PE-DYN-001': 'dynamic_resolution',
  'SG-PE-PK-001': 'packed',
  'SG-PE-PK-002': 'packed',
  'SG-PE-PK-003': 'packed',
  'SG-PE-PK-004': 'packed',
  'SG-PE-PK-005': 'packed',
  'SG-PE-SHELL-001': 'shellcode',
  'SG-PE-OVL-001': 'payload_embedding',
  'SG-PE-EXEC-001': 'system_modification',
  'SG-PE-NET-001': 'network_communication',
  'SG-ELF-002': 'system_modification',
  'SG-ELF-003': 'c2',
  'SG-SC-PS-001': 'powershell_abuse',
  'SG-SC-PS-002': 'powershell_abuse',
  'SG-SC-JS-001': 'script_execution',
  'SG-SC-JS-002': 'script_execution',
  'SG-SC-VBS-001': 'downloader',
  'SG-SC-BAT-001': 'downloader',
  'SG-SC-SH-001': 'c2',
  'SG-SC-PY-001': 'c2',
  'SG-SC-MACRO-001': 'macro_execution',
  'SG-SC-GEN-001': 'script_execution',
  'SG-ANY-ONION-001': 'c2',
  'SG-ANY-ENC-001': 'c2'
};

function buildBehaviors(ruleHits, ctx) {
  const behaviors = [];
  const seen = new Set();

  for (const hit of ruleHits) {
    if (hit.weight === 0) continue; // info-only rules don't produce behaviors
    const b = RULE_TO_BEHAVIOR[hit.id];
    if (!b || seen.has(b) || !BEHAVIOR_DEFS[b]) continue;
    seen.add(b);
    const def = BEHAVIOR_DEFS[b];
    const evidence = hit.evidence || [];
    // Confidence scales with severity & evidence count
    let confidence = 0.6;
    if (hit.severity === 'critical') confidence = 0.85;
    else if (hit.severity === 'high') confidence = 0.75;
    else if (hit.severity === 'medium') confidence = 0.65;
    confidence = Math.min(0.95, confidence + (evidence.length ? 0.05 : 0));
    behaviors.push({
      id: b,
      name: def.name,
      severity: def.severity,
      confidence: Math.round(confidence * 100) / 100,
      description: def.description,
      evidence: evidence.slice(0, 8)
    });
  }

  if (behaviors.length === 0) {
    behaviors.push({
      id: 'behavior_normal',
      name: 'No Suspicious Behavior',
      severity: 'info',
      confidence: 0.9,
      description: 'No dangerous behavior patterns detected by the static analysis engine.',
      evidence: ['Rule database scanned', `File type: ${ctx.fileType || 'unknown'}`]
    });
  }

  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  behaviors.sort((a, b) => order[a.severity] - order[b.severity]);
  return behaviors;
}

module.exports = { buildBehaviors, BEHAVIOR_DEFS };
