# Cybersecurity Research & Threat Intelligence Reports

This repository contains a collection of technical reports, threat intelligence briefs, and offensive security research focused on the 2025-2026 cybersecurity landscape.

## Project Structure

Reports are categorized using the following prefix system:
- **OS**: Offensive Security (Exploit research, lab PoCs, and red teaming tactics)
- **IS**: Information Security (Threat intelligence, incident post-mortems, and defensive strategy)
- **LS**: Landscape (Broad industry trends, projections, and situational awareness)

---

## Report Index

### 2026 Reports

| File | Type | Description |
| :--- | :--- | :--- |
| OS-IS-CVE-2026-6307-07-2026.md | OS/IS | **V8 Security (Longinus) Report** Analysis of CVE-2026-6307, nicknamed "Longinus", a critical vulnerability in V8's TurboFan compiler affecting JavaScript-to-WebAssembly call inlining and FrameState merging. |
| OS-IS-IPV6FRAGESCAPE-06-2026.md | OS/IS | **ipv6 LPE** Analysis the ipv6_frag_escape proof‑of‑concept (PoC) exploit released in June 2026 |
| OS-IS-CHAOS-OP-06-2026.md | OS/IS | **Engagement Report** Details the offensive security operations conducted against the Supabase Edge Functions associated with the chaosfoundry.digital infrastructure | 
| OS-IS-DIRTYSPLOITS-06-2026.md | OS/IS | **A Mix of Linux Exploits** Analysis of recent DirtyClone, DirtyFrag, Fragnesia, pedit-cow, PinTheft, CopyFail, dirtycbc, ssh-keysign-pwn, nft-catchall-uaf and pintheft(non uring_io) |
| OS-IS-EXPLOITARIUM-RESEARCH-06-2026.md(.yar) | OS/IS | **Exploitarium Research:** Analysis of `Exploitarium` 0-day exploits. Source: `https://github.com/bikini/exploitarium` |
| IS-LS-Q1-Q2-05-2026.md | LS/IS | **2026 Mid-Year Landscape:** Analysis of Agentic AI, npm supply chain attacks (Axios/TanStack), and the Canvas LMS breach. |
| IS-REPORT-05-2026.md | IS | **Supply Chain & Workflow Poisoning:** Deep dive into TeamPCP, GitHub internal breaches, and Linux "Dirty Frag" vulnerabilities. |
| IS-IRAN-APT-03-2026.md | IS | **Iranian Cyber Update:** Coverage of the Stryker Corporation attack and the KadNap P2P botnet. |
| OS-REFAMPv2-02-2026.md | OS | **DDoS & Botnets:** Implementation of Reflection/Amplification attacks and Mirai-family C2 evasion. |
| IS-LS-PROJECTION-Q1-01-2026.md | LS | **2026 Projections:** Early 2026 forecasts regarding Cloud infrastructure and polymorphic malware. |

### 2025 Reports

| File | Type | Description |
| :--- | :--- | :--- |
| OS-IS-BYOVD-11-2025.md | OS/IS | **Kernel Research:** Bring Your Own Vulnerable Driver (BYOVD) tactics and Linux eBPF rootkit development. |
| OS-LS-ADVANCED-RCE-WEBVULN-11-2025.md | OS/LS | **Web Vulnerabilities:** Advanced RCE chains, V8 Type Confusion, and modern GraphQL/SAP exploitation. |
| IS-IRAN-0119-2025.md | IS | **Iranian Capabilities:** Comprehensive overview of IRGC/MOIS TTPs and their malware arsenal (MuddyWater, OilRig, etc.). |

---

## Formatting & Syntax Notices

To maintain a high level of technical clarity, these reports utilize specific formatting standards. Ensure your markdown viewer supports the following extensions for the best experience:

### 1. Mathematical Notation
Several reports (specifically the DDoS and Kernel research) use LaTeX/KaTeX for expressing amplification factors, execution flows, and cryptographic projections.
- **Inline:** `$ \text{Factor} = \frac{\text{Response}}{\text{Request}} $`
- **Block:**
  $$ \text{Command: } \texttt{esxcli vm process kill} \quad \longrightarrow \quad \text{Encryption} $$

### 2. Specialized Callouts (Alerts)
We use GitHub-style callouts to highlight critical warnings, especially regarding legal ethical boundaries and lab safety.

```markdown
> [!WARNING]
> This document is authorized exclusively for internal red-team exercises within air-gapped laboratory networks.

> [!NOTE]
> Information generated via A.T.L.A.S assisted research.
```

### 3. Technical Diagrams
Architecture and attack flow diagrams are provided in ASCII format to ensure compatibility across all terminal-based and web-based markdown editors.

```text
[Attacker] ---> [OIDC Token Abuse] ---> [Cloud Environment]
```

### 4. Code Blocks & Diffs
Code samples are provided with language-specific syntax highlighting. Offensive samples often include "Production-Quality" annotations to explain evasion mechanics line-by-line.

---

## Consolidated CVE Index

The following table summarizes all vulnerabilities discussed across the research reports, sorted by year.

| CVE ID | Affected System / Product | Vulnerability Type / Description | Source Report |
| :--- | :--- | :--- | :--- |
| **2026** | | | |
| CVE-2026-46331 | act_pedit | Race condition in `net/sched` `act_pedit` partial copy-on-write page-cache write. | OS-IS-DIRTYSPLOITS-06-2026.md |
| CVE-2026-23111 | nf_tables | Use-after-free in the `nf_tables` subsystem due to missing reactivation on the netlink abort path. | OS-IS-DIRTYSPLOITS-06-2026.md |
| CVE-2026-43503 | Linux Kernal | Linux kernel local privilege escalation via insufficient flag propagation in __pskb_copy_fclone() when cloning socket buffers carrying spliced, file-backed page-cache fragments. | OS-IS-DIRTYSPLOITS-06-2026.md |
| CVE-2026-55200 | libssh2 <= 1.11.1 | Buffer Overflow via unchecked packet_length field in SSH2 packet parsing leading to RCE | OS-IS-EXPLOITARIUM-RESEARCH-06-2026.md |
| CVE-2026-45115 | MyBB <= 1.8.40 | Priv-Esc via insufficient permissions checks in the Admin Control Panel's user-management module | OS-IS-EXPLOITARIUM-RESEARCH-06-2026.md |
| CVE-2026-46300 | Linux Kernel | Fragnesia: XFRM ESP-in-TCP reassembly bypass | IS-REPORT-05-2026 |
| CVE-2026-43500 | Linux Kernel | Dirty Frag: rxrpc fragment heap corruption | IS-REPORT-05-2026 |
| CVE-2026-43284 | Linux Kernel | Dirty Frag: IPsec ESP (esp4/esp6) heap corruption | IS-REPORT-05-2026 |
| CVE-2026-32922 | OpenClaw | Path Traversal leading to Admin RCE | IS-LS-Q1-Q2-05-2026 |
| CVE-2026-31976 | GitHub Actions | Tag Poisoning / Backdoored action.yml pattern | IS-REPORT-05-2026 |
| CVE-2026-28472 | OpenClaw | WebSocket Gateway Authorization Bypass | IS-LS-Q1-Q2-05-2026 |
| CVE-2026-27941 | Openlit | Workflow Poisoning via pull_request_target | IS-REPORT-05-2026 |
| CVE-2026-27001 | OpenClaw | AI Agentic Security Vulnerability | IS-LS-Q1-Q2-05-2026 |
| CVE-2026-26327 | OpenClaw | DNS Service Discovery & TLS Pin Bypass | IS-LS-Q1-Q2-05-2026 |
| CVE-2026-25593 | OpenClaw | AI Framework Vulnerability | IS-LS-Q1-Q2-05-2026 |
| CVE-2026-24763 | OpenClaw | Sandbox Escape via PATH Command Injection | IS-LS-Q1-Q2-05-2026 |
| **2025** | | | |
| CVE-2025-66478 | Legacy Encryption | Cryptographic vulnerability / "Harvest Now, Decrypt Later" risk | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-64446 | FortiWeb | Path Traversal to Admin RCE | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-59287 | Microsoft WSUS | Unauthenticated RCE via .NET Deserialization | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-57751 | Citrix NetScaler ADC | ICCP RCE via arbitrary file write | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-55182 | React Web Framework | React2Shell: Remote Code Execution | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-53770 | SharePoint | ViewState Deserialization Webshell | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-49844 | Redis | Lua UAF Remote Code Execution | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-49706 | Access Controls | Identity compromise / Authentication bypass | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-49704 | Edge Devices | WMI/PowerShell abuse vulnerability | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-48633 | Android Framework | Mobile-based reconnaissance vulnerability | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-42925 | SAP SRM | Stored XSS leading to session hijacking | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-31324 | SAP NetWeaver | InvokerServlet Deserialization RCE | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-16379 | SNMP Protocol | Information disclosure in network management | IS-LS-PROJECTION-Q1-01-2026 |
| CVE-2025-13223 | Chromium V8 | Type Confusion leading to RCE | OS-LS-ADVANCED-RCE-WEBVULN-11-2025 |
| CVE-2025-1316 | Botnet Target | Lifecycle infection vector | OS-REFAMPv2-02-2026 |
| **2024** | | | |
| CVE-2024-50302 | Linux Kernel | hiddev vulnerability utilized in rootkits | OS-IS-BYOVD-11-2025 |
| CVE-2024-30085 | Windows KTM | Kernel Transaction Manager Object Race → UAF | OS-IS-BYOVD-11-2025 |
| CVE-2024-30078 | Windows / dxgkrnl | Wi-Fi RCE via GPU context corruption | OS-IS-BYOVD-11-2025 |
| CVE-2024-24919 | Check Point Gateways | Authentication bypass / Information disclosure | IS-IRAN-0119-2025 |
| CVE-2024-21887 | Pulse Secure / Ivanti | Command Injection | IS-IRAN-0119-2025 |
| CVE-2024-21405 | Intel iGPU | Out-of-bounds read leading to info leak | OS-IS-BYOVD-11-2025 |
| CVE-2024-6765 | Windows CLFS | Log manipulation / Arbitrary write | OS-IS-BYOVD-11-2025 |
| CVE-2024-6047 | Botnet Target | Lifecycle infection vector | OS-REFAMPv2-02-2026 |
| CVE-2024-4671 | AMD GPU | Shader compiler heap overflow | OS-IS-BYOVD-11-2025 |
| CVE-2024-3400 | Palo Alto PanOS | OS Command Injection | IS-IRAN-0119-2025 |
| CVE-2024-0085 | NVIDIA GPU | nvhda64v.sys heap overflow → kernel EoP | OS-IS-BYOVD-11-2025 |
| **2023** | | | |
| CVE-2023-39780 | ASUS Routers | Edge device vulnerability (KadNap botnet) | IS-IRAN-APT-03-2026 |
| CVE-2023-3519 | Citrix Netscaler | Unauthenticated RCE | IS-IRAN-0119-2025 |
| CVE-2023-31083 | Linux Kernel | snd-rawmidi Use-after-free | OS-IS-BYOVD-11-2025 |
| CVE-2023-28252 | Windows CLFS | Privilege Escalation (BYOVD chain) | OS-IS-BYOVD-11-2025 |
| **Pre-2023** | | | |
| CVE-2022-0847 | Linux Kernal | **DirtyFrag(Variant)** Linux kernel page-cache write vulnerability in the IPsec ESP input processing path. | OS-IS-DIRTYSPLOITS-06-2026.md |
| CVE-2022-1388 | F5 BIG-IP | iControl REST Authentication Bypass | IS-IRAN-0119-2025 |
| CVE-2021-44228 | Log4j2 | Log4Shell RCE | IS-IRAN-0119-2025 |
| CVE-2021-21551 | Dell dbutil_2_3.sys | Memory corruption in IOCTL (BYOVD) | OS-IS-BYOVD-11-2025 |
| CVE-2021-1732 | Windows Win32k | Privilege Escalation (BYOVD accessory) | OS-IS-BYOVD-11-2025 |
| CVE-2021-0512 | Linux Kernel | hiddev OOB write | OS-IS-BYOVD-11-2025 |
| CVE-2020-36158 | Linux Kernel | mwifiex heap overflow | OS-IS-BYOVD-11-2025 |
| CVE-2020-5902 | F5 BIG-IP | TMUI Remote Code Execution | IS-IRAN-0119-2025 |
| CVE-2020-1472 | MS AD / ZeroLogon | Active Directory Privilege Escalation | IS-IRAN-0119-2025 |
| CVE-2019-19781 | Citrix Netscaler | Path Traversal / RCE | IS-IRAN-0119-2025 |
| CVE-2019-16098 | MSI RTCore64.sys | Arbitrary MSR read/write (BYOVD) | OS-IS-BYOVD-11-2025 |
| CVE-2019-11510 | Pulse Secure VPN | Arbitrary File Read | IS-IRAN-0119-2025 |
| CVE-2018-20250 | WinRAR | Directory Traversal (ACE format) | IS-IRAN-0119-2025 |
| CVE-2018-13379 | Fortinet FortiOS | Path Traversal (Credential Leak) | IS-IRAN-0119-2025 |
| CVE-2017-11882 | MS Office | Equation Editor buffer overflow (RCE) | IS-IRAN-0119-2025 |
| CVE-2015-2291 | Intel Ethernet | Arbitrary kernel R/W (BYOVD) | OS-IS-BYOVD-11-2025 |

---

## Lab Safety & Legal Disclaimer

**All offensive security content within these reports is for academic and defensive research only.** 

The techniques described—including kernel-level exploitation, workflow poisoning, and DDoS amplification—can cause significant damage if used outside of controlled environments. Unauthorized access to computer systems is a violation of international law. 

**Author:** J4ck3LSyN
**Github:** https://github.com/J4ck3LSyN-Gen2/  
**X**: https://twitter.com/J4ck3LSyN  
**Assistance:** A.T.L.A.S (Advanced.Transmit.Logic.Analysis.Systems)  
