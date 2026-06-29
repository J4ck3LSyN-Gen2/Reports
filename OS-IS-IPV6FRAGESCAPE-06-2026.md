> [!WARNING]
> **Legal Disclaimer**
> The information contained in this report is for academic, research, and defensive security purposes only. The techniques, tools, and code described herein can cause significant damage if used maliciously. The author and publisher assume no liability for any misuse or damage caused by the information in this document. Unauthorized access to computer systems is illegal. Always obtain explicit, written permission from the system owner before conducting any security testing.
>
---
**Author:** _J4ck3LSyN_  
**Atlas Assistance** vrs2.9  
**Date:** _06-29-2026  
**Report:** OS-IS-IPV6FRAGESCAPE-06-2026.md  
**Source Repo:** https://github.com/sgkdev/ipv6_frag_escape  

# IPv6 Fragment Escape PoC Research Report  
## Offensive Security & Information Security Analysis – June 2026  

---  

### Table of Contents  
- [1. Executive Summary](#1-executive-summary)  
- [2. Exploit Catalog](#2-exploit-catalog)  
- [3. Technical Deep Dive](#3-technical-deep-dive)  
- [4. Detection & Mitigation Strategies](#4-detection--mitigation-strategies)  
- [5. References & Credits](#5-references--credits)  

---  

## 1. Executive Summary  
This report analyzes the **ipv6_frag_escape** proof‑of‑concept (PoC) exploit released in June 2026. The exploit targets a flaw in the Linux kernel’s IPv6 fragmentation handling (`__ip6_append_data`) that enables an in‑slab overflow into `skb_shared_info`, leading to a self‑use‑after‑free, arbitrary physical read/write via forged page‑table entries, and ultimately a container escape or local privilege escalation to root. Unlike the DirtyFrag family (CVE‑2022‑0847 variant) which abuses UDP spliced packets and missing `SKBFL_SHARED_FRAG` flags, this vulnerability lies in the IPv6 fragmentation pathway and does **not** have an assigned CVE as of the report date.  

Key findings:  
- A single PoC (`IPV6_FRAG_ESCAPE.c`) achieves reliable container escape and root privilege escalation on tested kernels (CentOS Stream 10 `6.12.0-242.el10`, RHEL 10 `6.12.0-228.el10`).  
- The exploit chain consists of seven stages: in‑slab overflow → page‑table UAF → KASLR bypass via BTF/vmlinux → arbitrary read/write → SELinux bypass via `avc_denied()` patch → `core_pattern` hijack → root shell via usermode‑helper.  
- Mitigation: apply the upstream fix (commit `38becddc`) that adds proper bounds checking in `__ip6_append_data`; additionally, restrict unprivileged user namespaces, monitor IPv6 fragmentation anomalies, and enforce strict eBPF/SELinux policies.  

---  

## 2. Exploit Catalog  

| Exploit Name | CVE Identifier | Subsystem | Primitive Type | Privilege Required | Target Example |  
|--------------|----------------|-----------|----------------|--------------------|----------------|  
| ipv6_frag_escape | *(none)* | net/ipv6 (fragmentation) | In‑slab overflow → self‑UAF → fake PTE → arbitrary RW | None (requires `CLONE_NEWUSER` for user‑ns) | Container escape → root via `core_pattern` hijack |  

*Note: No CVE has been assigned to this variant at time of writing.*  

---  

## 3. Technical Deep Dive  

### 3.1 Vulnerability Overview  
The bug resides in the IPv6 fragmentation output path (`net/ipv6/output_core.c::__ip6_append_data`). When constructing a fragmented IPv6 packet, the function incorrectly calculates the available space in the `skb`’s data buffer, allowing an attacker to write past the end of the buffer into the adjacent `skb_shared_info` structure. Specifically, the one‑byte field `nr_frags` (number of fragments) can be overwritten.  

### 3.2 Exploitation Flow  

1. **In‑slab overflow to a self‑UAF**  
   - By overwriting `nr_frags` with a non‑zero value (e.g., `1`), the kernel’s `skb_release_data()` will later call `put_page()` on a dangling `frags[0]` pointer.  
   - Through heap spraying (controlled cache reuse), the attacker plants a legitimate `struct page *` (pointing to a pipe buffer page) into the slab slot that will be interpreted as `frags[0]`.  
   - When the SKB is freed, `put_page()` drops a reference on a page the attacker still owns, creating a **use‑after‑free** of that page. The overflow does not touch `frags[0]`, making the race forgiving.  

2. **Page UAF to fake page‑table (Dirty‑Pagetable)**  
   - The freed page is reclaimed as a last‑level page table (PTE) by faulting a fresh anonymous mapping.  
   - The same physical page is now both a live leaf page table **and** the pipe buffer the attacker can read/write via the pipe.  
   - Writing eight bytes to the pipe installs a forged PTE; reading the pipe reads back the PTE contents. This yields a **finite arbitrary physical read/write** primitive (~460 PTE windows per table).  

3. **Defeat KASLR**  
   - Using the physical read primitive, the exploit scans the fixed low‑memory SMP trampoline page table (never randomized by KASLR). Its kernel‑half entry points to `level4_kernel_pgt`, revealing the kernel’s physical base.  
   - Following the pointer chain via `init_top_pgt` (recognizable by its self‑referencing entry 511) yields a virtual‑to‑physical translator, recovering the kernel virtual base and tying the attacker’s address space to physical memory.  

4. **Finite → infinite read/write**  
   - One PTE in the leaf table is forged to point to the table’s own physical address.  
   - The corresponding virtual address now aliases the page table itself, turning the primitive into **unrestricted, random‑access kernel read/write** (no pipe needed).  
   - Ring‑3 TLB coherence is ensured by triggering an oversized `mprotect()` to flush the entire MM.  

5. **Resolve offsets & steal credentials**  
   - Structural offsets (`task_struct`, `cred`, etc.) are read at runtime from `/sys/kernel/btf/vmlinux` (provided the kernel is built with `CONFIG_DEBUG_INFO_BTF` and the file is world‑readable, as on stock RHEL/CentOS).  
   - The attacker walks the vmemmap `struct page` walk to locate its own `task_struct` via `mm_struct.owner`, then zeros the credential IDs and fills all capability sets on `cred` and `real_cred`.  
   - If BTF resolution fails, the exploit falls back to parsing `/proc/kallsyms` via the arbitrary read primitive to resolve `init_user_ns` and grant `CAP_SYSLOG` in the initial namespace.  

6. **Disable SELinux without flipping enforcing**  
   - The prologue of `avc_denied()` is overwritten with a `xor eax, eax ; ret` stub (stepping over the `endbr64` instruction under Intel IBT).  
   - Every SELinux denial now returns success (granting the operation) while `getenforce()` still reports `Enforcing`.  
   - This step is required because the subsequent `core_pattern` hijack would otherwise be blocked by SELinux when triggering a core dump from a confined domain.  

7. **Escape through `core_pattern`**  
   - The global `core_pattern` variable is overwritten with a `|`‑prefixed handler pointing to the attacker’s binary via `/proc/<PID>/root` (the task’s container chroot).  
   - A child process is crashed (e.g., via `SIGSEGV`), triggering the kernel to invoke the core‑pattern handler as a usermode‑helper.  
   - The handler runs as **root in the initial namespaces**, inheriting the attacker’s binary but with full privileges.  
   - A Unix domain socket bound inside the container relays an interactive root shell back to the attacker’s container‑isolated process.  

### 3.3 Key Differences from DirtyFrag (CVE‑2022‑0847 variant)  

| Aspect | DirtyFrag (CVE‑2022‑0847) | ipv6_frag_escape (this report) |  
|--------|---------------------------|--------------------------------|  
| **Subsystem** | netfilter/XFRM (ESP‑in‑UDP) | IPv6 fragmentation (`__ip6_append_data`) |  
| **Primitive** | Missing `SKBFL_SHARED_FRAG` flag → in‑place decryption over page cache | In‑slab overflow → self‑UAF → forged PTE → arbitrary RW |  
| **Prerequisite** | Requires `CAP_NET_ADMIN` (via user+net ns) or direct splice path (patched) | Requires ability to create IPv6 fragments (unprivileged if user ns allows `CLONE_NEWNET`; often combined with `CLONE_NEWUSER` for CAP_NET_RAW) |  
| **CVE Status** | CVE‑2022‑0847 (variant) | **No CVE assigned** (upstream fix commit `38becddc`) |  
| **Mitigation** | Commit `f4c50a4034e6` (set `SKBFL_SHARED_FRAG` for spliced UDP) + later clone fix `48f6a5356a33` | Commit `38becddc` (bounds check in `__ip6_append_data`) |  
| **Privilege Escalation Path** | Overwrite `/usr/bin/su` via page‑cache write | Overwrite `core_pattern` → usermode‑helper → root shell (container escape) |  
| **Stealth** | Relies on ESP traffic to localhost:4500 (detectable via netfilter/XFRM logs) | Uses IPv6 fragmentation packets; can be obscured via fragmentation offsets and low TTL |  

---  

## 4. Detection & Mitigation Strategies  

### 4.1 Detection Opportunities  

| Indicator | Description | Suggested Detection (e.g., Sigma, Auditd) |  
|-----------|-------------|-------------------------------------------|  
| **Unprivileged user namespace creation** | `unshare(CLONE_NEWUSER)` (often combined with `CLONE_NEWNET`) | `syscall.name:unshare` with args containing `CLONE_NEWUSER|CLONE_NEWNET` |  
| **Abnormal IPv6 fragmentation** | Large number of fragmented IPv6 packets with abnormal offset/offset+length exceeding MTU | Monitor `ip6tables`/`nft` logs for `frag` hits; NetFlow/IPFIX alerts on high fragment rate |  
| **Suspicious pipe activity** | Repeated writes of 8‑byte values to a pipe followed by reads of same data (potential PTE probing) | Audit `pipe_write`/`pipe_read` with unusual patterns; eBPF tracepoint on `pipe_write` checking for repeated 8‑byte patterns |  
| **Arbitrary read/write via /proc/kallsyms or /sys/kernel/btf/vmlinux** | Repeated reads of kernel symbols or BTF from unprivileged processes | Audit file opens on `/proc/kallsyms`, `/sys/kernel/btf/vmlinux` from non‑root users |  
| **core_pattern modification** | Sudden change of `/proc/sys/kernel/core_pattern` to a `|`‑prefixed path | Audit `sys_setuid`/`sys_corewrapper`? Actually monitor `proc` writes: `inotify`/`audit` on `/proc/sys/kernel/core_pattern` |  
| **SELinux denials suppressed** | Sudden drop in `avc: denied` messages while `getenforce` still shows Enforcing | Spike‑drop detection in `auditd` AVC logs; correlate with `getenforce` via `auditd` rule on `security` class |  

### 4.2 Mitigation Strategies  

1. **Kernel Patch**  
   - Apply the fix from commit `38becddc` (“ipv6: fix out‑of‑bounds write in __ip6_append_data”) which adds proper bounds checking before copying data into the skb.  
   - Ensure kernel version ≥ 6.12.0‑242.el10 (CentOS Stream 10) or ≥ 6.12.0‑228.el10 (RHEL 10) or later.  

2. **Namespace Restrictions**  
   - Set `kernel.unprivileged_userns_clone=0` to disable unprivileged user namespaces (may break container runtimes; evaluate impact).  
   - Use SELinux/AppArmor to restrict `unshare(CLONE_NEWUSER|CLONE_NEWNET)` to specific trusted domains.  

3. **Network Hardening**  
   - Drop or rate‑limit fragmented IPv6 packets at the host or network edge unless legitimately needed.  
   - Enable `net.ipv6.conf.all.disable_ipv6=1` if IPv6 is not required (drastic).  
   - Use `nftables`/`iptables` rules to limit IPv6 fragment headers:  
     ```bash
     nft add rule ip6 filter input ip6 protocol frag drop
     ```  

4. **Runtime Protections**  
   - Enable `CONFIG_DEBUG_PAGEALLOC`, `CONFIG_PAGE_POISONING`, `CONFIG_SLAB_FREELIST_RANDOM`, `CONFIG_SLAB_FREELIST_HARDENED`, `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`, `CONFIG_INIT_ON_FREE_DEFAULT_ON` to detect use‑after‑free and slab abuses.  
   - Deploy eBPF-based monitors for:  
     - `skb_release_data` calls with abnormal `nr_frags` values.  
     - `put_page` on pages that are currently mapped as page tables (detected via `/proc/kpageflags`).  
   - Enforce strict `seccomp` profiles that forbid `unshare` for untrusted workloads.  

5. **File‑System Integrity**  
   - Protect `/proc/sys/kernel/core_pattern` via `sysctl` hardening (`kernel.core_pattern` set to a core dump collector in a restricted namespace) or make it immutable via `sysctl -w kernel.core_pattern=|/bin/false` (if core dumps not needed).  
   - Use File Integrity Monitoring (FIM) on `/proc/sys/kernel/core_pattern` and `/etc/sysctl.d/` to detect unauthorized changes.  

6. **SELinux Hardening**  
   - Ensure `avc_denied()` audit logging is robust; consider enabling `auditd` rule to watch for changes to the `avc_denied` symbol via kprobes or integrity‑protected kernel modules.  
   - Keep the kernel boot parameter `ibt=on` (Intel CET) to block the `xor eax,eax;ret` bypass if hardware supports it.  

---  

## 5. References & Credits  

### 5.1 Primary Sources  
- **ipv6_frag_escape PoC** – `.../ipv6_frag_escape/`  
  - `IPV6_FRAG_ESCAPE.c` – main exploit  
  - `README.md` – detailed exploitation chain and prerequisites  
  - Supporting files: `kallsysms.c`, `pagemap.c`, `pagemap.h`  

### 5.2 Kernel Fixes  
- Commit `38becddc`: “ipv6: fix out‑of‑bounds write in __ip6_append_data”  
  <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=38becddc>  

### 5.3 Related Work (for context)  
- DirtyFrag (CVE‑2022‑0847 variant) – see `OS-IS-DIRTYSPLOITS-06-2026.md`  
- DirtyClone (CVE‑2026‑43503) – see same report  
- Fragnesia, nft‑catchall‑uaf, pedit‑cow, PinTheft/pintheft, etc. – referenced in DirtySploits report  

### 5.4 Tooling & References  
- **Linux Kernel Documentation** – https://www.kernel.org/doc/html/latest/  
- **BPF and Tracepoint References** – https://www.kernel.org/doc/html/latest/bpf/index.html  
- **Auditd Reference** – https://people.redhat.com/sgrubb/audit/  
- **Sigma Rule Generator** – https://github.com/Neo23x0/sigma  
- **YARA Documentation** – https://virustotal.github.io/yara/  

---  

*Report generated by A.T.L.A.S (Advanced Transmit Logic Analysis System)*
