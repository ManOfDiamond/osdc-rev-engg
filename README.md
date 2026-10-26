### Challenge 2: Operation Watchdog

**Title:** Operation Watchdog (Telemetry & Anti-Tamper Evasion)

**Track:** Binary Reverse Engineering / Defensive Bypass

**Difficulty:** Medium

**Estimated Time:** 35–45 minutes

---

#### 1. Scenario

SentinelCore Defense Systems claims that its `watchdog_agent` v3.2 endpoint
agent cannot be inspected or modified. Assess the supplied ELF builds and
demonstrate that the privileged telemetry state can still be reached while
the process is being debugged or instrumented.

The challenge has two architecture-specific binary targets:

| Architecture | Participant target |
|---|---|
| amd64 | `watchdog_agent_amd64` |
| arm64 | `watchdog_agent_arm64` |

Participants receive only the selected stripped ELF binary, not the source
files or build artifacts. The bypass must therefore be based on analysis of
the binary itself. The architecture-specific source files in this repository
are author-side reference implementations and are not part of the challenge
distribution.

#### 2. What the agent does

At startup, the agent:

1. Calls `ptrace(PTRACE_TRACEME)` through an inline raw system-call wrapper.
2. Reads `/proc/self/status` through raw `open`/`read`/`close` system calls and
   extracts `TracerPid`.
3. Computes two FNV-1a checksums over fixed-size code regions.
4. Mixes those checksums with `pt_status` and `tracer_pid` to derive a 32-bit
   key. A traced process therefore receives a different key without relying on
   a simple visible “debugger detected” branch.
5. Decrypts the embedded payload with a SplitMix32-derived keystream.
6. Accepts the result only when its CRC32 equals `0xae92defe`.

The plaintext is not stored directly in the payload. A successful run must
produce:

```text
[+] INTEGRITY CHECK PASSED: Host telemetry environment verified.
[+] ROOT INTEGRITY VERIFIED: Privileged sensor daemon initialized.
[*] Monitoring endpoint operations... (Press Ctrl+C to terminate)
```

#### 3. Architecture-specific checksum regions

Both targets use the same integrity-hash layout:

* `check_raw_ptrace` (0x30 bytes)
* `probe_environment_signature` (0x30 bytes)

The targets share the same anti-tamper flow. The raw-syscall wrapper uses
architecture-specific syscall instructions and numbers, and each target has
its own encrypted payload bytes. These details must be recovered from the
selected binary. Changing a hashed instruction changes the derived key and
causes the CRC integrity gate to terminate the process.

#### 4. Deliverables

Submit a short vulnerability report containing:

1. **Root-cause analysis:** Identify the raw anti-debugging checks, checksum
   regions, key derivation, encrypted payload, and CRC gate. Explain why the
   controls can be bypassed by an analyst who controls execution.
2. **Verified proof of concept:** Provide either:
   * a static patch with the exact file offsets or virtual addresses, original
     opcodes, replacement opcodes, and patched binary; or
   * an automated GDB script or equivalent debugger/instrumentation proof of
     concept, including the runtime values or control-flow changes it relies
     on. `LD_PRELOAD` interposition is not sufficient for the anti-debugging
     checks because the targets invoke the relevant system calls inline rather
     than through replaceable libc call sites.
3. **Remediation advice:** Give at least two concrete measures that increase
   resistance to dynamic bypasses.

The proof of concept must succeed under GDB or the selected instrumentation,
not only during an uninstrumented execution.

#### 5. Helper tools

The challenge distribution contains only the selected binary. The following
files are author-side development and verification tools, not participant
deliverables:

* `q2/extract_key.py` extracts `.text`, computes FNV-1a hashes, derives the
  clean key, and can decrypt and CRC-check a supplied payload.
* `q2/generate_payload.py` regenerates an encrypted payload for a supplied
  key and verifies its round trip.
* `q2/verify.sh <path_to_patched_binary>` runs a candidate binary under
  batch-mode GDB for three seconds and checks for `ROOT INTEGRITY VERIFIED`.

For stripped binaries, `extract_key.py` accepts the manually recovered
addresses with `--ptrace` and `--probe`; the corresponding default hash lengths
are 0x30 bytes each. For unstripped binaries, it attempts to resolve the
function addresses through `nm`.

---