# Operation Watchdog (Telemetry & Anti-Tamper Evasion)

**Track:** Binary Reverse Engineering / Defensive Bypass

**Difficulty:** Hard

**Event duration:** 24 hours

---

## 1. Scenario

SentinelCore Defense Systems has shipped an internal build of its next-generation
endpoint monitoring agent, `watchdog_agent` (v3.2). The vendor claims the daemon
is tamper-proof and immune to external instrumentation: active debuggers and
unauthorized dynamic tracers are supposedly trapped and neutralized before any
privileged routine can execute.

Your team has been engaged to run a white-box assessment of the compiled
binary. Determine what integrity and anti-instrumentation controls are
protecting the application, and demonstrate that the agent's privileged
telemetry state can be reached while the process is actively being debugged.

## 2. What you're given

You receive **one** stripped ELF binary, no source, no build scripts, no
symbols. Pick the file matching your analysis environment:

| Architecture | Binary               |
|---|----------------------|
| x86_64 (amd64) | `watchdog_agent_amd64` |
| ARM64 (aarch64) | `watchdog_agent_arm64` |

Both targets implement the same agent behavior; only the instruction set and
calling convention differ. Everything you need to solve the challenge is
recoverable from the binary itself through static and dynamic analysis.

## 3. Objective

Get the agent to print its privileged-state telemetry **while the process is
running directly inside an active debugger** (GDB or equivalent dynamic
instrumentation). A clean, un-instrumented run is not sufficient; the whole
point is reaching this state under observation.

A successful run prints, in order:

```text
[+] INTEGRITY CHECK PASSED: Host telemetry environment verified.
[+] ROOT INTEGRITY VERIFIED: Privileged sensor daemon initialized.
[*] Monitoring endpoint operations... (Press Ctrl+C to terminate)
```

Anything short of this exact telemetry (including an `INTEGRITY FAULT` or a
crash) is not a successful bypass.

## 4. Rules of engagement

- You may use any static analysis (disassembly, decompilation) and any
  dynamic analysis (debuggers, emulation, instrumentation frameworks) you
  like.
- A patch that only makes a *clean* run succeed does not satisfy the
  objective; your bypass must hold up specifically while the process is
  traced/instrumented.
- Do not attempt to attack the host machine, other participants, or
  infrastructure outside the provided binary. Scope is limited to the
  supplied artifact.

## 5. Deliverables

Submit a short written report containing:

1. **Root-cause analysis.** Identify the integrity and anti-instrumentation
   mechanisms the binary implements, and explain, in your own words, backed
   by what you found in the disassembly, why they do not stop a determined
   analyst who controls execution.
2. **Verified proof of concept.** Provide **one** of the following:
   - **Static patch:** the exact file offsets or virtual addresses, original
     bytes/opcodes, and replacement bytes/opcodes you changed, together with
     the patched binary. The patched binary must reach the target telemetry
     *while running under GDB with no further manual intervention*.
   - **Dynamic/live bypass:** an automated GDB script (or equivalent
     instrumentation script) that reproduces your bypass against the
     **unmodified** binary we supplied, including the breakpoint
     address(es), the register(s) or memory you change, and the value(s) you
     set. We will replay it as given.
3. **Remediation advice.** At least two concrete, specific changes the
   engineering team could make to meaningfully raise the bar against the
   class of bypass you used, not generic advice like "add more checks."

## 6. Submission format

Submit a single archive or document containing your written report (deliverables
1–3 above) and any supporting artifacts (patched binary, GDB script, etc.)
referenced in it. Make sure your PoC is runnable as submitted; we will
execute it against the original binary (or your patched binary, for a static
patch) exactly as provided.

## 7. Scoring

Submissions are graded on all three deliverables, not PoC success alone. A
working bypass with a thin or incorrect root-cause explanation will score
lower than a complete, accurate write-up. Partial credit is available for a
correct root-cause analysis even without a fully working PoC.

Good luck.
