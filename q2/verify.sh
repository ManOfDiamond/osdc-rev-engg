#!/usr/bin/env bash
#
# verify.sh - Operation Watchdog verifier
#
# Three modes, auto-selected by which arguments you pass:
#
#   1) verify.sh <patched_binary>
#        Runs a STATICALLY PATCHED binary under gdb with no breakpoints.
#        Use this when the submission IS an already-modified binary file
#        that is expected to reach the privileged state on its own, even
#        while traced (e.g. patched integrity checks, hardcoded ptrace
#        results, NOP'd checksum calls, etc). This is the original
#        behavior and is correct for that submission type: a genuine
#        static-patch bypass must survive being traced with no further help.
#
#   2) verify.sh <binary> --script <gdb_commands_file>
#        Runs a participant-supplied GDB command file (their own
#        breakpoints / register overrides, one gdb command per line,
#        e.g. a file containing:
#            break *0x14c4
#            run
#            set $edi = 0x137b0ed6
#            continue
#        ) against the given (normally unmodified) binary. Use this for
#        "live GDB script" submissions.
#
#   3) verify.sh <binary> --break 0xADDR --reg <name> --key 0xKEY
#        Author-side convenience mode: builds and runs the
#        break/run/set/continue sequence directly from values you already
#        derived yourself (via extract_key.py + objdump/raw byte analysis
#        against THIS SPECIFIC binary -- these addresses are architecture-
#        and build-specific and are never auto-discovered by this script).
#        --reg is the register holding the key argument right before the
#        call/bl to enter_privileged_state: "edi" on x86_64 (SysV ABI,
#        first integer arg), "w0" on aarch64 (AAPCS64, first arg).
#
# PASS requires "ROOT INTEGRITY VERIFIED" to appear in the captured
# output before the timeout.
#
# Environment overrides:
#   GDB_BIN       gdb binary to use (default: gdb). Set to gdb-multiarch
#                 or an aarch64 gdb when verifying an arm64 target from
#                 an amd64 host.
#   TIMEOUT_SECS  seconds to let the target run before killing it
#                 (default: 5). The agent prints its success/failure
#                 message immediately (unbuffered stdout) and then either
#                 exits (failure) or sleeps forever (success), so the
#                 timeout only needs to outlast the probes + decrypt, not
#                 the whole "Monitoring..." loop.

set -u

GDB_BIN="${GDB_BIN:-gdb}"
TIMEOUT_SECS="${TIMEOUT_SECS:-5}"

usage() {
    cat >&2 <<'EOF'
Usage:
  verify.sh <patched_binary>
  verify.sh <binary> --script <gdb_commands_file>
  verify.sh <binary> --break 0xADDR --reg <edi|w0|...> --key 0xKEY

Env:
  GDB_BIN=gdb-multiarch verify.sh ...     # use a different gdb
  TIMEOUT_SECS=8 verify.sh ...            # change the capture window
EOF
    exit 1
}

[ $# -ge 1 ] || usage
TARGET_BIN="$1"; shift

if [ ! -f "$TARGET_BIN" ]; then
    echo "[FAIL] No such file: $TARGET_BIN" >&2
    exit 1
fi
chmod +x "$TARGET_BIN" 2>/dev/null

SCRIPT_FILE=""
BREAK_ADDR=""
REG_NAME=""
KEY_VAL=""

while [ $# -gt 0 ]; do
    case "$1" in
        --script) SCRIPT_FILE="${2:-}"; shift 2 ;;
        --break)  BREAK_ADDR="${2:-}"; shift 2 ;;
        --reg)    REG_NAME="${2:-}"; shift 2 ;;
        --key)    KEY_VAL="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "[FAIL] Unknown argument: $1" >&2; usage ;;
    esac
done

GDB_ARGS=(-batch -nx)
CLEANUP_FILES=()
cleanup() { for f in "${CLEANUP_FILES[@]:-}"; do [ -n "$f" ] && rm -f "$f"; done; }
trap cleanup EXIT

if [ -n "$SCRIPT_FILE" ]; then
    # Mode 2: run a participant-supplied gdb command file as-is. Deliberately
    # NOT PIE-bias-corrected -- this replays exactly what was submitted.
    if [ -n "$BREAK_ADDR$REG_NAME$KEY_VAL" ]; then
        echo "[FAIL] --script cannot be combined with --break/--reg/--key." >&2
        usage
    fi
    [ -f "$SCRIPT_FILE" ] || { echo "[FAIL] gdb script not found: $SCRIPT_FILE" >&2; exit 1; }
    GDB_ARGS+=(-x "$SCRIPT_FILE")
    MODE="script"
elif [ -n "$BREAK_ADDR" ] || [ -n "$REG_NAME" ] || [ -n "$KEY_VAL" ]; then
    # Mode 3: all three of --break/--reg/--key are required together.
    if [ -z "$BREAK_ADDR" ] || [ -z "$REG_NAME" ] || [ -z "$KEY_VAL" ]; then
        echo "[FAIL] --break, --reg, and --key must all be supplied together." >&2
        usage
    fi

    ABS_BIN="$(cd "$(dirname "$TARGET_BIN")" && pwd)/$(basename "$TARGET_BIN")"

    # $BREAK_ADDR is the link-time/file address (what objdump/readelf show --
    # i.e. the address assuming a PIE load bias of 0). For a PIE binary the
    # real runtime breakpoint address is (actual load base + $BREAK_ADDR),
    # and GDB's automatic translation of a raw "break *0xADDR" is not always
    # reliable in every environment (seen in practice: "Cannot insert
    # breakpoint ... Cannot access memory"). So for PIE targets we compute
    # the real base ourselves from /proc/<pid>/maps after the process is
    # loaded (via `starti`, which stops at the ELF entry point before any
    # of the agent's own code runs) instead of trusting GDB to do it.
    ELF_TYPE_LINE="$(readelf -h "$TARGET_BIN" 2>/dev/null | grep -i '^ *Type:')"
    IS_PIE=0
    case "$ELF_TYPE_LINE" in *DYN*) IS_PIE=1 ;; esac

    if [ "$IS_PIE" = "1" ]; then
        PIE_HELPER="$(mktemp /tmp/verify_pie_helper.XXXXXX.py)"
        CLEANUP_FILES+=("$PIE_HELPER")
        cat > "$PIE_HELPER" <<PYEOF
import os
pid = gdb.selected_inferior().pid
target_path = os.path.realpath("${ABS_BIN}")
base = None
with open("/proc/%d/maps" % pid) as f:
    for line in f:
        parts = line.split()
        if len(parts) >= 6 and os.path.realpath(parts[5]) == target_path:
            start = int(parts[0].split("-")[0], 16)
            if base is None or start < base:
                base = start
if base is None:
    raise gdb.error("verify.sh: could not find a mapping for " + target_path +
                     " in /proc/%d/maps -- is the path/binary correct?" % pid)
target = base + ${BREAK_ADDR}
print("[verify.sh] PIE load base=0x%x  real breakpoint addr=0x%x" % (base, target))
gdb.execute("break *0x%x" % target)
PYEOF
        GDB_ARGS+=(-ex "starti")
        GDB_ARGS+=(-x "$PIE_HELPER")
        GDB_ARGS+=(-ex "continue")
    else
        # Non-PIE: the raw address from objdump/readelf already IS the
        # real runtime address, no translation needed.
        GDB_ARGS+=(-ex "break *${BREAK_ADDR}")
        GDB_ARGS+=(-ex "run")
    fi

    GDB_ARGS+=(-ex "set \$${REG_NAME} = ${KEY_VAL}")
    GDB_ARGS+=(-ex "continue")
    MODE="break-reg-key (PIE=${IS_PIE})"
else
    # Mode 1: plain run, no breakpoints -- for statically patched binaries.
    GDB_ARGS+=(-ex "run")
    MODE="static-patch"
fi
GDB_ARGS+=(-ex "quit")

# Resolve gdb only after argument validation, so a missing gdb never masks
# a usage mistake (unknown flag, bad combo, incomplete triple, etc).
if ! command -v "$GDB_BIN" >/dev/null 2>&1; then
    echo "[FAIL] '$GDB_BIN' not found on PATH. Install gdb, or set GDB_BIN=<path>." >&2
    exit 1
fi

echo "[*] Mode: $MODE   gdb: $GDB_BIN   timeout: ${TIMEOUT_SECS}s" >&2

OUTPUT=$(timeout "$TIMEOUT_SECS" "$GDB_BIN" "${GDB_ARGS[@]}" "$TARGET_BIN" 2>&1)

echo "$OUTPUT"
echo "-----"

if echo "$OUTPUT" | grep -q "ROOT INTEGRITY VERIFIED"; then
    echo "[PASS] Privileged state reached under GDB."
    exit 0
else
    echo "[FAIL] Did not reach privileged state under GDB."
    exit 1
fi