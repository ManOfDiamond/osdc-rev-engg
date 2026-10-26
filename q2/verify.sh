#!/usr/bin/env bash
TARGET_BIN="$1"

if [ -z "$TARGET_BIN" ] || [ ! -f "$TARGET_BIN" ]; then
    echo "Usage: ./verify.sh <path_to_patched_binary>"
    exit 1
fi

chmod +x "$TARGET_BIN"

# Run under GDB with a 3-second timeout
OUTPUT=$(timeout 3 gdb -batch -ex "run" -ex "quit" "$TARGET_BIN" 2>&1)

if echo "$OUTPUT" | grep -q "ROOT INTEGRITY VERIFIED"; then
    echo "[PASS] Challenge successfully solved! Privileged state achieved under GDB."
    exit 0
else
    echo "[FAIL] Binary failed to run or triggered an integrity fault under GDB."
    exit 1
fi
