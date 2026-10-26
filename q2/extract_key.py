#!/usr/bin/env python3
"""
extract_key.py - Operation Watchdog key extractor

Computes the "clean" (untraced) derived_key directly from the real compiled
bytes of a watchdog_agent binary -- the same way a legitimate solver would:
read check_raw_ptrace()/probe_environment_signature()'s actual instruction
bytes off disk
(never from a live, possibly-traced process) and run the known algorithm.

Usage:
    python3 extract_key.py /path/to/watchdog_agent
    python3 extract_key.py /path/to/watchdog_agent_arm --cross aarch64-linux-gnu-

Requires: nm, readelf, objcopy (or their <prefix>- cross-tool equivalents)
on PATH. Works on stripped OR unstripped binaries -- if the binary is stripped, pass
--ptrace/--probe addresses manually (see --help).
"""
import argparse
import re
import subprocess
import sys


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def find_symbol_addr(binary, symbol, nm_bin):
    out = run([nm_bin, binary])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == symbol and parts[1] in ("T", "t"):
            return int(parts[0], 16)
    return None


def find_text_vaddr(binary, readelf_bin):
    out = run([readelf_bin, "-S", binary])
    lines = out.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\.text\s", line):
            # the address is the 4th field in this line format:
            # [16] .text  PROGBITS  <addr>  <offset>
            m = re.search(r"PROGBITS\s+([0-9a-fA-F]+)", line)
            if m:
                return int(m.group(1), 16)
    raise RuntimeError("could not find .text section address; inspect `readelf -S` output manually")


def extract_text(binary, objcopy_bin, out_path="_text_extract.bin"):
    run([objcopy_bin, "-O", "binary", "--only-section=.text", binary, out_path])
    with open(out_path, "rb") as f:
        return f.read()


def fnv1a32(data: bytes) -> int:
    chk = 2166136261
    for byte in data:
        chk ^= byte
        chk = (chk * 16777619) & 0xFFFFFFFF
    return chk


def rotl32(v: int, s: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF


def probe_environment_signature(seed: int) -> int:
    seed &= 0xFFFFFFFF
    seed ^= 0x9E3779B9
    seed = (rotl32(seed, 5) + 0x7F4A7C15) & 0xFFFFFFFF
    seed ^= (seed >> 11)
    return seed & 0xFFFFFFFF


def derive_key(h1: int, h2: int, pt_status: int = 0, tracer_pid: int = 0) -> int:
    base = ((h1 * 0x9E3779B1) & 0xFFFFFFFF) ^ rotl32(h2, 13)
    taint = (((pt_status & 0xFFFFFFFF) * 0x85EBCA6B) & 0xFFFFFFFF) ^ \
            (((tracer_pid & 0xFFFFFFFF) * 0xC2B2AE35) & 0xFFFFFFFF)
    pre = (rotl32(base ^ taint, 7) + 0x01234567) & 0xFFFFFFFF
    return (probe_environment_signature(pre) ^ pre) & 0xFFFFFFFF


def splitmix32_next(state: int):
    state = (state + 0x9E3779B9) & 0xFFFFFFFF
    z = state
    z = ((z ^ (z >> 16)) * 0x21F0AAAD) & 0xFFFFFFFF
    z = ((z ^ (z >> 15)) * 0x735A2D97) & 0xFFFFFFFF
    z ^= (z >> 15)
    return state, z & 0xFFFFFFFF


def decrypt(enc: bytes, key: int) -> bytes:
    state = key
    out = bytearray()
    for i, b in enumerate(enc):
        if i % 4 == 0:
            state, sm = splitmix32_next(state)
            ks_word = sm ^ key
        ks = (ks_word >> ((i % 4) * 8)) & 0xFF
        out.append(b ^ ks)
    return bytes(out)


def crc32_calc(buf: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in buf:
        crc ^= byte
        for _ in range(8):
            mask = -(crc & 1) & 0xFFFFFFFF
            crc = (crc >> 1) ^ (0xEDB88320 & mask)
    return (~crc) & 0xFFFFFFFF


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="path to the watchdog_agent binary")
    ap.add_argument("--cross", default="", help="cross-toolchain prefix, e.g. aarch64-linux-gnu-")
    ap.add_argument("--ptrace", type=lambda x: int(x, 0), default=None,
                    help="check_raw_ptrace() address in hex, if binary is stripped")
    ap.add_argument("--probe", type=lambda x: int(x, 0), default=None,
                    help="probe_environment_signature() address in hex, if binary is stripped")
    ap.add_argument("--ptrace-len", type=lambda x: int(x, 0), default=0x30)
    ap.add_argument("--probe-len", type=lambda x: int(x, 0), default=0x30)
    ap.add_argument("--enc-payload", default=None,
                     help="comma-separated hex bytes of enc_payload (without trailing 0x00), to decrypt+verify")
    ap.add_argument("--expected-crc32", default=None, help="hex EXPECTED_CRC32 from the source, to verify")
    args = ap.parse_args()

    nm_bin = args.cross + "nm"
    readelf_bin = args.cross + "readelf"
    objcopy_bin = args.cross + "objcopy"

    ptrace_addr = args.ptrace
    probe_addr = args.probe
    if ptrace_addr is None:
        ptrace_addr = find_symbol_addr(args.binary, "check_raw_ptrace", nm_bin)
    if probe_addr is None:
        probe_addr = find_symbol_addr(args.binary, "probe_environment_signature", nm_bin)

    if ptrace_addr is None or probe_addr is None:
        print("Could not resolve symbols automatically (binary likely stripped).", file=sys.stderr)
        print("Re-run with --ptrace 0x... --probe 0x... (use the unstripped build to find them).", file=sys.stderr)
        sys.exit(1)

    text_vaddr = find_text_vaddr(args.binary, readelf_bin)
    text_bytes = extract_text(args.binary, objcopy_bin)

    def extract(addr, length):
        off = addr - text_vaddr
        return text_bytes[off:off + length]

    h1 = fnv1a32(extract(ptrace_addr, args.ptrace_len))
    h2 = fnv1a32(extract(probe_addr, args.probe_len))
    key = derive_key(h1, h2, pt_status=0, tracer_pid=0)

    print(f"check_ptrace  = 0x{ptrace_addr:x}")
    print(f"probe         = 0x{probe_addr:x}")
    print(f"h1            = 0x{h1:08x}")
    print(f"h2            = 0x{h2:08x}")
    print(f"derived_key   = 0x{key:08x}   (assumes clean: pt_status=0, tracer_pid=0)")

    if args.enc_payload:
        enc = bytes(int(b, 16) for b in args.enc_payload.split(","))
        dec = decrypt(enc, key)
        crc = crc32_calc(dec)
        print(f"decrypted     = {dec!r}")
        print(f"crc32         = 0x{crc:08x}")
        if args.expected_crc32:
            expected = int(args.expected_crc32, 16)
            print("MATCH" if crc == expected else "MISMATCH", "against --expected-crc32")


if __name__ == "__main__":
    main()
