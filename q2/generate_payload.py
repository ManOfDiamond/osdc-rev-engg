#!/usr/bin/env python3
"""
generate_payload.py - Operation Watchdog payload regenerator

Given a derived_key (from extract_key.py, run against a specific build),
produces the enc_payload[] C array for that build. EXPECTED_CRC32 is NOT
regenerated here because it only depends on the plaintext message, not the
key -- it is the same 0xae92defe for every build/architecture.

Usage:
    python3 generate_payload.py 0x2cfee65e
    python3 generate_payload.py 0x171ddce4 --message "custom text\n"
"""
import argparse


def splitmix32_next(state: int):
    state = (state + 0x9E3779B9) & 0xFFFFFFFF
    z = state
    z = ((z ^ (z >> 16)) * 0x21F0AAAD) & 0xFFFFFFFF
    z = ((z ^ (z >> 15)) * 0x735A2D97) & 0xFFFFFFFF
    z ^= (z >> 15)
    return state, z & 0xFFFFFFFF


def encrypt(plain: bytes, key: int) -> bytes:
    state = key
    out = bytearray()
    for i, b in enumerate(plain):
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
    ap.add_argument("key", type=lambda x: int(x, 0), help="derived_key from extract_key.py, e.g. 0x2cfee65e")
    ap.add_argument("--message", default="[+] ROOT INTEGRITY VERIFIED: Privileged sensor daemon initialized.\n",
                     help="plaintext to encrypt (default: the standard target message)")
    args = ap.parse_args()

    plain = args.message.encode()
    enc = encrypt(plain, args.key)
    crc = crc32_calc(plain)

    lines = []
    for i in range(0, len(enc), 8):
        chunk = enc[i:i + 8]
        lines.append("    " + ", ".join("0x%02x" % c for c in chunk) + ",")
    body = "\n".join(lines)

    print("/* generated for key = 0x%08x */" % args.key)
    print("static uint8_t enc_payload[] = {")
    print(body)
    print("    0x00")
    print("};")
    print("#define EXPECTED_CRC32 0x%08xu  /* unchanged -- depends only on the plaintext */" % crc)

    # round-trip sanity check
    state = args.key
    dec = bytearray()
    for i in range(len(enc)):
        if i % 4 == 0:
            state, sm = splitmix32_next(state)
            ks_word = sm ^ args.key
        ks = (ks_word >> ((i % 4) * 8)) & 0xFF
        dec.append(enc[i] ^ ks)
    assert bytes(dec) == plain, "round-trip failed -- this should never happen"
    assert crc32_calc(dec) == crc


if __name__ == "__main__":
    main()
