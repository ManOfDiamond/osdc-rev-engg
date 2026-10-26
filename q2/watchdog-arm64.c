#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdint.h>

/*
 * Target ciphertext. Decrypts under the correct runtime key to:
 * "[+] ROOT INTEGRITY VERIFIED: Privileged sensor daemon initialized.\n"
 * No plaintext marker is stored anywhere; correctness is verified by CRC32.
 */
/* generated for key = 0xf1e2b812 */
static uint8_t enc_payload[] = {
    0xac, 0xbb, 0x0c, 0xc9, 0x14, 0xe0, 0xf4, 0x3d,
    0x81, 0x47, 0x6f, 0x9d, 0xa8, 0x40, 0xea, 0x7a,
    0xb9, 0x8c, 0xd2, 0xee, 0xa9, 0x25, 0x4b, 0x1b,
    0x5d, 0x65, 0xdb, 0xad, 0x71, 0x3e, 0xb2, 0x33,
    0x8d, 0xce, 0xf6, 0x87, 0xd3, 0x02, 0xcb, 0x70,
    0x24, 0xe5, 0xaf, 0x09, 0x04, 0x59, 0x54, 0x56,
    0x73, 0xb6, 0xb2, 0xe7, 0x4c, 0x39, 0xa3, 0x4a,
    0xb5, 0xff, 0x56, 0xe4, 0xf1, 0xec, 0xbd, 0xab,
    0xd9, 0xc5, 0x79,
    0x00
};
#define EXPECTED_CRC32 0xae92defeu  /* unchanged -- depends only on the plaintext */
#define PAYLOAD_LEN (sizeof(enc_payload) - 1)

// Raw syscall wrapper: bypasses libc entirely, so there's no PLT entry to hook
static inline long raw_syscall(long num, long a1, long a2, long a3, long a4) {
    long ret;
    #if defined(__x86_64__)
    __asm__ volatile (
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3), "r"(a4)
        : "rcx", "r11", "memory"
    );
    #elif defined(__aarch64__)
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile (
        "svc #0"
        : "=r"(x0)
        : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3)
        : "memory"
    );
    ret = x0;
    #else
    ret = syscall(num, a1, a2, a3, a4);
    #endif
    return ret;
}

// 1. Direct raw ptrace check (no PLT symbol to hook)
long check_raw_ptrace(void) {
    #if defined(__x86_64__)
    return raw_syscall(101 /* SYS_ptrace */, 0 /* PTRACE_TRACEME */, 0, 1, 0);
    #elif defined(__aarch64__)
    return raw_syscall(117 /* SYS_ptrace */, 0 /* PTRACE_TRACEME */, 0, 1, 0);
    #else
    return ptrace(0, 0, 1, 0);
    #endif
}

// 2. Direct raw open/read of /proc/self/status
int check_raw_tracerpid(void) {
    char buf[1024];
    #if defined(__x86_64__)
    long fd = raw_syscall(2 /* SYS_open */, (long)"/proc/self/status", O_RDONLY, 0, 0);
    #elif defined(__aarch64__)
    long fd = raw_syscall(56 /* SYS_openat */, AT_FDCWD, (long)"/proc/self/status", O_RDONLY, 0);
    #else
    long fd = open("/proc/self/status", O_RDONLY);
    #endif

    if (fd < 0) return 0;

    #if defined(__x86_64__)
    long bytes = raw_syscall(0 /* SYS_read */, fd, (long)buf, sizeof(buf) - 1, 0);
    raw_syscall(3 /* SYS_close */, fd, 0, 0, 0);
    #elif defined(__aarch64__)
    long bytes = raw_syscall(63 /* SYS_read */, fd, (long)buf, sizeof(buf) - 1, 0);
    raw_syscall(57 /* SYS_close */, fd, 0, 0, 0);
    #else
    long bytes = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    #endif

    if (bytes <= 0) return 0;
    buf[bytes] = '\0';

    char *p = strstr(buf, "TracerPid:");
    if (p) {
        return atoi(p + 10);
    }
    return 0;
}

// FNV-1a over a code region. Patching a single instruction byte in that
// region mutates this value completely.
static uint32_t checksum32(uint8_t *addr, size_t len) {
    uint32_t chk = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        chk ^= addr[i];
        chk *= 16777619u;
    }
    return chk;
}

static inline uint32_t rotl32(uint32_t v, int s) {
    return (v << s) | (v >> (32 - s));
}

// Second, independent region folded into the key. Keep this body stable.
__attribute__((noinline))
static uint32_t probe_environment_signature(uint32_t seed) {
    seed ^= 0x9E3779B9u;
    seed = rotl32(seed, 5) + 0x7F4A7C15u;
    seed ^= (seed >> 11);
    return seed;
}

// splitmix32: expands a single 32-bit key into a byte keystream
static uint32_t splitmix32_next(uint32_t *state) {
    uint32_t z = (*state += 0x9E3779B9u);
    z = (z ^ (z >> 16)) * 0x21F0AAADu;
    z = (z ^ (z >> 15)) * 0x735A2D97u;
    z = z ^ (z >> 15);
    return z;
}

static uint32_t crc32_calc(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

void enter_privileged_state(uint32_t key) {
    char decrypted[sizeof(enc_payload)];
    uint32_t state = key;
    uint32_t ks_word = 0;
    for (size_t i = 0; i < PAYLOAD_LEN; i++) {
        if (i % 4 == 0) ks_word = splitmix32_next(&state) ^ key;
        uint8_t ks = (uint8_t)(ks_word >> ((i % 4) * 8));
        decrypted[i] = enc_payload[i] ^ ks;
    }
    decrypted[PAYLOAD_LEN] = '\0';

    // Integrity gate: a wrong key decrypts to garbage, and garbage will not
    // match this CRC. Nothing human-readable is compared directly.
    if (crc32_calc((uint8_t *)decrypted, PAYLOAD_LEN) != EXPECTED_CRC32) {
        puts("[!] INTEGRITY FAULT: Telemetry state corruption / code tampering detected.");
        puts("[-] Process terminated.");
        exit(1);
    }

    puts("[+] INTEGRITY CHECK PASSED: Host telemetry environment verified.");
    printf("%s", decrypted);
    puts("[*] Monitoring endpoint operations... (Press Ctrl+C to terminate)");

    while (1) {
        sleep(5);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("[*] Starting Watchdog Endpoint Agent v3.2 (Kernel Enforced)...");
    puts("[*] Probing runtime execution environment for untrusted instrumentation...");

    long pt_status = check_raw_ptrace();     // 0 if clean, -1 if traced
    int tracer_pid = check_raw_tracerpid();  // 0 if clean, >0 if traced

    // Checksum two disjoint, fixed-size code regions. Any binary patch in
    // either one mutates the key below.
    uint32_t h1 = checksum32((uint8_t *)check_raw_ptrace, 0x30);
    uint32_t h2 = checksum32((uint8_t *)probe_environment_signature, 0x30);
    uint32_t base = (h1 * 0x9E3779B1u) ^ rotl32(h2, 13);

    /*
     * MATHEMATICAL LOCK:
     * When uninstrumented, pt_status == 0 and tracer_pid == 0, so this term
     * is zero and the key is derived purely from the code checksums above.
     * Under a debugger or tracer, this term becomes nonzero noise and the
     * key silently diverges -- there is no branch here to flip or NOP.
     */
    uint32_t taint = ((uint32_t)pt_status * 0x85EBCA6Bu) ^ ((uint32_t)tracer_pid * 0xC2B2AE35u);
    uint32_t derived_key = rotl32(base ^ taint, 7) + 0x01234567u;
    derived_key = probe_environment_signature(derived_key) ^ derived_key;
    enter_privileged_state(derived_key);

    return 0;
}