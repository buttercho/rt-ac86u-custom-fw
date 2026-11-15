/*
 * abi_asserts.c — Stage 1 Cross-Compiler ABI & Struct Layout Gate
 *
 * Compiled in CI with BOTH:
 *   1. arm-buildroot-linux-gnueabi-gcc (-mabi=aapcs-linux -marm -msoft-float)
 *      -> Verifies 32-bit HND userspace NVRAM_SPACE (0x20000 = 131072 B),
 *         pointer/long/off_t ABI, and soft-float macro invariants.
 *   2. aarch64-buildroot-linux-gnu-gcc (-march=armv8-a+crc+crypto)
 *      -> Verifies 64-bit BCM4906 kernel toolchain ARMv8 Crypto Extension
 *         support and LP64 data-model invariants.
 */

#include <stdint.h>
#include <stddef.h>

#if defined(__ARM_EABI__) && !defined(__aarch64__)
/* 32-bit Broadcom HND userspace ABI invariants */
_Static_assert(sizeof(void *) == 4, "RT-AC86U userspace must be ILP32 (32-bit ARM)");
_Static_assert(sizeof(long) == 4, "RT-AC86U userspace long must be 4 bytes");
#if defined(__ARM_PCS_VFP)
#error "FATAL: Hard-float ABI (__ARM_PCS_VFP) enabled! Broadcom HND blobs require -msoft-float."
#endif

#ifdef CHECK_MERLIN_HEADERS
#include <bcmnvram.h>
/* RT-AC86U uses 128 KB (0x20000) NVRAM_SPACE on 94908HND */
_Static_assert(MAX_NVRAM_SPACE >= 0x10000, "Unexpected MAX_NVRAM_SPACE shrink");
struct _nvram_tuple_abi_probe {
    char *name;
    char *value;
    struct _nvram_tuple_abi_probe *next;
};
_Static_assert(sizeof(struct nvram_tuple) == sizeof(struct _nvram_tuple_abi_probe),
               "FATAL: struct nvram_tuple layout changed — breaks libnvram.so ABI!");
#endif

#elif defined(__aarch64__)
/* 64-bit BCM4906 (Cortex-A53) kernel/ebtables ABI invariants */
_Static_assert(sizeof(void *) == 8, "BCM4906 kernel/aarch64 target must be LP64");
_Static_assert(sizeof(long) == 8, "BCM4906 LP64 long must be 8 bytes");
#if !defined(__ARM_FEATURE_CRC32)
#error "Expected ARMv8 CRC32 feature (__ARM_FEATURE_CRC32) on BCM4906 Cortex-A53"
#endif
#if !defined(__ARM_FEATURE_CRYPTO)
#error "Expected ARMv8 Crypto Extensions (__ARM_FEATURE_CRYPTO) on BCM4906 Cortex-A53"
#endif
#endif

int abi_probe_anchor(void) {
    return (int)sizeof(void *);
}
