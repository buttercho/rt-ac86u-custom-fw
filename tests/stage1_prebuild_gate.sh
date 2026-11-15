#!/usr/bin/env bash
# ==============================================================================
# stage1_prebuild_gate.sh — Fail-Closed Pre-Build Patch, Blob & ABI Gate
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PATCH_DIR="${FW_ROOT}/patches"

ALREADY_PATCHED=0
APPLY_SET2="${APPLY_SET2:-1}"
MERLIN_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --already-patched)
            ALREADY_PATCHED=1
            shift
            ;;
        --set1-only)
            APPLY_SET2=0
            shift
            ;;
        *)
            MERLIN_DIR="$1"
            shift
            ;;
    esac
done

export APPLY_SET2

if [[ -z "${MERLIN_DIR}" || ! -d "${MERLIN_DIR}" ]]; then
    echo "Usage: $0 [--already-patched] [--set1-only] <path-to-asuswrt-merlin.ng>" >&2
    exit 1
fi

MERLIN_DIR="$(cd "${MERLIN_DIR}" && pwd)"
echo "======================================================================"
echo "STAGE 1: Pre-Build Patch, Struct ABI & Closed-Source Blob Contract Gate (APPLY_SET2=${APPLY_SET2})"
echo "======================================================================"

if [[ "${ALREADY_PATCHED}" -eq 0 ]]; then
    APPLY_SET2="${APPLY_SET2}" "${FW_ROOT}/scripts/apply_backports.sh" --check-only "${MERLIN_DIR}"
    APPLY_SET2="${APPLY_SET2}" python3 "${SCRIPT_DIR}/check_blob_contracts.py" \
        --merlin-dir "${MERLIN_DIR}" \
        --patch-dir "${PATCH_DIR}"
    APPLY_SET2="${APPLY_SET2}" python3 "${SCRIPT_DIR}/audit_build_graph.py" \
        --merlin-dir "${MERLIN_DIR}" \
        --patch-dir "${PATCH_DIR}"
else
    echo "[stage1:git] Checking for .rej / .orig merge artifacts..."
    REJ_FILES="$(find "${MERLIN_DIR}/release" \( -name '*.rej' -o -name '*.orig' \) 2>/dev/null | head -n 20 || true)"
    if [[ -n "${REJ_FILES}" ]]; then
        echo "FATAL: Found patch reject/orig artifacts:" >&2
        echo "${REJ_FILES}" >&2
        exit 1
    fi
    APPLY_SET2="${APPLY_SET2}" python3 "${SCRIPT_DIR}/check_blob_contracts.py" \
        --merlin-dir "${MERLIN_DIR}" \
        --patch-dir "${PATCH_DIR}" \
        --already-patched
    APPLY_SET2="${APPLY_SET2}" python3 "${SCRIPT_DIR}/audit_build_graph.py" \
        --merlin-dir "${MERLIN_DIR}" \
        --patch-dir "${PATCH_DIR}" \
        --already-patched
fi

# Cross-compiler ABI assertions (automatically runs in CI container when HND toolchains are in PATH)
ARM_GCC="$(command -v arm-buildroot-linux-gnueabi-gcc || true)"
AARCH64_GCC="$(command -v aarch64-buildroot-linux-gnu-gcc || true)"

TMP_OBJ="$(mktemp -d -t stage1_abi_XXXXXX)"
trap 'rm -rf "${TMP_OBJ}"' EXIT

if [[ -n "${ARM_GCC}" ]]; then
    echo "[stage1:abi] Verifying 32-bit HND ARM soft-float, -march=armv8-a+crc & struct nvram_tuple ABI via ${ARM_GCC}..."
    NVRAM_INC="${MERLIN_DIR}/release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/include"
    EXTRA_INC=()
    if [[ -f "${NVRAM_INC}/bcmnvram.h" ]]; then
        EXTRA_INC=(-DCHECK_MERLIN_HEADERS -I"${NVRAM_INC}")
    fi
    "${ARM_GCC}" -std=gnu11 -mabi=aapcs-linux -marm -msoft-float -ffixed-r8 \
        -march=armv8-a+crc -mtune=cortex-a53 \
        "${EXTRA_INC[@]}" -Wall -Werror -c "${SCRIPT_DIR}/abi_asserts.c" -o "${TMP_OBJ}/abi32.o"
    echo "[stage1:abi] PASS: 32-bit ARM EABI5 soft-float, -march=armv8-a+crc & nvram ABI assertions passed."
    if [[ "${ALREADY_PATCHED}" -eq 1 ]]; then
        python3 "${SCRIPT_DIR}/stage1_syntax_preflight.py" \
            --merlin-dir "${MERLIN_DIR}" \
            --cc "${ARM_GCC}"
    fi
else
    echo "[stage1:abi] Host mode (arm-buildroot-linux-gnueabi-gcc not in PATH; will run inside fw-build CI container)."
fi

if [[ -n "${AARCH64_GCC}" ]]; then
    echo "[stage1:abi] Verifying 64-bit BCM4906 Cortex-A53 ARMv8-CE compiler flags via ${AARCH64_GCC}..."
    "${AARCH64_GCC}" -std=gnu11 -march=armv8-a+crc+crypto -mtune=cortex-a53 \
        -Wall -Werror -c "${SCRIPT_DIR}/abi_asserts.c" -o "${TMP_OBJ}/abi64.o"
    echo "[stage1:abi] PASS: 64-bit AArch64 +crc+crypto ABI assertions passed."
fi

# Verify kernel config_base.6a does NOT enable struct-mutating debug options that alter sk_buff / module CRCs
CFG_6A="${MERLIN_DIR}/release/src-rt-5.02hnd/kernel/linux-4.1/config_base.6a"
if [[ -f "${CFG_6A}" ]]; then
    for forbidden_kcfg in "CONFIG_DEBUG_LOCK_ALLOC=y" "CONFIG_LOCKDEP=y" "CONFIG_SLUB_DEBUG_ON=y" "CONFIG_MODVERSIONS=n"; do
        if grep -q "^${forbidden_kcfg}$" "${CFG_6A}"; then
            echo "FATAL: Forbidden struct/CRC-breaking kernel option ${forbidden_kcfg} found in config_base.6a!" >&2
            exit 1
        fi
    done
    echo "[stage1:kernel] Verified config_base.6a preserves sk_buff/blog_p & module CRC invariants."
fi

echo "==> STAGE 1 PASSED."
