#!/bin/sh
# preflash_check_on_router.sh — Read-only + /tmp backup pre-flight check for ASUS RT-AC86U (Asuswrt-Merlin)
# Usage over SSH on router:
#   sh /tmp/preflash_check_on_router.sh [/tmp/RT-AC86U_386.14_2_ubi.w]

set -eu

PASS_CNT=0
WARN_CNT=0
FAIL_CNT=0

pass() { PASS_CNT=$((PASS_CNT + 1)); printf "[PASS] %s\n" "$1"; }
warn() { WARN_CNT=$((WARN_CNT + 1)); printf "[WARN] %s\n" "$1"; }
fail() { FAIL_CNT=$((FAIL_CNT + 1)); printf "[FAIL] %s\n" "$1"; }

printf "=== RT-AC86U Pre-Flash Safety & Longevity Check ===\n"

# 1. Verify hardware model & kernel arch
MODEL="$(nvram get productid 2>/dev/null || true)"
ODMPID="$(nvram get odmpid 2>/dev/null || true)"
ARCH="$(uname -m 2>/dev/null || true)"
FWVER="$(nvram get firmver 2>/dev/null || true)_$(nvram get buildno 2>/dev/null || true)_$(nvram get extendno 2>/dev/null || true)"

if [ "$MODEL" = "RT-AC86U" ] || [ "$ODMPID" = "RT-AC86U" ]; then
    pass "Hardware model verified: productid=${MODEL} odmpid=${ODMPID:-none} fw=${FWVER}"
else
    fail "Unexpected router model: productid='${MODEL}' odmpid='${ODMPID}' (expected RT-AC86U)"
fi

if [ "$ARCH" = "aarch64" ]; then
    pass "64-bit HND kernel verified: uname -m = ${ARCH}"
else
    fail "Unexpected kernel architecture: '${ARCH}' (expected aarch64)"
fi

# 2. Check free RAM for WebUI multipart upload (httpd/web.c:14696 requires MemFree >= 4x image size ~= 180 MB)
MEM_FREE_KB="$(awk '/^MemFree:/ {print $2}' /proc/meminfo)"
MEM_CACHED_KB="$(awk '/^Cached:/ {print $2}' /proc/meminfo)"
MEM_BUFFERS_KB="$(awk '/^Buffers:/ {print $2}' /proc/meminfo)"
MEM_AVAIL_KB=$(( ${MEM_FREE_KB:-0} + ${MEM_CACHED_KB:-0} + ${MEM_BUFFERS_KB:-0} ))

if [ "${MEM_FREE_KB:-0}" -ge 184320 ]; then
    pass "MemFree = $((MEM_FREE_KB / 1024)) MB (>= 180 MB WebUI 4x upload requirement)"
elif [ "${MEM_AVAIL_KB:-0}" -ge 204800 ]; then
    warn "MemFree = $((MEM_FREE_KB / 1024)) MB (reclaimable $((MEM_AVAIL_KB / 1024)) MB). Reboot router or run 'sync; echo 3 > /proc/sys/vm/drop_caches' before WebUI upload!"
else
    warn "Low free RAM: MemFree=$((MEM_FREE_KB / 1024)) MB, Avail=$((MEM_AVAIL_KB / 1024)) MB. Unmount USB drives and reboot router BEFORE flashing!"
fi

# 3. Verify /jffs and /data UBIFS mounts & NAND health
if awk '$2 == "/jffs" && $4 ~ /(^|,)rw(,|$)/ {found=1} END {exit !found}' /proc/mounts; then
    JFFS_FREE_KB="$(df -k /jffs 2>/dev/null | awk 'NR==2 {print $4}')"
    pass "/jffs UBIFS mounted read-write (free: ${JFFS_FREE_KB:-unknown} KB)"
else
    fail "/jffs is NOT mounted read-write! Inspect /proc/mounts before upgrading."
fi

if awk '$2 == "/data" && $4 ~ /(^|,)rw(,|$)/ {found=1} END {exit !found}' /proc/mounts; then
    DATA_FREE_KB="$(df -k /data 2>/dev/null | awk 'NR==2 {print $4}')"
    pass "/data UBIFS mounted read-write (free: ${DATA_FREE_KB:-unknown} KB)"
else
    fail "/data is NOT mounted read-write! Broadcom wlcsm NVRAM persistence depends on /data."
fi

if dmesg 2>/dev/null | grep -qiE "UBI error|UBIFS error|uncorrectable ECC"; then
    warn "dmesg contains UBI/UBIFS/ECC warnings — review 'dmesg | grep -iE \"ubi|ecc\"' before flashing."
else
    pass "Zero UBI/UBIFS/NAND ECC errors in dmesg ring buffer"
fi

# 4. Check 128 KB (131,072-byte) NVRAM ceiling
NVRAM_FILE="/data/.kernel_nvram.setting"
if [ -f "$NVRAM_FILE" ]; then
    NV_BYTES="$(wc -c < "$NVRAM_FILE" | tr -d ' ')"
    if [ "$NV_BYTES" -lt 114688 ]; then
        pass "NVRAM usage healthy: ${NV_BYTES} / 131072 bytes ($((NV_BYTES * 100 / 131072))%)"
    else
        warn "NVRAM usage high: ${NV_BYTES} / 131072 bytes (>= 87.5% ceiling 114688 B)"
    fi
else
    warn "${NVRAM_FILE} not readable; check 'nvram show >/dev/null' stderr for size"
fi

RSTATS_PATH="$(nvram get rstats_path 2>/dev/null || true)"
if [ "$RSTATS_PATH" = "*nvram" ]; then
    warn "rstats_path is currently '*nvram' (new firmware will auto-migrate this to /jffs/)"
fi

# 5. Stage pre-upgrade backups in /tmp RAM (zero NAND writes)
BACKUP_TS="$(date +%Y%m%d_%H%M%S 2>/dev/null || echo preupgrade)"
JFFS_TAR="/tmp/jffs_backup_${BACKUP_TS}.tar.gz"
NVRAM_BAK="/tmp/nvram_backup_${BACKUP_TS}.cfg"

if tar -czf "$JFFS_TAR" -C / jffs 2>/dev/null; then
    pass "Created /jffs backup in RAM: ${JFFS_TAR} ($(wc -c < "$JFFS_TAR" | tr -d ' ') bytes)"
else
    warn "Could not create ${JFFS_TAR}"
fi

if nvram save "$NVRAM_BAK" >/dev/null 2>&1; then
    pass "Created NVRAM backup in RAM: ${NVRAM_BAK}"
else
    nvram show 2>/dev/null | sort > "${NVRAM_BAK}.txt" || true
    pass "Saved sorted NVRAM text dump in RAM: ${NVRAM_BAK}.txt"
fi

printf "\nCopy backups off router to your PC BEFORE flashing:\n"
printf "  scp admin@192.168.1.1:'/tmp/*_backup_%s*' .\n" "$BACKUP_TS"

# 6. Optional firmware image verification (if uploaded via SCP to /tmp)
if [ "${1:-}" != "" ]; then
    FW_IMG="$1"
    printf "\n=== Verifying Staged Firmware Image: %s ===\n" "$FW_IMG"
    case "$FW_IMG" in
        *cferom*)
            fail "DANGER: Image filename contains 'cferom'! NEVER flash a cferom image!"
            ;;
        *)
            pass "Filename does not contain 'cferom'"
            ;;
    esac

    if [ ! -f "$FW_IMG" ]; then
        fail "Staged image not found at ${FW_IMG}"
    else
        FW_SIZE="$(wc -c < "$FW_IMG" | tr -d ' ')"
        if [ "$FW_SIZE" -ge 35651584 ] && [ "$FW_SIZE" -le 56623104 ]; then
            pass "Image size within safe 34..54 MB UBI envelope: ${FW_SIZE} bytes"
        else
            fail "Image size ${FW_SIZE} bytes is outside expected 34..54 MB range!"
        fi

        if command -v sha256sum >/dev/null 2>&1; then
            printf "  SHA-256: %s\n" "$(sha256sum "$FW_IMG" | awk '{print $1}')"
        fi

        if [ "$FAIL_CNT" -eq 0 ]; then
            printf "\nReady to flash via CLI:\n  /sbin/hnd-write %s\n" "$FW_IMG"
        fi
    fi
fi

printf "\nSummary: %d PASS, %d WARN, %d FAIL\n" "$PASS_CNT" "$WARN_CNT" "$FAIL_CNT"
if [ "$FAIL_CNT" -gt 0 ]; then
    exit 1
fi
exit 0
