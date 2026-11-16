#!/usr/bin/env bash
# ==============================================================================
# stage4_qemu_smoke.sh — Post-Build QEMU Cortex-A53 Emulated Daemon Smoke Suite
#
# Executes the ACTUAL cross-compiled RT-AC86U binaries inside `fs.install` under
# `qemu-arm-static -cpu cortex-a53` (32-bit userspace) and `qemu-aarch64-static
# -cpu cortex-a53` (64-bit ebtables), plus Node.js syntax checks on modified .asp!
# ==============================================================================
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <path-to-fs.install> <path-to-asuswrt-merlin.ng>" >&2
    exit 1
fi

ROOTFS="$(cd "$1" && pwd)"
MERLIN_DIR="$(cd "$2" && pwd)"

echo "======================================================================"
echo "STAGE 4: Post-Build QEMU Cortex-A53 Emulated Runtime Smoke Suite"
echo "======================================================================"

QEMU_ARM="$(command -v qemu-arm-static || command -v qemu-arm || true)"
QEMU_AARCH64="$(command -v qemu-aarch64-static || command -v qemu-aarch64 || true)"

if [[ -z "${QEMU_ARM}" || -z "${QEMU_AARCH64}" ]]; then
    echo "FATAL: qemu-arm-static and qemu-aarch64-static are required for Stage 4!" >&2
    exit 1
fi

LD_PATHS="${ROOTFS}/lib:${ROOTFS}/usr/lib:${ROOTFS}/lib/public:${ROOTFS}/lib/private"
LD_PATHS_64="${ROOTFS}/lib/aarch64:${ROOTFS}/usr/lib/aarch64:${ROOTFS}/usr/lib:${ROOTFS}/usr/lib/ebtables:${ROOTFS}/lib"

QEMU_ARM_CPU_ARGS=()
ARM_CPUS="$("${QEMU_ARM}" -cpu help 2>/dev/null || true)"
for cand in cortex-a53 max any cortex-a15 cortex-a7; do
    if echo "${ARM_CPUS}" | grep -qw "${cand}"; then
        QEMU_ARM_CPU_ARGS=(-cpu "${cand}")
        break
    fi
done

QEMU_AARCH64_CPU_ARGS=()
AARCH64_CPUS="$("${QEMU_AARCH64}" -cpu help 2>/dev/null || true)"
for cand in cortex-a53 max any; do
    if echo "${AARCH64_CPUS}" | grep -qw "${cand}"; then
        QEMU_AARCH64_CPU_ARGS=(-cpu "${cand}")
        break
    fi
done

run_arm32() {
    "${QEMU_ARM}" "${QEMU_ARM_CPU_ARGS[@]}" -L "${ROOTFS}" -E "LD_LIBRARY_PATH=${LD_PATHS}" -E "OPENSSL_CONF=/dev/null" "$@"
}

run_aarch64() {
    "${QEMU_AARCH64}" "${QEMU_AARCH64_CPU_ARGS[@]}" -L "${ROOTFS}" -E "LD_LIBRARY_PATH=${LD_PATHS_64}" -E "OPENSSL_CONF=/dev/null" "$@"
}

TMP_WORK="$(mktemp -d -t stage4_qemu_XXXXXX)"
trap 'rm -rf "${TMP_WORK}"' EXIT

# 1. OpenSSL + ARMv8 Crypto Dispatch + CA Bundle Validation
echo "[stage4:crypto] Testing OpenSSL version & AES-GCM/SHA-256 on emulated Cortex-A53..."
OPENSSL_OUT="$(run_arm32 "${ROOTFS}/usr/sbin/openssl" version -a)"
echo "${OPENSSL_OUT}"
run_arm32 "${ROOTFS}/usr/sbin/openssl" speed -elapsed -seconds 1 aes-128-gcm sha256 >/dev/null

CA_BUNDLE=""
for cand in \
    "${ROOTFS}/rom/etc/ssl/certs/ca-certificates.crt" \
    "${ROOTFS}/etc/ssl/certs/ca-certificates.crt" \
    "${ROOTFS}/rom/certs/ca-bundle.crt"
do
    if [[ -s "${cand}" ]] && grep -q "BEGIN CERTIFICATE" "${cand}"; then
        CA_BUNDLE="${cand}"
        break
    fi
done
test -n "${CA_BUNDLE}" || { echo "FATAL: Missing non-empty installed CA certificate bundle in ${ROOTFS}" >&2; exit 1; }
SRC_CA="${MERLIN_DIR}/release/src/router/rom/certs/ca-bundle.crt"
test -s "${SRC_CA}" || { echo "FATAL: Missing ${SRC_CA}" >&2; exit 1; }
if grep -q "emSign ECC Root CA - G3" "${SRC_CA}" || grep -q "emSign ECC Root CA - G3" "${CA_BUNDLE}"; then
    echo "FATAL: Distrusted emSign ECC Root CA - G3 present in built ca-bundle.crt!" >&2
    exit 1
fi

# 2. dnsmasq 2.93 + IANA 2024 DNSSEC Root KSK (38696) Live Syntax Test
echo "[stage4:dnsmasq] Testing dnsmasq 2.93 --version & live DNSSEC KSK-2024 (38696) config..."
DNSMASQ_VER="$(run_arm32 "${ROOTFS}/usr/sbin/dnsmasq" --version | head -n 2)"
echo "${DNSMASQ_VER}"
echo "${DNSMASQ_VER}" | grep -q "2.93" || { echo "FATAL: Expected dnsmasq 2.93!" >&2; exit 1; }
echo "${DNSMASQ_VER}" | grep -qi "DNSSEC" || { echo "FATAL: dnsmasq missing DNSSEC compile support!" >&2; exit 1; }

cat > "${TMP_WORK}/trust-anchors.conf" <<'EOF'
trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
EOF

cat > "${TMP_WORK}/dnsmasq.conf" <<EOF
pid-file=${TMP_WORK}/dnsmasq.pid
no-resolv
server=1.1.1.1
cache-size=4096
neg-ttl=60
min-cache-ttl=60
edns-packet-max=1232
dnssec
conf-file=${TMP_WORK}/trust-anchors.conf
EOF

DNSMASQ_TEST_OUT="$(run_arm32 "${ROOTFS}/usr/sbin/dnsmasq" --test -C "${TMP_WORK}/dnsmasq.conf" 2>&1)"
echo "${DNSMASQ_TEST_OUT}"
echo "${DNSMASQ_TEST_OUT}" | grep -qi "syntax check OK" \
    || { echo "FATAL: dnsmasq --test failed on KSK-2024 config!" >&2; exit 1; }

# 3. Dropbear 2026.94 + Live Ed25519 Key Generation
echo "[stage4:dropbear] Testing Dropbear 2026.94 & Ed25519 hostkey generation..."
DB_VER="$(run_arm32 "${ROOTFS}/usr/bin/dropbearmulti" dropbear -V 2>&1 || run_arm32 "${ROOTFS}/usr/sbin/dropbear" -V 2>&1)"
echo "${DB_VER}"
echo "${DB_VER}" | grep -q "2026.94" || { echo "FATAL: Expected Dropbear 2026.94!" >&2; exit 1; }
if [[ -x "${ROOTFS}/usr/bin/dropbearkey" || -L "${ROOTFS}/usr/bin/dropbearkey" ]]; then
    run_arm32 "${ROOTFS}/usr/bin/dropbearkey" -t ed25519 -f "${TMP_WORK}/ed25519_host_key" >/dev/null
    test -s "${TMP_WORK}/ed25519_host_key"
fi

# 4. OpenVPN 2.6.23 + Static Key Gen
echo "[stage4:openvpn] Testing OpenVPN 2.6.23 --version & --genkey..."
OVPN_VER="$(run_arm32 "${ROOTFS}/usr/sbin/openvpn" --version | head -n 3)"
echo "${OVPN_VER}"
echo "${OVPN_VER}" | grep -q "2.6.23" || { echo "FATAL: Expected OpenVPN 2.6.23!" >&2; exit 1; }
run_arm32 "${ROOTFS}/usr/sbin/openvpn" --genkey secret "${TMP_WORK}/ovpn.key"
test -s "${TMP_WORK}/ovpn.key"

# 5. curl 8.17.0, wget 1.25.0, sqlite 3.54.1, miniupnpd 2.3.11, busybox, 64-bit ebtables
echo "[stage4:daemons] Testing curl, wget, sqlite3, miniupnpd, busybox, and 64-bit ebtables..."
CURL_VER="$(run_arm32 "${ROOTFS}/usr/sbin/curl" --version | head -n 1)"
echo "${CURL_VER}"
echo "${CURL_VER}" | grep -q "8.17.0" || { echo "FATAL: Expected curl 8.17.0!" >&2; exit 1; }

WGET_VER="$(run_arm32 "${ROOTFS}/usr/sbin/wget" --version | head -n 1)"
echo "${WGET_VER}"
echo "${WGET_VER}" | grep -q "1.25" || { echo "FATAL: Expected GNU Wget 1.25.0!" >&2; exit 1; }

if [[ -x "${ROOTFS}/usr/sbin/sqlite3" || -x "${ROOTFS}/usr/bin/sqlite3" ]]; then
    SQLITE_BIN="${ROOTFS}/usr/sbin/sqlite3"
    [[ -x "${SQLITE_BIN}" ]] || SQLITE_BIN="${ROOTFS}/usr/bin/sqlite3"
    SQL_VER="$(run_arm32 "${SQLITE_BIN}" :memory: 'SELECT sqlite_version();')"
    echo "sqlite3 runtime version: ${SQL_VER}"
    [[ "${SQL_VER}" == "3.54.1" ]] || { echo "FATAL: Expected SQLite 3.54.1, got ${SQL_VER}" >&2; exit 1; }
fi

UPNP_HELP="$(run_arm32 "${ROOTFS}/usr/sbin/miniupnpd" -h 2>&1 || true)"
echo "${UPNP_HELP}" | head -n 3

BB_OUT="$(run_arm32 "${ROOTFS}/bin/busybox" ash -c 'echo CORTEX_A53_BUSYBOX_OK')"
[[ "${BB_OUT}" == "CORTEX_A53_BUSYBOX_OK" ]] || { echo "FATAL: BusyBox ash smoke test failed!" >&2; exit 1; }

if [[ -x "${ROOTFS}/usr/sbin/ebtables" ]]; then
    EBT_VER="$(run_aarch64 "${ROOTFS}/usr/sbin/ebtables" -V)"
    echo "64-bit ebtables: ${EBT_VER}"
fi

# 6. WebUI .asp XSS & NVRAM Option Regression + Node.js Syntax Gate
echo "[stage4:webui] Auditing patched WebUI .asp templates..."
SURVEY_ASP="${ROOTFS}/www/Advanced_Wireless_Survey.asp"
OTHER_ASP="${ROOTFS}/www/Tools_OtherSettings.asp"

grep -q 'htmlEnDeCode.htmlEncode(decodeURIComponent(' "${SURVEY_ASP}" \
    || { echo "FATAL: Missing htmlEncode XSS fix in Advanced_Wireless_Survey.asp!" >&2; exit 1; }
if grep -q 'value="\*nvram"' "${OTHER_ASP}"; then
    echo "FATAL: Dangerous rstats *nvram option still present in Tools_OtherSettings.asp!" >&2
    exit 1
fi

if command -v node >/dev/null 2>&1; then
    python3 - "${SURVEY_ASP}" "${OTHER_ASP}" "${TMP_WORK}" <<'PYEOF'
import re, subprocess, sys

script_re = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)
asp_tag_re = re.compile(r"<%.*?%>", re.S)

tmp_dir = sys.argv[-1]
for idx, asp_path in enumerate(sys.argv[1:-1]):
    text = open(asp_path, "r", encoding="utf-8", errors="replace").read()
    for b_idx, block in enumerate(script_re.findall(text)):
        if not block.strip():
            continue
        # Replace server-side <% ... %> EJ tags with neutral JS string/0 literals for syntax validation
        cleaned = asp_tag_re.sub("0", block)
        js_file = f"{tmp_dir}/asp_{idx}_{b_idx}.js"
        with open(js_file, "w", encoding="utf-8") as fh:
            fh.write(cleaned)
        subprocess.run(["node", "--check", js_file], check=True)
print("[stage4:webui] Node.js syntax check passed on all extracted <script> blocks.")
PYEOF
fi

echo "==> STAGE 4 PASSED."
