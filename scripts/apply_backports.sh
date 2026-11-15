#!/usr/bin/env bash
# ==============================================================================
# apply_backports.sh — Deterministic Dependency Backport & Patch Orchestrator
# Target: ASUS RT-AC86U (BCM4906 / 94908HND) — Asuswrt-Merlin 386.14_2-sec2026
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FW_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PATCH_DIR="${FW_ROOT}/patches"

EXPECTED_BASE_COMMIT="6a5df61aab6f3fa2dffc518994d42e4f2a27fb2b" # 386.14_2
MERLIN_388_COMMIT="5a50083681c069ef68d5768d0202b690bbcf7c09"    # 3004.388.13+

# Cryptographically pinned upstream release tarballs (zero unverified downloads)
ZLIB_VERSION="1.3.2"
ZLIB_URL="https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz"
ZLIB_SHA256="bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16"

EXPAT_VERSION="2.10.0"
EXPAT_URL="https://github.com/libexpat/libexpat/releases/download/R_2_10_0/expat-2.10.0.tar.gz"
EXPAT_SHA256="5466a341f9c692ef7a958a6881311be597f8e1ce345984cf78414f54793dea4c"

SQLITE_AMALGAMATION="3540100"
SQLITE_URL="https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip"
SQLITE_SHA3_256="92281c86e2957f9b9305890f9ac04204caa7b677cc868dc326d942689df28e30"

OPENVPN_BASE_VER="2.6.12"
OPENVPN_BASE_URL="https://github.com/OpenVPN/openvpn/releases/download/v2.6.12/openvpn-2.6.12.tar.gz"
OPENVPN_BASE_SHA256="1c610fddeb686e34f1367c347e027e418e07523a10f4d8ce4a2c2af2f61a1929"

OPENVPN_NEW_VER="2.6.23"
OPENVPN_NEW_URL="https://github.com/OpenVPN/openvpn/releases/download/v2.6.23/openvpn-2.6.23.tar.gz"
OPENVPN_NEW_SHA256="4041c709162bec1325abf5aa8cf27a255cc477c634b15ee310411c701fc40a96"

MODE="full"
MERLIN_DIR=""

usage() {
    cat <<EOF
Usage: $0 [--patches-only | --check-only] <path-to-asuswrt-merlin.ng>

Modes:
  (default)       Full CI mode: verifies 386.14_2 commit, syncs pinned 3004.388
                  drop-in packages, fetches & hash-verifies upstream tarballs,
                  applies surgical C backports, and applies patches/001..005.
  --patches-only  Offline mode: applies patches/001..005 directly without network.
  --check-only    Dry-run mode: verifies patches/001..005 apply cleanly with
                  zero fuzz via 'git apply --check --verbose' (mutates nothing).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --patches-only)
            MODE="patches-only"
            shift
            ;;
        --check-only)
            MODE="check-only"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            MERLIN_DIR="$1"
            shift
            ;;
    esac
done

if [[ -z "${MERLIN_DIR}" || ! -d "${MERLIN_DIR}/.git" ]]; then
    echo "ERROR: Valid path to asuswrt-merlin.ng git checkout required." >&2
    usage >&2
    exit 1
fi

MERLIN_DIR="$(cd "${MERLIN_DIR}" && pwd)"
echo "==> [apply_backports] Target repo: ${MERLIN_DIR} (mode=${MODE})"

HEAD_COMMIT="$(git -C "${MERLIN_DIR}" rev-parse HEAD)"
if [[ "${HEAD_COMMIT}" != "${EXPECTED_BASE_COMMIT}" ]]; then
    echo "ERROR: Expected baseline commit ${EXPECTED_BASE_COMMIT} (386.14_2), got ${HEAD_COMMIT}" >&2
    exit 1
fi
echo "==> [apply_backports] Verified baseline HEAD = ${HEAD_COMMIT} (386.14_2)"

if [[ "${MODE}" == "check-only" ]]; then
    echo "==> [apply_backports] Dry-run checking modular patches (001..005)..."
    # Note: patches 001..005 are sequential; verify them in an isolated temporary index/worktree
    # or sequentially when files don't overlap. Since 002 & 005 both touch shared/defaults.c and
    # 003 & 004 both touch rc/services.c, verify sequential application in a tiny scratch git repo!
    python3 - "${MERLIN_DIR}" "${PATCH_DIR}" <<'PYEOF'
import glob, os, shutil, subprocess, sys, tempfile

merlin_dir, patch_dir = sys.argv[1], sys.argv[2]
patches = sorted(glob.glob(os.path.join(patch_dir, "*.patch")))
if len(patches) < 5:
    raise SystemExit(f"ERROR: Expected >=5 patches in {patch_dir}, found {len(patches)}")

touched = set()
for p in patches:
    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("+++ b/"):
                touched.add(line[6:].strip())

with tempfile.TemporaryDirectory(prefix="stage1_patch_check_") as tmp:
    subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
    for rel in sorted(touched):
        src = os.path.join(merlin_dir, rel)
        if not os.path.isfile(src):
            raise SystemExit(f"ERROR: Missing target file in baseline checkout: {rel}")
        dst = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
    for p in patches:
        print(f"  -> git apply --verbose {os.path.basename(p)}")
        subprocess.run(["git", "apply", "--verbose", p], cwd=tmp, check=True)
print(f"==> [apply_backports] All {len(patches)} sequential patches verified with ZERO fuzz/rejects.")
PYEOF
    exit 0
fi

download_and_verify() {
    local url="$1"
    local dest="$2"
    local algo="$3"
    local expected_hash="$4"

    echo "  -> Downloading $(basename "${dest}")..."
    curl -fsSL --retry 3 --connect-timeout 20 -o "${dest}" "${url}"

    local actual_hash
    if [[ "${algo}" == "sha256" ]]; then
        actual_hash="$(sha256sum "${dest}" | awk '{print $1}')"
    elif [[ "${algo}" == "sha3_256" ]]; then
        actual_hash="$(python3 -c 'import hashlib,sys; print(hashlib.sha3_256(open(sys.argv[1],"rb").read()).hexdigest())' "${dest}")"
    else
        echo "ERROR: Unsupported hash algorithm ${algo}" >&2
        exit 1
    fi

    if [[ "${actual_hash}" != "${expected_hash}" ]]; then
        echo "FATAL: Hash mismatch for $(basename "${dest}")!" >&2
        echo "  Expected (${algo}): ${expected_hash}" >&2
        echo "  Actual   (${algo}): ${actual_hash}" >&2
        exit 1
    fi
    echo "  -> Verified ${algo}: ${actual_hash}"
}

if [[ "${MODE}" == "full" ]]; then
    echo "==> [Step 1/4] Syncing proven Tier-1/Tier-2 packages from Merlin 3004.388 (${MERLIN_388_COMMIT})..."
    if ! git -C "${MERLIN_DIR}" cat-file -e "${MERLIN_388_COMMIT}^{commit}" 2>/dev/null; then
        git -C "${MERLIN_DIR}" fetch --depth=1 origin "${MERLIN_388_COMMIT}"
    fi

    BACKPORT_PATHS=(
        "release/src/router/dnsmasq"
        "release/src/router/nettle"
        "release/src/router/dropbear"
        "release/src/router/miniupnpd"
        "release/src/router/curl"
        "release/src/router/wget"
        "release/src/router/haveged"
        "release/src/router/nano"
        "release/src/router/libcap-ng"
        "release/src/router/wsdd2"
        "release/src/router/wireguard-tools"
        "release/src/router/openssl-1.1"
        "release/src/router/rom/certs/ca-bundle.crt"
    )

    for rel_path in "${BACKPORT_PATHS[@]}"; do
        echo "  -> Syncing ${rel_path} from 3004.388..."
        rm -rf "${MERLIN_DIR}/${rel_path}"
        git -C "${MERLIN_DIR}" checkout "${MERLIN_388_COMMIT}" -- "${rel_path}"
    done

    # Fail-closed sanity assertions on 3004.388 backports
    grep -q '(MAXDNAME \* 2) + 1' "${MERLIN_DIR}/release/src/router/dnsmasq/src/dnsmasq.h" \
        || { echo "FATAL: dnsmasq union bigname overflow fix missing!" >&2; exit 1; }
    grep -q 'mx_value <= 0' "${MERLIN_DIR}/release/src/router/miniupnpd/minissdp.c" \
        || { echo "FATAL: miniupnpd CVE-2026-107159 mx_value guard missing!" >&2; exit 1; }
    if grep -q 'emSign ECC Root CA - G3' "${MERLIN_DIR}/release/src/router/rom/certs/ca-bundle.crt"; then
        echo "FATAL: Distrusted emSign ECC Root CA - G3 still present in ca-bundle.crt!" >&2
        exit 1
    fi

    echo "==> [Step 2/4] Downloading & verifying SONAME-locked upstream release tarballs..."
    TMP_DL="$(mktemp -d -t ac86u_backports_XXXXXX)"
    trap 'rm -rf "${TMP_DL}"' EXIT

    # 2a. zlib 1.3.2 (keeps libz.so.1, fixes CVE-2022-37434, CVE-2023-45853, CVE-2026-27171)
    download_and_verify "${ZLIB_URL}" "${TMP_DL}/zlib.tar.gz" "sha256" "${ZLIB_SHA256}"
    rm -rf "${MERLIN_DIR}/release/src/router/zlib"
    mkdir -p "${MERLIN_DIR}/release/src/router/zlib"
    tar -xzf "${TMP_DL}/zlib.tar.gz" --strip-components=1 -C "${MERLIN_DIR}/release/src/router/zlib"

    # 2b. expat 2.10.0 (replaces expat-2.0.1 in-place, keeps libexpat.so.1)
    download_and_verify "${EXPAT_URL}" "${TMP_DL}/expat.tar.gz" "sha256" "${EXPAT_SHA256}"
    rm -rf "${MERLIN_DIR}/release/src/router/expat-2.0.1"
    mkdir -p "${MERLIN_DIR}/release/src/router/expat-2.0.1"
    tar -xzf "${TMP_DL}/expat.tar.gz" --strip-components=1 -C "${MERLIN_DIR}/release/src/router/expat-2.0.1"

    # 2c. SQLite 3.54.1 amalgamation (keeps Merlin's configure.ac/Makefile.am & libsqlite3.so.0)
    download_and_verify "${SQLITE_URL}" "${TMP_DL}/sqlite.zip" "sha3_256" "${SQLITE_SHA3_256}"
    python3 -c '
import shutil, sys, zipfile
zip_path, dst_dir = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_path) as zf:
    for member in zf.namelist():
        base = member.rsplit("/", 1)[-1]
        if base in ("sqlite3.c", "sqlite3.h", "sqlite3ext.h", "shell.c"):
            with zf.open(member) as src, open(f"{dst_dir}/{base}", "wb") as dst:
                shutil.copyfileobj(src, dst)
' "${TMP_DL}/sqlite.zip" "${MERLIN_DIR}/release/src/router/sqlite"
    grep -q '3.54.1' "${MERLIN_DIR}/release/src/router/sqlite/sqlite3.h" \
        || { echo "FATAL: SQLite 3.54.1 amalgamation replacement failed!" >&2; exit 1; }

    # 2d. OpenVPN 2.6.23 while preserving 100% of Merlin's #ifdef ASUSWRT custom patches
    download_and_verify "${OPENVPN_BASE_URL}" "${TMP_DL}/openvpn-base.tar.gz" "sha256" "${OPENVPN_BASE_SHA256}"
    download_and_verify "${OPENVPN_NEW_URL}" "${TMP_DL}/openvpn-new.tar.gz" "sha256" "${OPENVPN_NEW_SHA256}"
    mkdir -p "${TMP_DL}/ovpn-stock-base" "${TMP_DL}/ovpn-new"
    tar -xzf "${TMP_DL}/openvpn-base.tar.gz" --strip-components=1 -C "${TMP_DL}/ovpn-stock-base"
    tar -xzf "${TMP_DL}/openvpn-new.tar.gz" --strip-components=1 -C "${TMP_DL}/ovpn-new"

    # Extract exact diff of Merlin customizations inside src/ against stock 2.6.12
    diff -uNr "${TMP_DL}/ovpn-stock-base/src" "${MERLIN_DIR}/release/src/router/openvpn/src" \
        > "${TMP_DL}/merlin-openvpn-src.patch" || true
    if [[ -s "${TMP_DL}/merlin-openvpn-src.patch" ]]; then
        echo "  -> Re-applying Merlin custom OpenVPN src/ patch onto OpenVPN ${OPENVPN_NEW_VER}..."
        patch -p1 --fuzz=0 -d "${TMP_DL}/ovpn-new/src" < <(
            sed -e "s|^--- ${TMP_DL}/ovpn-stock-base/src/|--- a/|" \
                -e "s|^+++ ${MERLIN_DIR}/release/src/router/openvpn/src/|+++ b/|" \
                "${TMP_DL}/merlin-openvpn-src.patch"
        )
    fi
    rm -rf "${MERLIN_DIR}/release/src/router/openvpn"
    mv "${TMP_DL}/ovpn-new" "${MERLIN_DIR}/release/src/router/openvpn"
    grep -rq 'ASUSWRT' "${MERLIN_DIR}/release/src/router/openvpn/src" \
        || { echo "FATAL: Merlin #ifdef ASUSWRT hooks missing after OpenVPN upgrade!" >&2; exit 1; }

    echo "==> [Step 3/4] Applying surgical C security fixes (BusyBox udhcpc/tar, libxml2, libovpn)..."
    python3 - "${MERLIN_DIR}" <<'PYEOF'
import os, sys

merlin = sys.argv[1]

def patch_exact(rel_path: str, old: str, new: str, label: str) -> None:
    full = os.path.join(merlin, rel_path)
    with open(full, "r", encoding="utf-8", errors="surrogateescape") as fh:
        data = fh.read()
    cnt = data.count(old)
    if cnt != 1:
        raise SystemExit(f"FATAL [{label}]: expected exact 1 match in {rel_path}, found {cnt}")
    data = data.replace(old, new, 1)
    with open(full, "w", encoding="utf-8", errors="surrogateescape") as fh:
        fh.write(data)
    print(f"  -> Patched {rel_path} ({label})")

# 1. BusyBox 1.25.1 udhcpc WAN DHCP integer underflow / OOB read (CVE-2026-88833)
patch_exact(
    "release/src/router/busybox/networking/udhcp/common.c",
    """\t\tlen = 2 + optionptr[OPT_LEN];
\t\trem -= len;
\t\tif (rem < 0)
\t\t\tgoto complain; /* complain and return NULL */""",
    """\t\tif (rem <= OPT_LEN)
\t\t\tgoto complain; /* CVE-2026-88833: prevent 1-byte OOB read on OPT_LEN */
\t\tlen = 2 + optionptr[OPT_LEN];
\t\trem -= len;
\t\tif (rem < 0)
\t\t\tgoto complain; /* complain and return NULL */""",
    "CVE-2026-88833 udhcp_get_option rem<=OPT_LEN"
)

patch_exact(
    "release/src/router/busybox/networking/udhcp/common.c",
    """\t\tif (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD) {
\t\t\toverload |= optionptr[OPT_DATA];
\t\t\t/* fall through */
\t\t}""",
    """\t\tif (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD) {
\t\t\tif (optionptr[OPT_LEN] >= 1)
\t\t\t\toverload |= optionptr[OPT_DATA];
\t\t\t/* fall through */
\t\t}""",
    "CVE-2026-88833 udhcp_get_option OVERLOAD len>=1"
)

# 2. BusyBox 1.25.1 tar symlink traversal & NULL link_target guard (CVE-2026-108119)
patch_exact(
    "release/src/router/busybox/archival/libarchive/data_extract_all.c",
    """\tif (archive_handle->ah_flags & ARCHIVE_CREATE_LEADING_DIRS) {
\t\tchar *slash = strrchr(dst_name, '/');
\t\tif (slash) {
\t\t\t*slash = '\\0';
\t\t\tbb_make_directory(dst_name, -1, FILEUTILS_RECUR);
\t\t\t*slash = '/';
\t\t}
\t}""",
    """\t/* CVE-2026-108119: refuse to traverse intermediate symlink components in dst_name */
\t{
\t\tchar *p = dst_name;
\t\twhile ((p = strchr(p, '/')) != NULL) {
\t\t\tif (p > dst_name) {
\t\t\t\tstruct stat check_st;
\t\t\t\t*p = '\\0';
\t\t\t\tif (lstat(dst_name, &check_st) == 0 && S_ISLNK(check_st.st_mode)) {
\t\t\t\t\t*p = '/';
\t\t\t\t\tbb_error_msg("refusing to extract through symlink %s", dst_name);
\t\t\t\t\tdata_skip(archive_handle);
\t\t\t\t\tgoto ret;
\t\t\t\t}
\t\t\t\t*p = '/';
\t\t\t}
\t\t\tp++;
\t\t}
\t}
\tif (archive_handle->ah_flags & ARCHIVE_CREATE_LEADING_DIRS) {
\t\tchar *slash = strrchr(dst_name, '/');
\t\tif (slash) {
\t\t\t*slash = '\\0';
\t\t\tbb_make_directory(dst_name, -1, FILEUTILS_RECUR);
\t\t\t*slash = '/';
\t\t}
\t}""",
    "CVE-2026-108119 tar intermediate symlink traversal guard"
)

patch_exact(
    "release/src/router/busybox/archival/libarchive/data_extract_all.c",
    """\tcase S_IFLNK:
\t\t/* Symlink */
//TODO: what if file_header->link_target == NULL (say, corrupted tarball?)
\t\tres = symlink(file_header->link_target, dst_name);""",
    """\tcase S_IFLNK:
\t\t/* Symlink (with NULL & CVE-2026-108119 unsafe target rejection) */
\t\tif (!file_header->link_target
\t\t || (!(archive_handle->ah_flags & ARCHIVE_EXTRACT_UNCONDITIONAL)
\t\t     && (file_header->link_target[0] == '/'
\t\t         || strcmp(file_header->link_target, "..") == 0
\t\t         || strncmp(file_header->link_target, "../", 3) == 0
\t\t         || strstr(file_header->link_target, "/../") != NULL))
\t\t) {
\t\t\tbb_error_msg("skipping unsafe symlink %s", dst_name);
\t\t\tbreak;
\t\t}
\t\tres = symlink(file_header->link_target, dst_name);""",
    "CVE-2026-108119 tar S_IFLNK target guard"
)

# 3. libxml2 2.10.4 xmlBuildQName 32-bit integer/stack overflow (CVE-2025-6021, keeps libxml2.so.2)
patch_exact(
    "release/src/router/libxml2/tree.c",
    """xmlBuildQName(const xmlChar *ncname, const xmlChar *prefix,
\t      xmlChar *memory, int len) {
    int lenn, lenp;
    xmlChar *ret;

    if (ncname == NULL) return(NULL);
    if (prefix == NULL) return((xmlChar *) ncname);

    lenn = strlen((char *) ncname);
    lenp = strlen((char *) prefix);

    if ((memory == NULL) || (len < lenn + lenp + 2)) {""",
    """xmlBuildQName(const xmlChar *ncname, const xmlChar *prefix,
\t      xmlChar *memory, int len) {
    size_t lenn, lenp;
    xmlChar *ret;

    if ((ncname == NULL) || (len < 0)) return(NULL);
    if (prefix == NULL) return((xmlChar *) ncname);

    lenn = strlen((char *) ncname);
    lenp = strlen((char *) prefix);
    if (lenn >= ((size_t)-1) - lenp - 2)
\treturn(NULL);

    if ((memory == NULL) || ((size_t) len < lenn + lenp + 2)) {""",
    "CVE-2025-6021 libxml2 xmlBuildQName size_t overflow fix"
)

# 4. libovpn >=2048-bit DH enforcement + fclose(NULL) fix
patch_exact(
    "release/src/router/libovpn/openvpn_setup.c",
    """\t\t\t\tif ((len != 0) && (len < 1024))
\t\t\t\t\tlogmessage("openvpn","WARNING: DH for server %d is too weak (%d bit, must be at least 1024 bit). Using a pre-generated 2048-bit PEM.", unit, len);
\t\t\t}
\t\t\tfclose(fp);
\t\t}
\t}

\tif (len < 1024) {\t// Provide a 2048-bit PEM, from RFC 3526.""",
    """\t\t\t\tif ((len != 0) && (len < 2048))
\t\t\t\t\tlogmessage("openvpn","WARNING: DH for server %d is too weak (%d bit, must be at least 2048 bit). Using a pre-generated 2048-bit PEM.", unit, len);
\t\t\t\tfclose(fp);
\t\t\t}
\t\t}
\t}

\tif (len < 2048) {\t// Enforce >= 2048-bit DH PEM for OpenVPN 2.6.23 / OpenSSL SECLEVEL""",
    "libovpn >=2048-bit DH & fclose(fp) NULL guard"
)
PYEOF
fi

echo "==> [Step 4/4] Applying modular RT-AC86U patches (001..005)..."
for patch_file in "${PATCH_DIR}"/00*.patch; do
    echo "  -> Applying $(basename "${patch_file}")..."
    git -C "${MERLIN_DIR}" apply --verbose "${patch_file}"
done

echo "==> [apply_backports] SUCCESS: Source tree is patched and ready for Stage 1/2 gates & build."
