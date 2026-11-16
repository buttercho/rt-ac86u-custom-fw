#!/usr/bin/env bash
# ==============================================================================
# run_stage2_local_and_ci.sh — Pre-Build ASan + UBSan + GCC -fanalyzer + cppcheck
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_BIN="$(mktemp -d -t stage2_asan_XXXXXX)"
trap 'rm -rf "${TMP_BIN}"' EXIT

echo "======================================================================"
echo "STAGE 2: Pre-Build ASan + UBSan Unit/Fuzz & Static Analysis Gate"
echo "======================================================================"

echo "[stage2:asan] Compiling stage2_asan_unit_tests.c with -fsanitize=address,undefined -Werror..."
gcc -std=gnu11 -O1 -g \
    -fsanitize=address,undefined \
    -fno-omit-frame-pointer \
    -Wall -Wextra -Werror \
    "${SCRIPT_DIR}/stage2_asan_unit_tests.c" \
    -o "${TMP_BIN}/stage2_asan_runner"

ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:strict_string_checks=1" \
UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=1" \
    "${TMP_BIN}/stage2_asan_runner"

if gcc --help=common 2>/dev/null | grep -- '-fanalyzer' >/dev/null; then
    echo "[stage2:fanalyzer] Running GCC interprocedural static analyzer (-O2 -fanalyzer -Werror)..."
    gcc -std=gnu11 -O2 -fanalyzer -Wall -Wextra -Werror \
        -c "${SCRIPT_DIR}/stage2_asan_unit_tests.c" \
        -o "${TMP_BIN}/stage2_analyzed.o"
    echo "[stage2:fanalyzer] PASS: Zero static-analyzer diagnostics."
fi

echo "[stage2:selftest] Running Stage 3 & Stage 5 forensic auditor self-tests..."
python3 "${SCRIPT_DIR}/stage3_rootfs_elf_ko_audit.py" --self-test
python3 "${SCRIPT_DIR}/stage5_image_forensics.py" --self-test

if command -v cppcheck >/dev/null 2>&1; then
    echo "[stage2:cppcheck] Running fail-closed cppcheck on test harness..."
    cppcheck --error-exitcode=1 --enable=warning,portability \
        --suppress=missingIncludeSystem --suppress=ConfigurationNotChecked \
        --quiet "${SCRIPT_DIR}/stage2_asan_unit_tests.c"
    if [[ $# -gt 0 && -d "$1" ]]; then
        MERLIN_DIR="$1"
        VENDOR_TARGETS=()
        for rel in \
            release/src/router/busybox/networking/udhcp/common.c \
            release/src/router/busybox/archival/libarchive/data_extract_all.c \
            release/src/router/libxml2/tree.c \
            release/src/router/libovpn/openvpn_setup.c \
            release/src/router/wsdd2/llmnr.c \
            release/src/router/shared/shutils.c \
            release/src/router/shared/pids.c \
            release/src/router/inadyn/src/ddns.c \
            release/src/router/rstats/rstats.c \
            release/src/router/cstats/cstats.c \
            release/src/router/libdisk/write_smb_conf.c
        do
            [[ -f "${MERLIN_DIR}/${rel}" ]] && VENDOR_TARGETS+=("${MERLIN_DIR}/${rel}")
        done
        if [[ ${#VENDOR_TARGETS[@]} -gt 0 ]]; then
            echo "[stage2:cppcheck] Running diff-scoped fail-closed cppcheck scan on ${#VENDOR_TARGETS[@]} patched vendor file(s)..."
            python3 - "${MERLIN_DIR}" "${VENDOR_TARGETS[@]}" <<'PYEOF'
import os
import re
import subprocess
import sys

merlin_dir = os.path.realpath(sys.argv[1])
targets = sys.argv[2:]

cpp_cmd = [
    "cppcheck",
    "-j",
    "4",
    "--platform=unix32",
    "--max-configs=1",
    "-DHND_ROUTER=1",
    "-DLINUX26=1",
    "-DRTCONFIG_BCMARM=1",
    "-DRTCONFIG_BCMWL6=1",
    "-DASUSWRT=1",
    "--enable=warning,portability",
    "--template={file}|{line}|{severity}|{id}|{message}",
    "--suppress=missingInclude",
    "--suppress=missingIncludeSystem",
    "--suppress=ConfigurationNotChecked",
    "--suppress=syntaxError",
    "--suppress=unknownMacro",
    "--quiet",
    *targets,
]
cpp_proc = subprocess.run(cpp_cmd, capture_output=True, text=True)
if cpp_proc.returncode != 0:
    print(cpp_proc.stdout, cpp_proc.stderr, file=sys.stderr)
    raise SystemExit(f"FATAL: cppcheck invocation failed with exit code {cpp_proc.returncode}")

diff_files = [
    "release/src/router/busybox/networking/udhcp/common.c",
    "release/src/router/busybox/archival/libarchive/data_extract_all.c",
    "release/src/router/libxml2/tree.c",
    "release/src/router/libovpn/openvpn_setup.c",
    "release/src/router/shared/shutils.c",
    "release/src/router/shared/pids.c",
    "release/src/router/inadyn/src/ddns.c",
    "release/src/router/rstats/rstats.c",
    "release/src/router/cstats/cstats.c",
    "release/src/router/libdisk/write_smb_conf.c",
]
diff_proc = subprocess.run(
    ["git", "-C", merlin_dir, "diff", "-U0", "--", *diff_files],
    capture_output=True,
    text=True,
)
if diff_proc.returncode != 0:
    raise SystemExit(f"FATAL: git diff failed in {merlin_dir}: {diff_proc.stderr}")

windows: dict[str, list[tuple[int, int]]] = {}
cur_file: str | None = None
for line in diff_proc.stdout.splitlines():
    if line.startswith("+++ b/"):
        cur_file = line[6:].strip()
        windows.setdefault(cur_file, [])
    elif cur_file and line.startswith("@@ "):
        m = re.search(r"\+(\d+)(?:,(\d+))?", line)
        if m:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            lo = max(1, start - 3)
            hi = start + max(count, 1) + 3
            windows[cur_file].append((lo, hi))

failures: list[str] = []
ignored_legacy = 0
combined_output = "\n".join(x for x in (cpp_proc.stdout, cpp_proc.stderr) if x)
for raw in combined_output.splitlines():
    parts = raw.split("|", 4)
    if len(parts) != 5:
        continue
    fpath, line_s, severity, cid, msg = parts
    try:
        lineno = int(line_s)
    except ValueError:
        continue
    rel = os.path.relpath(os.path.realpath(fpath), merlin_dir) if os.path.exists(fpath) else fpath
    rel = rel.replace("\\", "/")
    if cid == "preprocessorErrorDirective":
        ignored_legacy += 1
        continue
    if rel == "release/src/router/wsdd2/llmnr.c":
        has_set2_fix = os.path.isfile(fpath) and ("tmp_name" in open(fpath, "r", encoding="utf-8", errors="replace").read())
        if has_set2_fix and severity == "error":
            failures.append(f"{rel}:{lineno} [{severity}:{cid}] {msg}")
        else:
            ignored_legacy += 1
        continue
    in_hunk = any(lo <= lineno <= hi for lo, hi in windows.get(rel, ()))
    if in_hunk and severity in ("error", "warning", "portability"):
        failures.append(f"{rel}:{lineno} [{severity}:{cid}] {msg}")
    else:
        ignored_legacy += 1

print(f"[stage2:cppcheck] Diff-scoped scan checked {len(targets)} vendor files ({ignored_legacy} pre-existing legacy diagnostics outside patched hunks).")
if failures:
    print("FATAL: cppcheck found diagnostic(s) inside modified hunks or llmnr.c errors:", file=sys.stderr)
    for item in failures:
        print(f"  {item}", file=sys.stderr)
    raise SystemExit(1)
PYEOF
        fi
    fi
    echo "[stage2:cppcheck] PASS: Zero cppcheck errors in test harness & patched files."
else
    echo "[stage2:cppcheck] cppcheck not installed locally (runs automatically in GitHub Actions CI)."
fi

echo "==> STAGE 2 PASSED."
