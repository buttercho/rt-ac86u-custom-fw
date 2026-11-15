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

if gcc --help=optimizers 2>/dev/null | grep -q -- '-fanalyzer'; then
    echo "[stage2:fanalyzer] Running GCC interprocedural static analyzer (-O2 -fanalyzer -Werror)..."
    gcc -std=gnu11 -O2 -fanalyzer -Wall -Wextra -Werror \
        -c "${SCRIPT_DIR}/stage2_asan_unit_tests.c" \
        -o "${TMP_BIN}/stage2_analyzed.o"
    echo "[stage2:fanalyzer] PASS: Zero static-analyzer diagnostics."
fi

if command -v cppcheck >/dev/null 2>&1; then
    echo "[stage2:cppcheck] Running fail-closed cppcheck on test harness..."
    cppcheck --error-exitcode=1 --enable=warning,portability \
        --suppress=missingIncludeSystem --suppress=ConfigurationNotChecked \
        --quiet "${SCRIPT_DIR}/stage2_asan_unit_tests.c"
    if [[ $# -gt 0 && -d "$1" ]]; then
        MERLIN_DIR="$1"
        VENDOR_TARGETS=()
        for rel in \
            release/src/router/shared/shutils.c \
            release/src/router/shared/misc.c \
            release/src/router/inadyn/src/ddns.c \
            release/src/router/rstats/rstats.c
        do
            [[ -f "${MERLIN_DIR}/${rel}" ]] && VENDOR_TARGETS+=("${MERLIN_DIR}/${rel}")
        done
        if [[ ${#VENDOR_TARGETS[@]} -gt 0 ]]; then
            echo "[stage2:cppcheck] Running advisory cppcheck scan on patched vendor files..."
            cppcheck --enable=warning,portability \
                --suppress=missingIncludeSystem --suppress=ConfigurationNotChecked \
                --suppress=syntaxError --suppress=unknownMacro \
                --quiet "${VENDOR_TARGETS[@]}" || true
        fi
    fi
    echo "[stage2:cppcheck] PASS: Zero cppcheck errors in test harness."
else
    echo "[stage2:cppcheck] cppcheck not installed locally (runs automatically in GitHub Actions CI)."
fi

echo "==> STAGE 2 PASSED."
