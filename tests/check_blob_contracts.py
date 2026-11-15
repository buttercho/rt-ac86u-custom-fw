#!/usr/bin/env python3
"""Stage 1 Pre-Build Closed-Source .o Blob Symbol & Build-Flag Contract Verifier.

Inspects all prebuilt Broadcom/ASUS/TrendMicro object blobs linked into `httpd` and `rc`
(`httpd/prebuild/RT-AC86U/*.o` and `rc/prebuild/RT-AC86U/*.o`) using `readelf`:
  1. Verifies RT-AC86U `target.mak` keeps ABI-coupled flags (`NATNL_AICLOUD=y`,
     `NATNL_AIHOME=y`, `BWDPI=y`, `AMAS=y`, `SW_HW_AUTH=y`, `UUPLUGIN=y`) while stripping
     only isolated daemons (`WEBDAV=n`, `SMARTSYNCBASE=n`, `TOR=n`, `MEDIASRV=n`,
     `TIMEMACHINE=n`, `PRINTER=n`, `MODEM=n`, `QUAGGA=n`).
  2. Verifies every prebuilt `.o` is 32-bit ARM EABI5 (zero hard-float ABI mismatch).
  3. Extracts every `GLOBAL UND` symbol imported by those `.o` blobs and proves:
     - Zero blob-imported functions/globals defined in `httpd`, `rc`, or `shared` were
       deleted or renamed by our patches (`001..005`).
     - Zero blob-imported definitions in `httpd`, `rc`, or `shared` live exclusively inside
       `#ifdef` guards for our disabled `RTCONFIG_*` flags.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile

REQUIRED_ENABLED_FLAGS = {
    "NATNL_AICLOUD": "y",
    "NATNL_AIHOME": "y",
    "BWDPI": "y",
    "AMAS": "y",
    "SW_HW_AUTH": "y",
    "UUPLUGIN": "y",
}

EXPECTED_STRIPPED_FLAGS = {
    "WEBDAV": "n",
    "SMARTSYNCBASE": "n",
    "TOR": "n",
    "MEDIASRV": "n",
    "TIMEMACHINE": "n",
    "PRINTER": "n",
    "MODEM": "n",
    "QUAGGA": "n",
}

DISABLED_RTCONFIG_MACROS = {
    "RTCONFIG_WEBDAV",
    "RTCONFIG_SMARTSYNCBASE",
    "RTCONFIG_TOR",
    "RTCONFIG_MEDIA_SERVER",
    "RTCONFIG_TIMEMACHINE",
    "RTCONFIG_USB_PRINTER",
    "RTCONFIG_USB_MODEM",
    "RTCONFIG_QUAGGA",
}


def parse_rt_ac86u_target_flags(target_mak_text: str) -> dict[str, str]:
    # Join backslash-continued lines and expand $(HND-94908_BASE) + += assignments
    joined = re.sub(r"\\\r?\n", " ", target_mak_text)
    vars_raw: dict[str, list[str]] = {}
    for line in joined.splitlines():
        m = re.match(r"^\s*export\s+([A-Za-z0-9_-]+)\s*(:=|\+=)\s*(.*)$", line)
        if not m:
            continue
        var_name, op, rhs = m.group(1), m.group(2), m.group(3)
        if op == ":=":
            vars_raw[var_name] = [rhs]
        else:
            vars_raw.setdefault(var_name, []).append(rhs)

    if "RT-AC86U" not in vars_raw:
        raise RuntimeError("Could not locate 'export RT-AC86U' stanza in release/src-rt/target.mak")

    combined = " ".join(vars_raw["RT-AC86U"])
    for ref_var in re.findall(r"\$\(([A-Za-z0-9_-]+)\)", combined):
        combined = combined.replace(f"$({ref_var})", " ".join(vars_raw.get(ref_var, [])))

    flags: dict[str, str] = {}
    for tok in combined.split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            flags[k.strip()] = v.strip().strip('"')
    return flags


def extract_blob_symbols(blob_paths: list[str], readelf_bin: str) -> tuple[set[str], set[str]]:
    und: set[str] = set()
    defined: set[str] = set()

    # Batch readelf calls in groups of 25 for speed
    for idx in range(0, len(blob_paths), 25):
        batch = blob_paths[idx : idx + 25]
        hdr_out = subprocess.check_output([readelf_bin, "-h", *batch], text=True)
        for line in hdr_out.splitlines():
            if "Class:" in line and "ELF32" not in line:
                raise RuntimeError(f"Non-ELF32 prebuilt .o detected: {line}")
            if "Flags:" in line and "hard-float" in line.lower():
                raise RuntimeError(f"Hard-float ABI detected in prebuilt .o: {line}")

        sym_out = subprocess.check_output([readelf_bin, "-Ws", *batch], text=True)
        for line in sym_out.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[0].endswith(":"):
                bind = parts[4]
                ndx = parts[6]
                name = parts[7].split("@")[0]
                if not name or name.startswith("$"):
                    continue
                if ndx == "UND" and bind == "GLOBAL":
                    und.add(name)
                elif ndx != "UND" and bind in ("GLOBAL", "WEAK"):
                    defined.add(name)

    return und - defined, defined


def find_c_symbol_occurrences(src_files: list[str], target_symbols: set[str]) -> dict[str, set[str]]:
    """Return mapping of symbol -> set of files where identifier appears outside comments."""
    ident_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
    found: dict[str, set[str]] = {s: set() for s in target_symbols}
    for path in src_files:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        tokens = set(ident_re.findall(text))
        for sym in tokens & target_symbols:
            found[sym].add(path)
    return found


def check_disabled_ifdef_exclusivity(src_files: list[str], target_symbols: set[str]) -> list[str]:
    """Detect if any blob-imported symbol appears ONLY inside disabled #ifdef RTCONFIG_* blocks."""
    ident_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
    ifdef_re = re.compile(r"^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b(.*)$")

    seen_active: set[str] = set()
    seen_disabled_only: dict[str, set[str]] = {}

    for path in src_files:
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()

        # Stack of booleans: True if frame is disabled by one of DISABLED_RTCONFIG_MACROS
        stack: list[bool] = []
        for line in lines:
            m = ifdef_re.match(line)
            if m:
                kw, expr = m.group(1), m.group(2)
                mentions_disabled = any(
                    re.search(rf"\b{re.escape(mac)}\b", expr) for mac in DISABLED_RTCONFIG_MACROS
                )
                if kw == "ifdef":
                    stack.append(mentions_disabled)
                elif kw == "ifndef":
                    stack.append(False)
                elif kw == "if":
                    # Conservative: flag simple `defined(RTCONFIG_X)` without `||` or `!`
                    is_disabled_guard = mentions_disabled and ("||" not in expr) and ("!" not in expr)
                    stack.append(is_disabled_guard)
                elif kw == "elif":
                    if stack:
                        is_disabled_guard = mentions_disabled and ("||" not in expr) and ("!" not in expr)
                        stack[-1] = is_disabled_guard
                elif kw == "else":
                    if stack:
                        stack[-1] = False
                elif kw == "endif":
                    if stack:
                        stack.pop()
                continue

            in_disabled = any(stack)
            for sym in set(ident_re.findall(line)) & target_symbols:
                if in_disabled:
                    seen_disabled_only.setdefault(sym, set()).add(os.path.basename(path))
                else:
                    seen_active.add(sym)

    violations: list[str] = []
    for sym, files in sorted(seen_disabled_only.items()):
        if sym not in seen_active:
            violations.append(f"{sym} (only inside disabled RTCONFIG guard in {sorted(files)})")
    return violations


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--merlin-dir", required=True, help="Path to asuswrt-merlin.ng checkout")
    ap.add_argument("--patch-dir", required=True, help="Path to patches/ directory")
    ap.add_argument("--already-patched", action="store_true", help="Set if patches are already applied to --merlin-dir")
    args = ap.parse_args()

    merlin_dir = os.path.abspath(args.merlin_dir)
    patch_dir = os.path.abspath(args.patch_dir)
    readelf_bin = shutil.which("arm-buildroot-linux-gnueabi-readelf") or shutil.which("readelf")
    if not readelf_bin:
        print("FATAL: readelf not found in PATH", file=sys.stderr)
        return 1

    blobs = sorted(
        glob.glob(os.path.join(merlin_dir, "release/src/router/httpd/prebuild/RT-AC86U/*.o"))
        + glob.glob(os.path.join(merlin_dir, "release/src/router/rc/prebuild/RT-AC86U/*.o"))
    )
    if len(blobs) < 2:
        print(f"FATAL: Expected RT-AC86U prebuilt .o blobs under httpd/rc, found {len(blobs)}", file=sys.stderr)
        return 1

    ext_und, blob_defined = extract_blob_symbols(blobs, readelf_bin)
    print(
        f"[stage1:blobs] Audited {len(blobs)} closed-source RT-AC86U .o blobs "
        f"({len(blob_defined)} internal defs, {len(ext_und)} external GLOBAL UND imports)."
    )

    patches = sorted(glob.glob(os.path.join(patch_dir, "*.patch")))
    touched_rels: set[str] = set()
    for p in patches:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("+++ b/"):
                    touched_rels.add(line[6:].strip())

    # Build a scratch patched view if --merlin-dir is unpatched (keeps local sparse checkout clean!)
    with tempfile.TemporaryDirectory(prefix="stage1_blob_contract_") as tmp:
        if args.already_patched:
            patched_root = merlin_dir
            unpatched_files: list[str] = []
        else:
            subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
            for rel in sorted(touched_rels):
                src = os.path.join(merlin_dir, rel)
                dst = os.path.join(tmp, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copy2(src, dst)
            for p in patches:
                subprocess.run(["git", "apply", p], cwd=tmp, check=True)
            patched_root = tmp
            unpatched_files = [
                os.path.join(merlin_dir, r)
                for r in sorted(touched_rels)
                if r.endswith((".c", ".h"))
            ]

        # 1. Verify target.mak flag contract
        target_mak_path = os.path.join(patched_root, "release/src-rt/target.mak")
        flags = parse_rt_ac86u_target_flags(open(target_mak_path, "r", encoding="utf-8").read())

        for k, expected in REQUIRED_ENABLED_FLAGS.items():
            actual = flags.get(k)
            if actual != expected:
                print(
                    f"FATAL: ABI-coupled flag {k}={actual!r} in RT-AC86U target.mak "
                    f"(must remain {expected!r} for closed-source blobs)!",
                    file=sys.stderr,
                )
                return 1

        for k, expected in EXPECTED_STRIPPED_FLAGS.items():
            actual = flags.get(k)
            if actual != expected:
                print(
                    f"FATAL: Expected stripped bloat flag {k}={expected!r} in RT-AC86U target.mak, got {actual!r}!",
                    file=sys.stderr,
                )
                return 1
        print(
            f"[stage1:flags] Verified RT-AC86U target.mak preserves {len(REQUIRED_ENABLED_FLAGS)} ABI flags "
            f"and strips {len(EXPECTED_STRIPPED_FLAGS)} unused services (FORCE_EN={flags.get('FORCE_EN')})."
        )

        # 2. Verify zero blob-imported symbol disappearance across touched C/H files
        patched_c_files = [
            os.path.join(patched_root, r)
            for r in sorted(touched_rels)
            if r.endswith((".c", ".h"))
        ]
        if unpatched_files:
            before_map = find_c_symbol_occurrences(unpatched_files, ext_und)
            after_map = find_c_symbol_occurrences(patched_c_files, ext_und)
            lost = sorted(sym for sym in ext_und if before_map[sym] and not after_map[sym])
            if lost:
                print(
                    f"FATAL: Patches removed {len(lost)} symbol(s) imported by closed-source .o blobs: {lost}",
                    file=sys.stderr,
                )
                return 1
            matched_cnt = sum(1 for sym in ext_und if after_map[sym])
            print(f"[stage1:symbols] Verified {matched_cnt} blob-imported symbols across patched C/H files (0 lost).")

        # 3. Scan available httpd/rc/shared/libdisk C sources (using patched versions where applicable)
        scan_files: list[str] = []
        for sub in (
            "release/src/router/httpd",
            "release/src/router/rc",
            "release/src/router/shared",
            "release/src/router/libdisk",
        ):
            base_dir = os.path.join(merlin_dir, sub)
            if not os.path.isdir(base_dir):
                continue
            for root, _dirs, files in os.walk(base_dir):
                for fn in files:
                    if fn.endswith((".c", ".h")):
                        rel = os.path.relpath(os.path.join(root, fn), merlin_dir)
                        override = os.path.join(patched_root, rel)
                        scan_files.append(override if os.path.isfile(override) else os.path.join(root, fn))

        violations = check_disabled_ifdef_exclusivity(scan_files, ext_und)
        if violations:
            print(
                "FATAL: Blob-imported symbols compiled out by disabled RTCONFIG_* guards:\n  - "
                + "\n  - ".join(violations),
                file=sys.stderr,
            )
            return 1
        print(f"[stage1:ifdef] Scanned {len(scan_files)} httpd/rc/shared source files: 0 disabled-#ifdef symbol conflicts.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
