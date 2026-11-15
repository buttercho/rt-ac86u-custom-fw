#!/usr/bin/env python3
"""Static & GNU Make Build-Graph Auditor for RT-AC86U (386.14_2-sec2026).

Verifies pre-build without running slow full compilation:
  1. 32-bit router/Makefile rules use `-march=armv8-a+crc -mtune=cortex-a53`
     (never invalid 32-bit `+crypto`/`+simd`), cleanly separated from 64-bit kernel
     `CONFIG_ARM64_CRYPTO=y` (`# CONFIG_CRYPTO_AES_ARM64_NEON_BLK is not set`).
  2. `openssl-1.1/Makefile:` includes `no-tests` (and `recordlentest.c` has zero
     OpenSSL 3.x `TEST_skip(` calls when `--already-patched`).
  3. `dropbear/config.h:` depends on `$(wildcard dropbear/config.h.in dropbear/src/config.h.in)`,
     `shared`, `nvram$(BCMEX)$(EX7)` (never bare `nvram`), and `wlcsm`; `dropbear:`
     passes `AUTOCONF=true AUTOHEADER=true`.
  4. Autotools `mtime` ordering on `3004.388` `dropbear` and `wget` when `--already-patched`.
  5. Real GNU `make -nk` dependency resolution across all touched/backported RT-AC86U
     router targets using synthesized RT-AC86U `.config` flags.
"""

from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys
import tempfile

MAKE_SOLVER_TARGETS = [
    "openssl-1.1/Makefile",
    "zlib/stamp-h1",
    "sqlite/stamp-h1",
    "expat-2.0.1/stamp-h1",
    "libcap-ng/configure",
    "dropbear",
    "curl/Makefile",
    "wget",
    "openvpn/Makefile",
    "miniupnpd",
    "dnsmasq",
    "wsdd2",
    "wireguard-tools",
    "libovpn",
    "rstats",
    "cstats",
    "httpd",
    "rc",
    "shared",
    "libdisk",
]

REQUIRED_ROUTER_FILES = [
    "release/src/router/Makefile",
    "release/src-rt-5.02hnd/kernel/linux-4.1/config_base.6a",
    "release/src-rt/platform.mak",
    "release/src-rt/target.mak",
    "release/src/router/common.mak",
    "release/src/router/config_base",
    "release/src-rt-5.02hnd/targets/94908HND/94908HND.RT-AC86U",
]

RT_AC86U_EXTRA_CONFIG = (
    "RTCONFIG_BCMARM=y\n"
    "RTCONFIG_BCMWL6=y\n"
    "RTCONFIG_BCMWL6A=y\n"
    "RTCONFIG_HND_ROUTER=y\n"
    "RTCONFIG_OPENSSL11=y\n"
    "RTCONFIG_IPV6=y\n"
    "RTCONFIG_OPENVPN=y\n"
    "RTCONFIG_SSH=y\n"
    "RTCONFIG_WIREGUARD=y\n"
    "RTCONFIG_PROTECTION_SERVER=y\n"
    "RTCONFIG_BWDPI=y\n"
    "RTCONFIG_HTTPS=y\n"
    "RTCONFIG_USB=y\n"
    "RTCONFIG_USB_EXTRAS=y\n"
    "RTCONFIG_SAMBA36X=y\n"
)


def read_merlin_bytes(merlin_dir: str, rel_path: str) -> bytes:
    """Read file from checked-out tree or git HEAD (for sparse local checkouts)."""
    disk_path = os.path.join(merlin_dir, rel_path)
    if os.path.isfile(disk_path):
        with open(disk_path, "rb") as fh:
            return fh.read()
    return subprocess.check_output(["git", "-C", merlin_dir, "show", f"HEAD:{rel_path}"])


def select_patches(patch_dir: str, set1_only: bool) -> list[str]:
    patches = sorted(glob.glob(os.path.join(patch_dir, "00*.patch")))
    if set1_only or os.environ.get("APPLY_SET2", "1") != "1":
        patches = [p for p in patches if not re.match(r"^00[6-9]-", os.path.basename(p))]
    if len(patches) < 5:
        raise RuntimeError(f"Expected >=5 patches in {patch_dir}, found {len(patches)}")
    return patches


def extract_make_rule_block(makefile_text: str, target_prefix: str) -> str:
    """Return target line and indented recipe lines until the next unindented target."""
    lines = makefile_text.splitlines()
    for idx, line in enumerate(lines):
        if line.startswith(target_prefix):
            block = [line]
            for nxt in lines[idx + 1 :]:
                if nxt == "" or nxt.startswith("\t") or nxt.startswith(" ") or nxt.startswith("#"):
                    block.append(nxt)
                    continue
                if nxt.startswith(("ifeq ", "ifneq ", "else", "endif")):
                    block.append(nxt)
                    continue
                break
            return "\n".join(block)
    raise RuntimeError(f"Missing target rule '{target_prefix}' in release/src/router/Makefile")


def materialize_patched_texts(
    merlin_dir: str, patch_dir: str, already_patched: bool, set1_only: bool
) -> dict[str, bytes]:
    """Return patched contents of key build-graph files (disk or temp-applied patches)."""
    if already_patched:
        return {rel: read_merlin_bytes(merlin_dir, rel) for rel in REQUIRED_ROUTER_FILES}

    patches = select_patches(patch_dir, set1_only)
    touched: set[str] = set(REQUIRED_ROUTER_FILES)
    for p in patches:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("+++ b/"):
                    touched.add(line[6:].strip())

    with tempfile.TemporaryDirectory(prefix="audit_graph_apply_") as tmp:
        subprocess.run(["git", "init", "-q"], cwd=tmp, check=True)
        for rel in sorted(touched):
            dst = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as fh:
                fh.write(read_merlin_bytes(merlin_dir, rel))
        for p in patches:
            subprocess.run(["git", "apply", p], cwd=tmp, check=True)
        return {
            rel: open(os.path.join(tmp, rel), "rb").read()
            for rel in REQUIRED_ROUTER_FILES
        }


def audit_cflags_and_kernel_config(router_mk: str, cfg_6a: str) -> None:
    """Verify 32-bit GCC 5.3 flag separation from 64-bit AArch64 kernel crypto."""
    if "+crypto" in router_mk or "+simd" in router_mk:
        raise RuntimeError(
            "FATAL: Invalid 32-bit HND GCC 5.3 feature modifier (+crypto/+simd) found in release/src/router/Makefile"
        )
    crc_count = router_mk.count("-march=armv8-a+crc -mtune=cortex-a53")
    if crc_count < 6:
        raise RuntimeError(
            f"Expected >=6 occurrences of '-march=armv8-a+crc -mtune=cortex-a53' in router/Makefile, found {crc_count}"
        )
    required_kcfg = [
        "CONFIG_ARM64_CRYPTO=y",
        "CONFIG_CRYPTO_AES_ARM64_CE_BLK=y",
        "# CONFIG_CRYPTO_AES_ARM64_NEON_BLK is not set",
    ]
    for line in required_kcfg:
        if line not in cfg_6a.splitlines():
            raise RuntimeError(f"Missing kernel crypto invariant '{line}' in config_base.6a")


def audit_openssl_and_dropbear_rules(router_mk: str, merlin_dir: str, already_patched: bool) -> None:
    """Verify OpenSSL 1.1 no-tests/TEST_skip and Dropbear HND prerequisites."""
    ssl_rule = extract_make_rule_block(router_mk, "openssl-1.1/Makefile:")
    if "no-tests" not in ssl_rule:
        raise RuntimeError("Missing 'no-tests' in openssl-1.1/Makefile: Configure rule")

    if already_patched:
        rec_path = os.path.join(merlin_dir, "release/src/router/openssl-1.1/test/recordlentest.c")
        if os.path.isfile(rec_path):
            with open(rec_path, "r", encoding="utf-8", errors="replace") as fh:
                if "TEST_skip(" in fh.read():
                    raise RuntimeError(
                        "Found unsupported OpenSSL 3.x TEST_skip( call in openssl-1.1/test/recordlentest.c"
                    )

    db_in = extract_make_rule_block(router_mk, "dropbear/config.h.in:").splitlines()[0]
    if re.search(r"(?<!\w)nvram(?=\s|$)", db_in):
        raise RuntimeError(f"Invalid bare 'nvram' prerequisite in '{db_in}'")

    db_cfg = extract_make_rule_block(router_mk, "dropbear/config.h:").splitlines()[0]
    for token in ("dropbear/src/config.h.in", "shared", "nvram$(BCMEX)$(EX7)", "wlcsm"):
        if token not in db_cfg:
            raise RuntimeError(f"Missing '{token}' prerequisite in '{db_cfg}'")
    if re.search(r"(?<!\w)nvram(?=\s|$)", db_cfg):
        raise RuntimeError(f"Invalid bare 'nvram' prerequisite in '{db_cfg}'")

    db_build = extract_make_rule_block(router_mk, "dropbear:")
    for token in ("AUTOCONF=true", "AUTOHEADER=true"):
        if token not in db_build:
            raise RuntimeError(f"Missing '{token}' in 'dropbear:' make invocation")

    if "[ ! -f $(STAGEDIR)/usr/lib/libexpat.la ]" not in router_mk:
        raise RuntimeError("Expected guarded libexpat.la rewrite in expat-2.0.1 rule")


def audit_autotools_timestamps(merlin_dir: str) -> None:
    """Verify 3004.388 Dropbear & Wget generated autotools files are newer than sources."""
    rtr = os.path.join(merlin_dir, "release/src/router")

    db_dir = os.path.join(rtr, "dropbear")
    db_src = os.path.join(db_dir, "configure.ac")
    db_cfg = os.path.join(db_dir, "configure")
    db_hin = os.path.join(db_dir, "src/config.h.in")
    if not os.path.isfile(db_hin):
        db_hin = os.path.join(db_dir, "config.h.in")
    if os.path.isfile(db_src):
        src_mtime = os.stat(db_src).st_mtime
        for gen in (db_cfg, db_hin):
            if not os.path.isfile(gen) or os.stat(gen).st_mtime < src_mtime:
                raise RuntimeError(f"Stale autotools timestamp on {gen} vs {db_src}")

    wget_dir = os.path.join(rtr, "wget")
    wget_src_candidates = [os.path.join(wget_dir, "configure.ac"), os.path.join(wget_dir, "Makefile.am")]
    wget_src_mtimes = [os.stat(p).st_mtime for p in wget_src_candidates if os.path.isfile(p)]
    if wget_src_mtimes:
        max_src = max(wget_src_mtimes)
        for rel in ("aclocal.m4", "configure", "Makefile.in", "src/Makefile.in"):
            gen = os.path.join(wget_dir, rel)
            if not os.path.isfile(gen) or os.stat(gen).st_mtime < max_src:
                raise RuntimeError(f"Stale autotools timestamp on {gen} vs configure.ac/Makefile.am")


def audit_gnu_make_dryrun(files: dict[str, bytes]) -> None:
    """Run real GNU make -nk in an ephemeral HND overlay over touched router targets."""
    with tempfile.TemporaryDirectory(prefix="audit_make_solver_") as tmp:
        hnd = os.path.join(tmp, "release/src-rt-5.02hnd")
        srcbase = os.path.join(hnd, "bcmdrivers/broadcom/net/wl/bcm94908/main/src")
        rtr = os.path.join(hnd, "router")
        os.makedirs(rtr, exist_ok=True)
        os.makedirs(os.path.join(srcbase, "kernel/linux-4.1"), exist_ok=True)
        os.makedirs(os.path.join(hnd, "targets/94908HND"), exist_ok=True)
        os.symlink(rtr, os.path.join(srcbase, "router"))

        with open(os.path.join(srcbase, "kernel/linux-4.1/Makefile"), "w", encoding="utf-8") as fh:
            fh.write("VERSION = 4\nPATCHLEVEL = 1\nSUBLEVEL = 52\nEXTRAVERSION =\n")
        with open(os.path.join(srcbase, "kernel/linux-4.1/.config"), "wb") as fh:
            fh.write(files["release/src-rt-5.02hnd/kernel/linux-4.1/config_base.6a"])

        dst_map = {
            os.path.join(srcbase, "platform.mak"): "release/src-rt/platform.mak",
            os.path.join(srcbase, "target.mak"): "release/src-rt/target.mak",
            os.path.join(rtr, "Makefile"): "release/src/router/Makefile",
            os.path.join(rtr, "common.mak"): "release/src/router/common.mak",
            os.path.join(rtr, "config_base"): "release/src/router/config_base",
            os.path.join(hnd, "targets/94908HND/94908HND.RT-AC86U"): "release/src-rt-5.02hnd/targets/94908HND/94908HND.RT-AC86U",
        }
        for dst, rel in dst_map.items():
            with open(dst, "wb") as fh:
                fh.write(files[rel])

        with open(os.path.join(srcbase, ".config"), "w", encoding="utf-8") as fh:
            fh.write(
                "export HND_ROUTER=y\nexport PROFILE=94908HND\n"
                "export BUILD_NAME=RT-AC86U\nexport ARM=y\nexport BCMWL6=y\nexport BCMWL6A=y\n"
            )
        cfg_base = files["release/src/router/config_base"].decode("utf-8", errors="replace")
        with open(os.path.join(rtr, ".config"), "w", encoding="utf-8") as fh:
            fh.write(cfg_base + "\n" + RT_AC86U_EXTRA_CONFIG)

        for stub_dir in ("bwdpi_source",):
            os.makedirs(os.path.join(rtr, stub_dir), exist_ok=True)
        # Notice dropbear/config.h.in is deliberately omitted so $(wildcard ... dropbear/src/config.h.in) is exercised.
        for stub in (
            "curl/configure",
            "wget/Makefile.am",
            "miniupnpd/config.h.in",
            "shared/version.h",
            "dropbear/src/config.h.in",
            "iptables-1.4.x/configure.ac",
            "e2fsprogs/configure",
        ):
            sp = os.path.join(rtr, stub)
            os.makedirs(os.path.dirname(sp), exist_ok=True)
            open(sp, "w", encoding="utf-8").close()

        proc = subprocess.run(
            [
                "make",
                "-C",
                rtr,
                "-nk",
                "--eval=override MAKE := echo SUBMAKE",
                "BCM_FSBUILD_DIR=/tmp/fs",
                "INSTALL_DIR=/tmp/inst",
                *MAKE_SOLVER_TARGETS,
            ],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0 or "No rule to make target" in (proc.stdout + proc.stderr):
            raise RuntimeError(
                f"GNU make -nk build-graph failure (rc={proc.returncode}):\n"
                f"STDERR:\n{proc.stderr[:1200]}\nSTDOUT tail:\n{proc.stdout[-800:]}"
            )
        for expected in ("no-tests", "-lwlcsm", "AUTOCONF=true", "-march=armv8-a+crc -mtune=cortex-a53"):
            if expected not in proc.stdout:
                raise RuntimeError(f"Expected '{expected}' in GNU make -nk dry-run output!")
        if "+crypto" in proc.stdout:
            raise RuntimeError("Unexpected '+crypto' flag in 32-bit router make -nk dry-run output!")


def main() -> int:
    parser = argparse.ArgumentParser(description="Static & GNU Make build-graph audit for RT-AC86U.")
    parser.add_argument("--merlin-dir", required=True)
    parser.add_argument("--patch-dir", required=True)
    parser.add_argument("--already-patched", action="store_true")
    parser.add_argument("--set1-only", action="store_true")
    args = parser.parse_args()

    files = materialize_patched_texts(args.merlin_dir, args.patch_dir, args.already_patched, args.set1_only)
    router_mk = files["release/src/router/Makefile"].decode("utf-8", errors="replace")
    cfg_6a = files["release/src-rt-5.02hnd/kernel/linux-4.1/config_base.6a"].decode("utf-8", errors="replace")

    audit_cflags_and_kernel_config(router_mk, cfg_6a)
    print("[stage1:graph] PASS: 32-bit -march=armv8-a+crc & 64-bit CONFIG_ARM64_CRYPTO separation verified.")

    audit_openssl_and_dropbear_rules(router_mk, args.merlin_dir, args.already_patched)
    print("[stage1:graph] PASS: OpenSSL 1.1 no-tests / TEST_skip & Dropbear HND prerequisites verified.")

    if args.already_patched:
        audit_autotools_timestamps(args.merlin_dir)
        print("[stage1:graph] PASS: Dropbear & Wget autotools mtime ordering verified.")

    audit_gnu_make_dryrun(files)
    print(f"[stage1:graph] PASS: GNU make -nk resolved all {len(MAKE_SOLVER_TARGETS)} RT-AC86U router targets cleanly.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        raise SystemExit(1)
