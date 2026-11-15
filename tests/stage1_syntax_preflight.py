#!/usr/bin/env python3
"""Stage 1 Real-Source Cross-Compiler Syntax Preflight (-fsyntax-only).

Runs inside the fw-build CI container against the patched asuswrt-merlin.ng tree
before `make rt-ac86u` begins, verifying that patched/backported translation units
parse and type-check cleanly under `arm-buildroot-linux-gnueabi-gcc` with the
exact injected 32-bit HND tuning flags (`-march=armv8-a+crc -mtune=cortex-a53`).
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile

STRIPPED_RTCONFIG = {
    "RTCONFIG_WEBDAV",
    "RTCONFIG_SMARTSYNCBASE",
    "RTCONFIG_TOR",
    "RTCONFIG_MEDIA_SERVER",
    "RTCONFIG_TIMEMACHINE",
    "RTCONFIG_USB_PRINTER",
    "RTCONFIG_USB_MODEM",
    "RTCONFIG_QUAGGA",
    "RTCONFIG_QTN",
    "RTCONFIG_PERMISSION_MANAGEMENT",
}

ENABLE_RTCONFIG = {
    "RTCONFIG_BCMARM",
    "RTCONFIG_BCMWL6",
    "RTCONFIG_BCMWL6A",
    "RTCONFIG_HND_ROUTER",
    "RTCONFIG_OPENSSL11",
    "RTCONFIG_IPV6",
    "RTCONFIG_OPENVPN",
    "RTCONFIG_SSH",
    "RTCONFIG_WIREGUARD",
    "RTCONFIG_PROTECTION_SERVER",
    "RTCONFIG_BWDPI",
    "RTCONFIG_USB",
    "RTCONFIG_USB_EXTRAS",
    "RTCONFIG_SAMBA36X",
    "RTCONFIG_ISP_METER",
    "RTCONFIG_BRCM_NAND_JFFS2",
    "RTCONFIG_JFFS2LOG",
    "RTCONFIG_NVRAM_ENCRYPT",
    "RTCONFIG_BCMSMP",
    "RTCONFIG_WIRELESSREPEATER",
    "RTCONFIG_PROXYSTA",
    "RTCONFIG_DPSTA",
    "RTCONFIG_AMAS",
}

MANDATORY_SOURCES = [
    ("release/src/router/wsdd2/wsdd2.c", ["-std=gnu11", "-Wall", "-Wextra"], []),
    ("release/src/router/wsdd2/wsd.c", ["-std=gnu11", "-Wall", "-Wextra"], []),
    ("release/src/router/wsdd2/llmnr.c", ["-std=gnu11", "-Wall", "-Wextra"], []),
    ("release/src/router/shared/pids.c", ["-std=gnu99", "-Wall"], []),
    ("release/src/router/shared/shutils.c", ["-std=gnu99", "-Wall"], []),
]

EXTENDED_SOURCES = [
    ("release/src/router/shared/defaults.c", ["-std=gnu99", "-Wall"], []),
    ("release/src/router/shared/misc.c", ["-std=gnu99", "-Wall"], []),
    ("release/src/router/rstats/rstats.c", ["-std=gnu99", "-Wall"], ["release/src/router/rstats"]),
    ("release/src/router/cstats/cstats.c", ["-std=gnu99", "-Wall"], ["release/src/router/cstats"]),
    ("release/src/router/libdisk/usb_info.c", ["-std=gnu99", "-Wall"], ["release/src/router/libdisk"]),
    ("release/src/router/libdisk/write_smb_conf.c", ["-std=gnu99", "-Wall"], ["release/src/router/libdisk"]),
]


def synthesize_headers(merlin_dir: str, inc_dir: str) -> None:
    """Create minimal pre-build rtconfig.h, version.h, bbid.h in inc_dir."""
    cfg_base_path = os.path.join(merlin_dir, "release/src/router/config_base")
    defined: dict[str, str | None] = {}
    if os.path.isfile(cfg_base_path):
        with open(cfg_base_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                m_y = re.match(r"^(RTCONFIG_[A-Za-z0-9_]+)=y$", line)
                if m_y:
                    defined[m_y.group(1)] = "1"
                else:
                    m_off = re.match(r"^#\s*(RTCONFIG_[A-Za-z0-9_]+)\s+is not set$", line)
                    if m_off:
                        defined.setdefault(m_off.group(1), None)

    for macro in ENABLE_RTCONFIG:
        defined[macro] = "1"
    for macro in STRIPPED_RTCONFIG:
        defined[macro] = None

    with open(os.path.join(inc_dir, "rtconfig.h"), "w", encoding="utf-8") as fh:
        fh.write("#ifndef __RTCONFIG_H__\n#define __RTCONFIG_H__\n")
        for k in sorted(defined):
            v = defined[k]
            if v is not None:
                fh.write(f"#define {k} {v}\n")
            else:
                fh.write(f"#undef {k}\n")
        fh.write("#endif\n")

    with open(os.path.join(inc_dir, "version.h"), "w", encoding="utf-8") as fh:
        fh.write(
            '#ifndef RTVERSION\n'
            '#define RT_VERSION "386.14_2"\n'
            '#define RT_MAJOR_VERSION "386"\n'
            '#define RT_MINOR_VERSION "14"\n'
            '#define RT_SERIALNO "386.14_2"\n'
            '#define RT_RCNO ""\n'
            '#define RT_EXTENDNO "sec2026"\n'
            '#define RT_BUILD_NAME "RT-AC86U"\n'
            '#define RT_BUILD_INFO "sec2026"\n'
            '#define RT_SWPJVERNO ""\n'
            '#define ENC_SP_EXTENDNO "sec2026"\n'
            "#endif\n"
        )

    with open(os.path.join(inc_dir, "bbid.h"), "w", encoding="utf-8") as fh:
        fh.write("#define BBOARD_ID 94908\n")


def run_syntax_check(
    cc: str, merlin_dir: str, inc_dir: str, rel_src: str, extra_cflags: list[str], rel_inc_dirs: list[str], mandatory: bool
) -> bool:
    src_path = os.path.join(merlin_dir, rel_src)
    if not os.path.isfile(src_path):
        if mandatory:
            raise RuntimeError(f"Missing mandatory preflight source: {rel_src}")
        return False

    inc_candidates = [
        inc_dir,
        os.path.join(merlin_dir, "release/src/router/shared"),
        os.path.join(merlin_dir, "release/src/router/libdisk"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/common/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/shared/bcmwifi/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/opensource/include/bcm963xx"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/shared/opensource/include/bcm963xx"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/userspace/public/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/userspace/private/include"),
        *(os.path.join(merlin_dir, d) for d in rel_inc_dirs),
    ]
    inc_flags = [f"-I{d}" for d in inc_candidates if os.path.isdir(d)]

    cmd = [
        cc,
        "-fsyntax-only",
        "-mabi=aapcs-linux",
        "-marm",
        "-msoft-float",
        "-ffixed-r8",
        "-march=armv8-a+crc",
        "-mtune=cortex-a53",
        "-DHND_ROUTER",
        "-DLINUX26",
        "-DCONFIG_BCMWL5",
        "-DBCMWPA2",
        "-DBCMQOS",
        "-DTYPEDEF_FLOAT_T",
        "-DRTCONFIG_ISP_METER",
        "-D_GNU_SOURCE",
        *extra_cflags,
        *inc_flags,
        src_path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0:
        print(f"[stage1:syntax] PASS: {rel_src}")
        return True

    err_lines = [l for l in proc.stderr.splitlines() if l.strip()]
    only_missing_hdr = (
        not mandatory
        and any("No such file or directory" in l for l in err_lines)
        and not any(
            tok in proc.stderr
            for tok in ("undeclared", "conflicting types", "syntax error", "expected ';'", "too few arguments", "too many arguments")
        )
    )
    if only_missing_hdr:
        print(f"[stage1:syntax] SKIP (requires build-time generated header): {rel_src}")
        return False

    raise RuntimeError(f"Cross-compiler -fsyntax-only failed on {rel_src}:\n{proc.stderr[:2000]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 1 cross-compiler -fsyntax-only preflight.")
    parser.add_argument("--merlin-dir", required=True)
    parser.add_argument("--cc", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="stage1_inc_") as inc_dir:
        synthesize_headers(args.merlin_dir, inc_dir)
        passed = 0
        for rel_src, flags, rel_incs in MANDATORY_SOURCES:
            if run_syntax_check(args.cc, args.merlin_dir, inc_dir, rel_src, flags, rel_incs, mandatory=True):
                passed += 1
        for rel_src, flags, rel_incs in EXTENDED_SOURCES:
            if run_syntax_check(args.cc, args.merlin_dir, inc_dir, rel_src, flags, rel_incs, mandatory=False):
                passed += 1
    print(f"[stage1:syntax] Verified {passed} real patched translation units with {os.path.basename(args.cc)}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        raise SystemExit(1)
