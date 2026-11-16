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
    "RTCONFIG_SHP",
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
    "RTCONFIG_CFGSYNC",
    "RTCONFIG_MULTICAST_IPTV",
    "RTCONFIG_HTTPS",
    "RTCONFIG_DUALWAN",
    "RTCONFIG_SW_HW_AUTH",
}

MANDATORY_SOURCES = [
    ("release/src/router/wsdd2/wsdd2.c", ["-DASUSWRT", "-std=gnu99", "-Wall", "-Wextra"], ["release/src/router/wsdd2"]),
    ("release/src/router/wsdd2/wsd.c", ["-DASUSWRT", "-std=gnu99", "-Wall", "-Wextra"], ["release/src/router/wsdd2"]),
    ("release/src/router/wsdd2/llmnr.c", ["-DASUSWRT", "-std=gnu99", "-Wall", "-Wextra"], ["release/src/router/wsdd2"]),
    ("release/src/router/shared/pids.c", ["-Wall"], []),
    ("release/src/router/shared/shutils.c", ["-Wall"], []),
    ("release/src/router/httpd/web.c", [], ["release/src/router/httpd", "release/src/router/rc"]),
]

EXTENDED_SOURCES = [
    ("release/src/router/shared/defaults.c", ["-Wall"], []),
    ("release/src/router/shared/misc.c", ["-Wall"], []),
    ("release/src/router/shared/network_utility.c", [], []),
    ("release/src/router/shared/process.c", [], []),
    ("release/src/router/shared/usb.c", [], []),
    ("release/src/router/httpd/aspbw.c", [], ["release/src/router/httpd"]),
    ("release/src/router/httpd/data_arrays.c", [], ["release/src/router/httpd"]),
    ("release/src/router/httpd/sysinfo.c", [], ["release/src/router/httpd"]),
    ("release/src/router/rc/asus_ddns.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/check_watchdog.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/common.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/erp_monitor.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/firewall.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/format.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/init.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/interface.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/netool.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/services.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/sysdeps/init-broadcom.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/wanduck.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/watchdog.c", [], ["release/src/router/rc"]),
    ("release/src/router/rc/wireguard.c", [], ["release/src/router/rc"]),
    ("release/src/router/rstats/rstats.c", ["-Wall"], ["release/src/router/rstats"]),
    ("release/src/router/cstats/cstats.c", ["-Wall"], ["release/src/router/cstats"]),
    ("release/src/router/libdisk/usb_info.c", ["-Wall"], ["release/src/router/libdisk"]),
    ("release/src/router/libdisk/write_smb_conf.c", ["-Wall"], ["release/src/router/libdisk"]),
    ("release/src/router/libovpn/openvpn_setup.c", [], ["release/src/router/libovpn", "release/src/router/rc"]),
]


def _safe_symlink(target: str, link_path: str) -> None:
    if os.path.exists(target) and not os.path.lexists(link_path):
        os.makedirs(os.path.dirname(link_path), exist_ok=True)
        os.symlink(target, link_path)


def synthesize_headers(merlin_dir: str, inc_dir: str) -> None:
    """Create minimal pre-build headers & symlinks in inc_dir."""
    cfg_base_path = os.path.join(merlin_dir, "release/src/router/config_base")
    defined: dict[str, str | None] = {}
    if os.path.isfile(cfg_base_path):
        with open(cfg_base_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                m_y = re.match(r"^(RTCONFIG_[A-Za-z0-9_]+)=y$", line)
                if m_y:
                    defined[m_y.group(1)] = "1"
                    continue
                m_num = re.match(r"^(RTCONFIG_[A-Za-z0-9_]+)=([0-9]+)$", line)
                if m_num:
                    defined[m_num.group(1)] = m_num.group(2)
                    continue
                m_off = re.match(r"^#\s*(RTCONFIG_[A-Za-z0-9_]+)\s+is not set$", line)
                if m_off:
                    defined.setdefault(m_off.group(1), None)

    for macro in ENABLE_RTCONFIG:
        defined[macro] = "1"
    defined.setdefault("RTCONFIG_MAX_RE", "9")
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

    with open(os.path.join(inc_dir, "json_config.h"), "w", encoding="utf-8") as fh:
        fh.write("#define JSON_C_HAVE_INTTYPES_H 1\n")

    with open(os.path.join(inc_dir, "cms_version.h"), "w", encoding="utf-8") as fh:
        fh.write('#define CMS_RELEASE_VERSION "5.02L.03"\n')

    ossl_conf_real = os.path.join(merlin_dir, "release/src/router/openssl-1.1/include/openssl/opensslconf.h")
    if not os.path.isfile(ossl_conf_real):
        os.makedirs(os.path.join(inc_dir, "openssl"), exist_ok=True)
        with open(os.path.join(inc_dir, "openssl/opensslconf.h"), "w", encoding="utf-8") as fh:
            fh.write(
                "#ifndef HEADER_OPENSSLCONF_H\n"
                "#define HEADER_OPENSSLCONF_H\n"
                "#define OPENSSL_API_COMPAT 0\n"
                "#define OPENSSL_FILE __FILE__\n"
                "#define OPENSSL_LINE __LINE__\n"
                "#define DEPRECATEDIN_1_2_0(f) f;\n"
                "#define DEPRECATEDIN_1_1_0(f) f;\n"
                "#define DEPRECATEDIN_1_0_0(f) f;\n"
                "#define DEPRECATEDIN_0_9_8(f) f;\n"
                "#define THIRTY_TWO_BIT\n"
                "#define BN_LLONG\n"
                "#define RC4_INT unsigned int\n"
                "#endif\n"
            )

    _safe_symlink(
        os.path.join(merlin_dir, "release/src/router/json-c"),
        os.path.join(inc_dir, "json-c"),
    )
    _safe_symlink(
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/include/tdts/sysdeps/hnd-tmcfg.h"),
        os.path.join(inc_dir, "tdts/tmcfg.h"),
    )
    udb_dir = os.path.join(merlin_dir, "release/src/router/bwdpi_source/prebuild/RT-AC86U")
    if os.path.isdir(udb_dir):
        os.makedirs(os.path.join(inc_dir, "udb"), exist_ok=True)
        for fn in os.listdir(udb_dir):
            _safe_symlink(os.path.join(udb_dir, fn), os.path.join(inc_dir, "udb", fn))


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
        os.path.dirname(src_path),
        os.path.join(merlin_dir, "release/src/router/shared"),
        os.path.join(merlin_dir, "release/src/router/shared/sysdeps/amas"),
        os.path.join(merlin_dir, "release/src/router/kernel_header/include"),
        os.path.join(merlin_dir, "release/src/router/libdisk"),
        os.path.join(merlin_dir, "release/src/router/libovpn"),
        os.path.join(merlin_dir, "release/src/router/libpasswd"),
        os.path.join(merlin_dir, "release/src/router/json-c"),
        os.path.join(merlin_dir, "release/src/router/mssl"),
        os.path.join(merlin_dir, "release/src/router/openssl-1.1/include"),
        os.path.join(merlin_dir, "release/src/router/curl/include"),
        os.path.join(merlin_dir, "release/src/router/networkmap"),
        os.path.join(merlin_dir, "release/src/router/sqlite"),
        os.path.join(merlin_dir, "release/src/router/cfg_mnt"),
        os.path.join(merlin_dir, "release/src/router/amas-utils"),
        os.path.join(merlin_dir, "release/src/router/amas-utils/prebuild/RT-AC86U"),
        os.path.join(merlin_dir, "release/src/router/protect_srv/include"),
        os.path.join(merlin_dir, "release/src/router/traffic_limiter"),
        os.path.join(merlin_dir, "release/src/router/sw-hw-auth"),
        os.path.join(merlin_dir, "release/src/router/aaews"),
        os.path.join(merlin_dir, "release/src/router/libletsencrypt"),
        os.path.join(merlin_dir, "release/src/router/nt_center/lib"),
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/include"),
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/asus_include"),
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/src/tdts_udb_sample"),
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/src/tdts_udb_sample/linux"),
        os.path.join(merlin_dir, "release/src/router/bwdpi_source/prebuild/RT-AC86U"),
        os.path.join(merlin_dir, "release/src/router/rom/rom/etc"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/common/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/common/include/devctrl_if"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/shared"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/shared/bcmwifi/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/broadcom/net/wl/impl51/main/src/wl/sys"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/bcmdrivers/opensource/include/bcm963xx"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/shared/opensource/include/bcm963xx"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/userspace/public/include"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/userspace/public/include/linux"),
        os.path.join(merlin_dir, "release/src-rt-5.02hnd/userspace/private/include"),
        *(os.path.join(merlin_dir, d) for d in rel_inc_dirs),
    ]
    seen_inc: set[str] = set()
    inc_flags: list[str] = []
    for d in inc_candidates:
        if d not in seen_inc and os.path.isdir(d):
            seen_inc.add(d)
            inc_flags.append(f"-I{d}")

    with open(src_path, "r", encoding="utf-8", errors="replace") as fh:
        head_lines = "".join(fh.readline() for _ in range(40))
    gnu_flag = [] if "_GNU_SOURCE" in head_lines else ["-D_GNU_SOURCE"]

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
        "-D__EXPORTED_HEADERS__",
        "-DRTCONFIG_ISP_METER",
        "-DASUS_DDNS",
        "-DASUS_EXT",
        "-DDLM",
        "-DBTN_SETUP",
        "-DWEB_REDIRECT",
        "-DTRANSLATE_ON_FLY",
        "-DFLASH_EMULATOR",
        "-DLinux",
        "-DWSC",
        "-DDNSMASQ",
        "-DCAPTCHA",
        "-DBCM49XX",
        "-DWL11AC_80P80",
        "-DWL11AC_160",
        "-DBCMDONGLEHOST",
        *gnu_flag,
        *extra_cflags,
        *inc_flags,
        src_path,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0:
        print(f"[stage1:syntax] PASS: {rel_src}")
        return True

    err_lines = [l for l in proc.stderr.splitlines() if l.strip()]
    all_error_lines = [l for l in err_lines if (": error:" in l or ": fatal error:" in l)]
    real_compile_errors = [l for l in all_error_lines if "No such file or directory" not in l]
    only_missing_hdr = (
        not mandatory
        and not real_compile_errors
        and any("No such file or directory" in l for l in err_lines)
    )
    if only_missing_hdr:
        print(f"[stage1:syntax] SKIP (requires build-time generated header): {rel_src}")
        return False

    summary = "\n".join(all_error_lines[:25]) if all_error_lines else proc.stderr[:2000]
    raise RuntimeError(f"Cross-compiler -fsyntax-only failed on {rel_src}:\n{summary}")


def check_dropbear_authpasswd_syntax(cc: str, merlin_dir: str, inc_dir: str) -> bool:
    """Syntax-check Dropbear svr-authpasswd.c with -Werror=implicit-function-declaration."""
    db_dir = os.path.join(merlin_dir, "release/src/router/dropbear")
    db_src = os.path.join(db_dir, "src/svr-authpasswd.c")
    if not os.path.isfile(db_src):
        return False

    db_stub = os.path.join(inc_dir, "dropbear_stub_inc")
    extra_inc: list[str] = []
    if not os.path.isfile(os.path.join(db_dir, "src/config.h")) and not os.path.isfile(
        os.path.join(db_dir, "config.h")
    ):
        os.makedirs(db_stub, exist_ok=True)
        with open(os.path.join(db_stub, "config.h"), "w", encoding="utf-8") as fh:
            fh.write(
                "#define BUNDLED_LIBTOM 1\n"
                "#define DISABLE_ZLIB 1\n"
                "#define DISABLE_PAM 1\n"
                "#define DISABLE_LASTLOG 1\n"
                "#define DISABLE_UTMP 1\n"
                "#define DISABLE_UTMPX 1\n"
                "#define DISABLE_WTMP 1\n"
                "#define DISABLE_WTMPX 1\n"
                "#define DISABLE_PUTUTLINE 1\n"
                "#define DISABLE_PUTUTXLINE 1\n"
                "#define HAVE_BASENAME 1\n"
                "#define HAVE_CLEARENV 1\n"
                "#define HAVE_CLOCK_GETTIME 1\n"
                "#define HAVE_CONST_GAI_STRERROR_PROTO 1\n"
                "#define HAVE_CRYPT 1\n"
                "#define HAVE_CRYPT_H 1\n"
                "#define HAVE_DAEMON 1\n"
                "#define HAVE_DECL_HTOLE64 1\n"
                "#define HAVE_ENDIAN_H 1\n"
                "#define HAVE_FORK 1\n"
                "#define HAVE_FREEADDRINFO 1\n"
                "#define HAVE_GAI_STRERROR 1\n"
                "#define HAVE_GETADDRINFO 1\n"
                "#define HAVE_GETGROUPLIST 1\n"
                "#define HAVE_GETNAMEINFO 1\n"
                "#define HAVE_GETPASS 1\n"
                "#define HAVE_GETSPNAM 1\n"
                "#define HAVE_GETUSERSHELL 1\n"
                "#define HAVE_HTOLE64 1\n"
                "#define HAVE_INTTYPES_H 1\n"
                "#define HAVE_LIBGEN_H 1\n"
                "#define HAVE_NETDB_H 1\n"
                "#define HAVE_NETINET_IN_H 1\n"
                "#define HAVE_NETINET_TCP_H 1\n"
                "#define HAVE_PATHS_H 1\n"
                "#define HAVE_PTY_H 1\n"
                "#define HAVE_PUTENV 1\n"
                "#define HAVE_SETRESGID 1\n"
                "#define HAVE_SHADOW_H 1\n"
                "#define HAVE_STDINT_H 1\n"
                "#define HAVE_STDIO_H 1\n"
                "#define HAVE_STDLIB_H 1\n"
                "#define HAVE_STRINGS_H 1\n"
                "#define HAVE_STRING_H 1\n"
                "#define HAVE_STRUCT_ADDRINFO 1\n"
                "#define HAVE_STRUCT_IN6_ADDR 1\n"
                "#define HAVE_STRUCT_SOCKADDR_IN6 1\n"
                "#define HAVE_STRUCT_SOCKADDR_STORAGE 1\n"
                "#define HAVE_STRUCT_SOCKADDR_STORAGE_SS_FAMILY 1\n"
                "#define HAVE_SYS_PRCTL_H 1\n"
                "#define HAVE_SYS_SELECT_H 1\n"
                "#define HAVE_SYS_SOCKET_H 1\n"
                "#define HAVE_SYS_STAT_H 1\n"
                "#define HAVE_SYS_TYPES_H 1\n"
                "#define HAVE_SYS_UIO_H 1\n"
                "#define HAVE_SYS_WAIT_H 1\n"
                "#define HAVE_UINT16_T 1\n"
                "#define HAVE_UINT32_T 1\n"
                "#define HAVE_UINT8_T 1\n"
                "#define HAVE_UNDERSCORE_STATIC_ASSERT 1\n"
                "#define HAVE_UNISTD_H 1\n"
                "#define HAVE_U_INT16_T 1\n"
                "#define HAVE_U_INT32_T 1\n"
                "#define HAVE_U_INT8_T 1\n"
                "#define HAVE_WRITEV 1\n"
                "#define STDC_HEADERS 1\n"
            )
        def_opts_path = os.path.join(db_dir, "src/default_options.h")
        if os.path.isfile(def_opts_path):
            def_opts = open(def_opts_path, "r", encoding="utf-8", errors="replace").read()
            guarded_lines = []
            for line in def_opts.splitlines():
                m = re.match(r"^( *#define\s+([^ \t]+)\s+.*)$", line)
                if m and m.group(2) != "DROPBEAR_DEFAULT_OPTIONS_H_":
                    guarded_lines.append(f"#ifndef {m.group(2)}\n{m.group(1)}\n#endif")
                else:
                    guarded_lines.append(line)
            with open(os.path.join(db_stub, "default_options_guard.h"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(guarded_lines) + "\n")
        extra_inc.append(f"-I{db_stub}")

    local_opts_flag = ["-DLOCALOPTIONS_H_EXISTS"] if os.path.isfile(os.path.join(db_dir, "localoptions.h")) else []
    inc_dirs = [
        db_dir,
        os.path.join(db_dir, "src"),
        os.path.join(db_dir, "libtomcrypt/src/headers"),
        os.path.join(db_dir, "libtommath"),
        os.path.join(merlin_dir, "release/src/router/protect_srv/include"),
        os.path.join(merlin_dir, "release/src/router/shared"),
        inc_dir,
    ]
    inc_flags = [*extra_inc, *(f"-I{d}" for d in inc_dirs if os.path.isdir(d))]
    cmd = [
        cc,
        "-fsyntax-only",
        "-Werror=implicit-function-declaration",
        "-mabi=aapcs-linux",
        "-marm",
        "-msoft-float",
        "-ffixed-r8",
        "-march=armv8-a+crc",
        "-mtune=cortex-a53",
        "-DARGTYPE=3",
        "-DDROPBEAR_SERVER",
        "-DDROPBEAR_CLIENT",
        *local_opts_flag,
        "-D_GNU_SOURCE",
        "-DSECURITY_NOTIFY",
        *inc_flags,
        db_src,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        err_lines = [l for l in proc.stderr.splitlines() if ": error:" in l or ": fatal error:" in l]
        summary = "\n".join(err_lines[:25]) if err_lines else proc.stderr[:2000]
        raise RuntimeError(f"Cross-compiler -fsyntax-only failed on release/src/router/dropbear/src/svr-authpasswd.c:\n{summary}")
    print("[stage1:syntax] PASS: release/src/router/dropbear/src/svr-authpasswd.c")
    return True


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
        if check_dropbear_authpasswd_syntax(args.cc, args.merlin_dir, inc_dir):
            passed += 1
    print(f"[stage1:syntax] Verified {passed} real patched translation units with {os.path.basename(args.cc)}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        raise SystemExit(1)
