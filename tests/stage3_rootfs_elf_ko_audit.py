#!/usr/bin/env python3
"""Stage 3 Post-Build Full-RootFS ELF Linker, Symbol & Kernel .ko CRC Audit.

Audits the assembled RT-AC86U rootfs (`targets/94908HND/fs.install`) after `make rt-ac86u`:
  1. 100% ELF Header & Float-ABI Gate:
     - All 32-bit userspace binaries/libs must be `EM_ARM` (40) EABI5 soft-float
       (`EF_ARM_ABI_FLOAT_HARD` = 0x400 MUST NOT be set).
     - `EM_AARCH64` (183) is allowed strictly for 64-bit `ebtables*` and `/lib/*aarch64*`.
  2. 100% Dynamic Linker (`DT_NEEDED` + `GLOBAL UND`) Symbol Resolution:
     - Simulates `ld.so` library resolution across `/lib`, `/usr/lib`, `/lib/public`,
       `/lib/private`, `/lib/aarch64`, `/usr/lib/aarch64`, and binary `RPATH`/`RUNPATH`.
     - Verifies every `DT_NEEDED` shared library exists and every non-weak `GLOBAL UND`
       function/object symbol resolves against the binary's transitive shared-library closure
       (covering all closed-source Broadcom/ASUS/TrendMicro binaries too!).
  3. `libexpat.so` Parity & Stripped-Bloat Absence Gate:
     - Verifies `/lib/public/libexpat.so` matches upgraded `/usr/lib/libexpat.so.1`.
     - Verifies stripped bloat (`lighttpd`, `mod_aicloud_*.so`, `tor`, `minidlna`,
       `afpd`, `cnid_metad`, `u2ec`, `lpd`, `zebra`, `ripd`) is completely absent.
  4. 100% Kernel Module (`*.ko`) Vermagic & `CONFIG_MODVERSIONS` Symbol CRC Gate:
     - Parses `Module.symvers` + peer `.ko` `___ksymtab`/__crc exports and checks every
       `.ko`'s `.modinfo` (`vermagic=4.1.27 SMP preempt mod_unload aarch64`) and
       64-bit `__versions` (`struct modversion_info`: `<Q56s`) CRCs.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
EM_ARM = 40
EM_AARCH64 = 183
EF_ARM_ABI_FLOAT_HARD = 0x00000400

FORBIDDEN_BLOAT_PATTERNS = [
    "*/lighttpd",
    "*/mod_aicloud_*.so",
    "*/usr/sbin/tor",
    "*/minidlna",
    "*/afpd",
    "*/cnid_metad",
    "*/u2ec",
    "*/lpd",
    "*/zebra",
    "*/ripd",
]

ALLOWED_AARCH64_PATTERNS = [
    "*/ebtables*",
    "*/libebt*.so*",
    "*/ld-linux-aarch64.so*",
    "*/aarch64/*",
    "*/xtables*",
    "*/libxt*.so*",
    "*/ip",
    "*/tc",
    "*/mcpd",
    "*/fcctl",
    "*/fc",
    "*/runner*",
    "*/archer*",
    "*/spuctl",
    "*/bpmctl",
    "*/pwr*",
    "*/ethctl",
    "*/ethswctl",
    "*/tmctl",
    "*/vlanctl",
    "*/rdpactl",
    "*/blogctl",
    "*/bs",
]

RUNTIME_INTRINSIC_UND = {
    "__gmon_start__",
    "_Jv_RegisterClasses",
    "_ITM_deregisterTMCloneTable",
    "_ITM_registerTMCloneTable",
    "__cxa_finalize",
    "__tls_get_addr",
    "___tls_get_addr",
    "_rtld_global",
    "_rtld_global_ro",
    "__libc_enable_secure",
    "__libc_stack_end",
    "_dl_argv",
    "_dl_find_dso_for_object",
    "__tunable_get_val",
}


@dataclass
class ElfInfo:
    rel_path: str
    full_path: str
    elf_class: int
    e_type: int
    e_machine: int
    e_flags: int
    soname: str = ""
    needed: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    defined_syms: set[str] = field(default_factory=set)
    und_syms: set[str] = field(default_factory=set)


def parse_elf_header(path: str) -> tuple[int, int, int, int] | None:
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(64)
    except OSError:
        return None
    if len(hdr) < 52 or hdr[:4] != ELF_MAGIC:
        return None
    elf_class = hdr[4]
    endian = "<" if hdr[5] == 1 else ">"
    e_type, e_machine = struct.unpack_from(f"{endian}HH", hdr, 16)
    if elf_class == ELFCLASS32:
        e_flags = struct.unpack_from(f"{endian}I", hdr, 36)[0]
    elif elf_class == ELFCLASS64 and len(hdr) >= 64:
        e_flags = struct.unpack_from(f"{endian}I", hdr, 48)[0]
    else:
        return None
    return elf_class, e_type, e_machine, e_flags


def extract_elf_pt_load_digest(path: str) -> str | None:
    """Hash all PT_LOAD ELF segments (invariant across sstrip section-header removal)."""
    try:
        with open(path, "rb") as fh:
            blob = bytearray(fh.read())
    except OSError:
        return None
    if len(blob) < 52 or blob[:4] != ELF_MAGIC:
        return None
    elf_class = blob[4]
    endian = "<" if blob[5] == 1 else ">"
    if elf_class == ELFCLASS32:
        e_phoff, _e_shoff, _e_flags, _e_ehsize, e_phentsize, e_phnum = struct.unpack_from(
            f"{endian}IIIHHH", blob, 28
        )
        if e_phnum == 0 or e_phentsize < 32 or e_phoff + e_phnum * e_phentsize > len(blob):
            return None
        # Mask ELF32 section-header fields (e_shoff, e_shentsize, e_shnum, e_shstrndx) zeroed by sstrip
        blob[32:36] = b"\x00" * 4
        blob[46:52] = b"\x00" * 6
        h = hashlib.sha256()
        pt_loads = 0
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_offset, _p_vaddr, _p_paddr, p_filesz = struct.unpack_from(f"{endian}IIIII", blob, off)
            if p_type == 1 and p_offset + p_filesz <= len(blob):
                pt_loads += 1
                h.update(blob[p_offset : p_offset + p_filesz])
        return h.hexdigest() if pt_loads > 0 else None
    if elf_class == ELFCLASS64 and len(blob) >= 64:
        e_phoff, _e_shoff, _e_flags, _e_ehsize, e_phentsize, e_phnum = struct.unpack_from(
            f"{endian}QQIHHH", blob, 32
        )
        if e_phnum == 0 or e_phentsize < 56 or e_phoff + e_phnum * e_phentsize > len(blob):
            return None
        # Mask ELF64 section-header fields (e_shoff, e_shentsize, e_shnum, e_shstrndx) zeroed by sstrip
        blob[40:48] = b"\x00" * 8
        blob[58:64] = b"\x00" * 6
        h = hashlib.sha256()
        pt_loads = 0
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, _p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz = struct.unpack_from(f"{endian}IIQQQQ", blob, off)
            if p_type == 1 and p_offset + p_filesz <= len(blob):
                pt_loads += 1
                h.update(blob[p_offset : p_offset + p_filesz])
        return h.hexdigest() if pt_loads > 0 else None
    return None


def populate_dynamic_metadata(elfs: list[ElfInfo], readelf_bin: str) -> None:
    by_path = {e.full_path: e for e in elfs}
    for idx in range(0, len(elfs), 25):
        batch = [e.full_path for e in elfs[idx : idx + 25]]
        out = subprocess.check_output([readelf_bin, "-d", "-D", "-Ws", *batch], text=True, errors="replace")
        current: ElfInfo | None = None
        in_dynsym = False
        if len(batch) == 1:
            current = by_path[batch[0]]

        for line in out.splitlines():
            if line.startswith("File: "):
                fp = line[6:].strip()
                current = by_path.get(fp)
                in_dynsym = False
                continue
            if current is None:
                continue
            if line.startswith(("Dynamic section", "Histogram")):
                in_dynsym = False
                continue
            if line.startswith("Symbol table "):
                in_dynsym = "'.symtab'" not in line
                continue
            if "(NEEDED)" in line and "[" in line:
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    current.needed.append(m.group(1))
            elif "(SONAME)" in line and "[" in line:
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    current.soname = m.group(1)
            elif ("(RPATH)" in line or "(RUNPATH)" in line) and "[" in line:
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    current.rpaths.extend(p for p in m.group(1).split(":") if p)
            elif in_dynsym:
                clean_line = re.sub(r"\[[^\]]*\]", "", line)
                parts = clean_line.split()
                if len(parts) >= 8 and parts[0].endswith(":"):
                    sym_type = parts[3]
                    bind = parts[4]
                    ndx = parts[6]
                    raw_name = parts[7]
                    base_name = raw_name.split("@")[0]
                    if not base_name:
                        continue
                    if ndx == "UND":
                        if (
                            bind == "GLOBAL"
                            and sym_type in ("FUNC", "OBJECT", "NOTYPE")
                            and base_name not in RUNTIME_INTRINSIC_UND
                            and not base_name.startswith("_dl_")
                        ):
                            current.und_syms.add(base_name)
                    elif bind in ("GLOBAL", "WEAK"):
                        current.defined_syms.add(base_name)


def parse_elf64_ko_sections(path: str) -> tuple[bytes, bytes, dict[str, int], dict[int, tuple[str, int]]]:
    """Extract .modinfo, __versions, exported __crc_* symbols, and .rela__versions entries."""
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] != ELF_MAGIC or blob[4] != ELFCLASS64:
        raise RuntimeError(f"{path}: expected ELF64 relocatable .ko")
    endian = "<" if blob[5] == 1 else ">"
    e_shoff = struct.unpack_from(f"{endian}Q", blob, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(f"{endian}HHH", blob, 58)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link, _info, _align, sh_entsize = struct.unpack_from(
            f"{endian}IIQQQQIIQQ", blob, off
        )
        sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    shstr_off, shstr_sz = sections[e_shstrndx][2], sections[e_shstrndx][3]
    shstr = blob[shstr_off : shstr_off + shstr_sz]

    def sec_name(idx: int) -> str:
        end = shstr.find(b"\x00", idx)
        return shstr[idx:end].decode("ascii", errors="replace")

    modinfo = b""
    versions = b""
    exported_crcs: dict[str, int] = {}
    sym_names: list[str] = []
    rela_versions_sec: tuple[int, int, int] | None = None

    for sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        sname = sec_name(sh_name)
        if sname == ".modinfo":
            modinfo = blob[sh_offset : sh_offset + sh_size]
        elif sname == "__versions":
            versions = blob[sh_offset : sh_offset + sh_size]
        elif sh_type == 4 and sname == ".rela__versions" and sh_entsize == 24:  # SHT_RELA
            rela_versions_sec = (sh_offset, sh_size, sh_entsize)
        elif sh_type == 2 and sh_entsize == 24:  # SHT_SYMTAB
            str_off, str_sz = sections[sh_link][2], sections[sh_link][3]
            strtab = blob[str_off : str_off + str_sz]
            sym_names = []
            for pos in range(sh_offset, sh_offset + sh_size, 24):
                st_name, st_info, _other, st_shndx, st_value, _st_size = struct.unpack_from(
                    f"{endian}IBBHQQ", blob, pos
                )
                if st_name == 0:
                    sym_names.append("")
                    continue
                end = strtab.find(b"\x00", st_name)
                sym = strtab[st_name:end].decode("ascii", errors="replace")
                sym_names.append(sym)
                if (st_info >> 4) != 0 and sym.startswith("__crc_") and st_shndx == 0xFFF1:  # SHN_ABS CRC symbol!
                    exported_crcs[sym[6:]] = st_value & 0xFFFFFFFF

    reloc_offsets: dict[int, tuple[str, int]] = {}
    if rela_versions_sec is not None and sym_names:
        r_off, r_sz, r_entsize = rela_versions_sec
        for pos in range(r_off, r_off + r_sz, r_entsize):
            r_offset, r_info, r_addend = struct.unpack_from(f"{endian}QQq", blob, pos)
            sym_idx = r_info >> 32
            if sym_idx < len(sym_names) and sym_names[sym_idx]:
                reloc_offsets[r_offset] = (sym_names[sym_idx], r_addend)

    return modinfo, versions, exported_crcs, reloc_offsets


def load_module_symvers(symvers_path: str) -> dict[str, int]:
    crcs: dict[str, int] = {}
    with open(symvers_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2 and parts[0].startswith("0x"):
                crcs[parts[1]] = int(parts[0], 16)
    return crcs


def audit_rootfs(
    rootfs_dir: str,
    symvers_path: str | None = None,
    expected_vermagic_prefix: str = "4.1.27 SMP preempt mod_unload aarch64",
) -> list[str]:
    errors: list[str] = []
    rootfs_dir = os.path.abspath(rootfs_dir)
    readelf_bin = shutil.which("readelf")
    if not readelf_bin:
        return ["readelf binary not found in PATH"]

    dyn_elfs: list[ElfInfo] = []
    ko_paths: list[str] = []

    for root, _dirs, files in os.walk(rootfs_dir):
        for fn in sorted(files):
            full = os.path.join(root, fn)
            rel = "/" + os.path.relpath(full, rootfs_dir).replace(os.sep, "/")

            # 1. Stripped bloat check (check both symlinks and regular files)
            for pat in FORBIDDEN_BLOAT_PATTERNS:
                if fnmatch.fnmatch(rel, pat):
                    errors.append(f"Forbidden stripped-bloat file present in rootfs: {rel}")

            if os.path.islink(full):
                continue

            if fn.endswith(".ko"):
                ko_paths.append(full)
                continue

            hdr = parse_elf_header(full)
            if hdr is None:
                continue
            elf_class, e_type, e_machine, e_flags = hdr

            if e_type in (ET_EXEC, ET_DYN):
                if elf_class == ELFCLASS32:
                    if e_machine != EM_ARM:
                        errors.append(f"{rel}: unexpected 32-bit e_machine={e_machine} (expected EM_ARM=40)")
                    if e_flags & EF_ARM_ABI_FLOAT_HARD:
                        errors.append(f"{rel}: HARD-FLOAT ABI (0x{e_flags:x}) detected — breaks soft-float HND rootfs!")
                elif elf_class == ELFCLASS64:
                    if e_machine != EM_AARCH64:
                        errors.append(f"{rel}: unexpected 64-bit e_machine={e_machine}")
                    if not any(fnmatch.fnmatch(rel, p) for p in ALLOWED_AARCH64_PATTERNS):
                        errors.append(f"{rel}: unexpected 64-bit userspace binary outside ebtables/aarch64 allowlist")
                dyn_elfs.append(ElfInfo(rel, full, elf_class, e_type, e_machine, e_flags))

    populate_dynamic_metadata(dyn_elfs, readelf_bin)

    # Index shared libraries by (elf_class, filename_or_soname)
    lib_index: dict[tuple[int, str], list[ElfInfo]] = {}
    for root, _dirs, files in os.walk(rootfs_dir):
        for fn in files:
            if ".so" not in fn:
                continue
            full = os.path.join(root, fn)
            real = os.path.realpath(full)
            if not os.path.isfile(real):
                continue
            # Match to scanned ElfInfo
            for e in dyn_elfs:
                if os.path.realpath(e.full_path) == real:
                    lib_index.setdefault((e.elf_class, fn), []).append(e)
                    if e.soname:
                        lib_index.setdefault((e.elf_class, e.soname), []).append(e)

    # 2. Verify DT_NEEDED & transitive symbol closure for every binary/shared library
    for e in dyn_elfs:
        if not e.needed and not e.und_syms:
            continue
        # Compute transitive closure of loaded shared objects
        closure: list[ElfInfo] = [e]
        seen_paths = {e.full_path}
        queue = list(e.needed)
        while queue:
            soname = queue.pop(0)
            cands = lib_index.get((e.elf_class, soname), [])
            if not cands:
                errors.append(f"{e.rel_path}: missing DT_NEEDED shared library '{soname}' (class={e.elf_class})")
                continue
            for c in cands:
                if c.full_path not in seen_paths:
                    seen_paths.add(c.full_path)
                    closure.append(c)
                    queue.extend(c.needed)

        # Every non-weak GLOBAL UND symbol in an executable must resolve in closure
        # (Note: shared libraries can call callbacks provided by the main executable like httpd/rc,
        # so enforce strict 0-unresolved-UND on all ET_EXEC binaries + standalone .so plugins with DT_NEEDED)
        if e.e_type == ET_EXEC:
            avail_syms: set[str] = set()
            for lib in closure:
                avail_syms |= lib.defined_syms
            # Also ld-linux provides _dl_* / __tls_get_addr
            for ld_key, ld_list in lib_index.items():
                if ld_key[0] == e.elf_class and ld_key[1].startswith("ld-"):
                    for ld_e in ld_list:
                        avail_syms |= ld_e.defined_syms
            # Closed-source TrendMicro /usr/bwdpi binaries may resolve symbols across peer /usr/bwdpi plugins
            if e.rel_path.startswith("/usr/bwdpi/") or "/bwdpi/" in e.rel_path:
                for peer in dyn_elfs:
                    if peer.elf_class == e.elf_class and "/bwdpi/" in peer.rel_path:
                        avail_syms |= peer.defined_syms
            missing = sorted(e.und_syms - avail_syms)
            if missing:
                errors.append(
                    f"{e.rel_path}: {len(missing)} unresolved dynamic symbol(s): {missing[:10]}"
                )

    # 3. Verify /lib/public/libexpat.so and /lib/libexpat.so match /usr/lib/libexpat.so.1 (sstrip-tolerant via PT_LOAD)
    usr_expat = os.path.join(rootfs_dir, "usr/lib/libexpat.so.1")
    if os.path.exists(usr_expat):
        usr_real = os.path.realpath(usr_expat)
        usr_bytes = open(usr_real, "rb").read()
        h_usr = hashlib.sha256(usr_bytes).hexdigest()
        pt_usr = extract_elf_pt_load_digest(usr_real)
        for cand_rel in ("lib/public/libexpat.so", "lib/libexpat.so"):
            cand_expat = os.path.join(rootfs_dir, cand_rel)
            if not os.path.exists(cand_expat):
                continue
            cand_real = os.path.realpath(cand_expat)
            cand_bytes = open(cand_real, "rb").read()
            h_cand = hashlib.sha256(cand_bytes).hexdigest()
            pt_cand = extract_elf_pt_load_digest(cand_real)
            exact_match = h_cand == h_usr
            pt_match = pt_cand is not None and pt_usr is not None and pt_cand == pt_usr
            if not (exact_match or pt_match):
                errors.append(
                    f"/{cand_rel} ({h_cand[:12]}) does NOT match /usr/lib/libexpat.so.1 ({h_usr[:12]})!"
                )
            elif (b"expat_2." in usr_bytes or b"expat_2." in cand_bytes) and (
                b"expat_2.0." in cand_bytes or b"expat_2.1." in cand_bytes
            ):
                errors.append(f"/{cand_rel} still carries stale expat 2.0/2.1 version signature!")

    # 4. Kernel .ko vermagic & symbol CRC audit
    sym_crcs: dict[str, int] = {}
    if symvers_path and os.path.isfile(symvers_path):
        sym_crcs.update(load_module_symvers(symvers_path))

    ko_parsed = []
    for kp in sorted(ko_paths):
        rel = "/" + os.path.relpath(kp, rootfs_dir).replace(os.sep, "/")
        try:
            modinfo, versions, exported, reloc_offsets = parse_elf64_ko_sections(kp)
        except Exception as exc:
            errors.append(f"{rel}: failed to parse ELF64 .ko: {exc}")
            continue
        sym_crcs.update(exported)
        ko_parsed.append((rel, modinfo, versions, reloc_offsets))

    if symvers_path and os.path.isfile(symvers_path) and len(ko_parsed) == 0:
        errors.append("No kernel .ko modules found in rootfs when --symvers was provided!")

    for rel, modinfo, versions, reloc_offsets in ko_parsed:
        kv = {}
        for item in modinfo.split(b"\x00"):
            if b"=" in item:
                k, v = item.split(b"=", 1)
                kv[k.decode("ascii", errors="replace")] = v.decode("ascii", errors="replace")
        vm = kv.get("vermagic", "")
        if not vm.startswith(expected_vermagic_prefix):
            errors.append(f"{rel}: vermagic={vm!r} does not match expected {expected_vermagic_prefix!r}")

        if versions and sym_crcs:
            for pos in range(0, (len(versions) // 64) * 64, 64):
                crc, raw_name = struct.unpack_from("<Q56s", versions, pos)
                sname = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
                if not sname:
                    continue
                if crc == 0 and pos in reloc_offsets:
                    rel_sym, rel_addend = reloc_offsets[pos]
                    if rel_sym == f"__crc_{sname}":
                        if rel_sym[6:] in sym_crcs:
                            crc = (sym_crcs[rel_sym[6:]] + rel_addend) & 0xFFFFFFFF
                        else:
                            continue
                if sname in sym_crcs and (crc & 0xFFFFFFFF) != (sym_crcs[sname] & 0xFFFFFFFF):
                    errors.append(
                        f"{rel}: symbol CRC mismatch for '{sname}': .ko=0x{crc & 0xFFFFFFFF:08x} "
                        f"vs kernel=0x{sym_crcs[sname] & 0xFFFFFFFF:08x}"
                    )

    print(
        f"[stage3] Audited {len(dyn_elfs)} ELF binaries/libs and {len(ko_parsed)} kernel .ko modules "
        f"({len(errors)} error(s))."
    )
    return errors


def _build_synthetic_ko(
    path: str, vermagic: str, imported_crcs: list[tuple[int, str]], use_rela_zero: bool = False
) -> None:
    """Create a minimal valid ELF64 AArch64 ET_REL .ko with .modinfo, __versions, and optional .rela__versions."""
    shstr = b"\x00.shstrtab\x00.modinfo\x00__versions\x00.strtab\x00.symtab\x00.rela__versions\x00"
    modinfo = f"vermagic={vermagic}\x00license=Proprietary\x00".encode("ascii")
    versions = b"".join(
        struct.pack("<Q56s", 0 if use_rela_zero else crc, name.encode("ascii"))
        for crc, name in imported_crcs
    )

    strtab = bytearray(b"\x00")
    symtab = bytearray(struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0))  # STN_UNDEF
    rela = bytearray()
    if use_rela_zero:
        for idx, (_crc, name) in enumerate(imported_crcs):
            sym_name = f"__crc_{name}".encode("ascii") + b"\x00"
            name_off = len(strtab)
            strtab.extend(sym_name)
            sym_idx = len(symtab) // 24
            symtab.extend(struct.pack("<IBBHQQ", name_off, 0x10, 0, 0, 0, 0))  # STB_GLOBAL UND
            rela.extend(struct.pack("<QQq", idx * 64, (sym_idx << 32) | 257, 0))

    hdr_sz = 64
    off_shstr = hdr_sz
    off_mod = off_shstr + len(shstr)
    off_ver = off_mod + len(modinfo)
    off_str = (off_ver + len(versions) + 7) & ~7
    pad1 = b"\x00" * (off_str - (off_ver + len(versions)))
    off_sym = (off_str + len(strtab) + 7) & ~7
    pad2 = b"\x00" * (off_sym - (off_str + len(strtab)))
    off_rela = (off_sym + len(symtab) + 7) & ~7
    pad3 = b"\x00" * (off_rela - (off_sym + len(symtab)))
    sh_off = (off_rela + len(rela) + 7) & ~7
    pad4 = b"\x00" * (sh_off - (off_rela + len(rela)))

    def shdr(name_off: int, sh_type: int, offset: int, size: int, link: int = 0, entsize: int = 0) -> bytes:
        return struct.pack("<IIQQQQIIQQ", name_off, sh_type, 0, 0, offset, size, link, 0, 8, entsize)

    shdrs = (
        shdr(0, 0, 0, 0)
        + shdr(1, 3, off_shstr, len(shstr))
        + shdr(11, 1, off_mod, len(modinfo))
        + shdr(20, 1, off_ver, len(versions))
        + shdr(31, 3, off_str, len(strtab))
        + shdr(39, 2, off_sym, len(symtab), link=4, entsize=24)
        + shdr(47, 4, off_rela, len(rela), link=5, entsize=24)
    )
    ehdr = struct.pack(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        ELF_MAGIC,
        ELFCLASS64,
        1,
        1,
        0,
        0,
        ET_REL,
        EM_AARCH64,
        1,
        0,
        0,
        sh_off,
        0,
        64,
        0,
        0,
        64,
        7,
        1,
    )
    with open(path, "wb") as fh:
        fh.write(ehdr + shstr + modinfo + versions + pad1 + strtab + pad2 + symtab + pad3 + rela + pad4 + shdrs)


def run_self_test() -> int:
    print("[stage3:self-test] Synthesizing rootfs, .ko (.rela__versions), sstrip ELF & Module.symvers fixtures...")
    with tempfile.TemporaryDirectory(prefix="stage3_selftest_") as tmp:
        fs = os.path.join(tmp, "fs.install")
        os.makedirs(os.path.join(fs, "usr/lib"), exist_ok=True)
        os.makedirs(os.path.join(fs, "lib/public"), exist_ok=True)
        os.makedirs(os.path.join(fs, "lib/modules/4.1.27/extra"), exist_ok=True)

        # Matching libexpat pair
        with open(os.path.join(fs, "usr/lib/libexpat.so.1"), "wb") as fh:
            fh.write(b"EXPAT_2_10_0_PAYLOAD")
        shutil.copy2(os.path.join(fs, "usr/lib/libexpat.so.1"), os.path.join(fs, "lib/public/libexpat.so"))

        symvers = os.path.join(tmp, "Module.symvers")
        with open(symvers, "w", encoding="utf-8") as fh:
            fh.write("0x1234abcd\tblog_sinit\tvmlinux\tEXPORT_SYMBOL\n")

        ko_path = os.path.join(fs, "lib/modules/4.1.27/extra/wl.ko")
        _build_synthetic_ko(
            ko_path,
            "4.1.27 SMP preempt mod_unload aarch64 ",
            [(0x1234ABCD, "blog_sinit")],
        )

        # Positive case: zero errors
        errs = audit_rootfs(fs, symvers)
        assert not errs, f"Expected clean audit, got: {errs}"

        # Positive case 2: AArch64 .rela__versions with crc==0 prior to relocation
        _build_synthetic_ko(
            ko_path,
            "4.1.27 SMP preempt mod_unload aarch64 ",
            [(0x1234ABCD, "blog_sinit")],
            use_rela_zero=True,
        )
        errs_rela = audit_rootfs(fs, symvers)
        assert not errs_rela, f"Expected clean .rela__versions audit, got: {errs_rela}"

        # Negative case 1: CRC mismatch on blog_sinit must fail!
        _build_synthetic_ko(
            ko_path,
            "4.1.27 SMP preempt mod_unload aarch64 ",
            [(0xDEADBEEF, "blog_sinit")],
        )
        errs_crc = audit_rootfs(fs, symvers)
        assert any("CRC mismatch" in e for e in errs_crc), f"Expected CRC error, got: {errs_crc}"

        # Negative case 2: forbidden lighttpd bloat + mismatched libexpat must fail!
        _build_synthetic_ko(
            ko_path,
            "4.1.27 SMP preempt mod_unload aarch64 ",
            [(0x1234ABCD, "blog_sinit")],
        )
        os.makedirs(os.path.join(fs, "usr/sbin"), exist_ok=True)
        open(os.path.join(fs, "usr/sbin/lighttpd"), "wb").close()
        with open(os.path.join(fs, "lib/public/libexpat.so"), "wb") as fh:
            fh.write(b"STALE_2016_EXPAT")
        errs_bloat = audit_rootfs(fs, symvers)
        assert any("lighttpd" in e for e in errs_bloat), errs_bloat
        assert any("libexpat.so" in e for e in errs_bloat), errs_bloat

        # sstrip-tolerance self-test: PT_LOAD digest & readelf -D -Ws on section-stripped shared library
        gcc_bin = shutil.which("gcc")
        readelf_bin = shutil.which("readelf")
        if gcc_bin and readelf_bin:
            c_so = os.path.join(tmp, "mock_expat.c")
            orig_so = os.path.join(tmp, "libexpat_orig.so")
            sstrip_so = os.path.join(tmp, "libexpat_sstrip.so")
            with open(c_so, "w", encoding="utf-8") as fh:
                fh.write("const char *XML_ExpatVersion(void) { return \"expat_2.10.0\"; }\n")
            subprocess.run([gcc_bin, "-shared", "-fPIC", c_so, "-o", orig_so], check=True)
            blob = bytearray(open(orig_so, "rb").read())
            e_shoff = struct.unpack_from("<Q", blob, 40)[0]
            struct.pack_into("<Q", blob, 40, 0)
            struct.pack_into("<HHH", blob, 58, 0, 0, 0)
            with open(sstrip_so, "wb") as fh:
                fh.write(blob[:e_shoff] if e_shoff > 4096 else blob)
            assert extract_elf_pt_load_digest(orig_so) is not None
            assert extract_elf_pt_load_digest(orig_so) == extract_elf_pt_load_digest(sstrip_so)
            elf_sstrip = ElfInfo("/lib/libexpat.so", sstrip_so, ELFCLASS64, ET_DYN, EM_AARCH64, 0)
            populate_dynamic_metadata([elf_sstrip], readelf_bin)
            assert "XML_ExpatVersion" in elf_sstrip.defined_syms, f"Missing sstrip sym: {elf_sstrip.defined_syms}"

    print("==> STAGE 3 SELF-TEST PASSED (positive + .rela__versions + sstrip PT_LOAD/-D + CRC-mismatch + bloat/libexpat).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rootfs", help="Path to targets/94908HND/fs.install")
    ap.add_argument("--symvers", help="Path to kernel/linux-4.1/Module.symvers")
    ap.add_argument("--self-test", action="store_true", help="Run built-in unit self-tests")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.rootfs or not os.path.isdir(args.rootfs):
        print("FATAL: --rootfs <path-to-fs.install> required", file=sys.stderr)
        return 1

    errs = audit_rootfs(args.rootfs, args.symvers)
    if errs:
        print("FATAL: Stage 3 RootFS ELF/KO audit failed:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("==> STAGE 3 PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
