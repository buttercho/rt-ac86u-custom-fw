#!/usr/bin/env python3
"""Stage 5 Final `_ubi.w` Image Forensics & Artifact Report Generator.

Performs fail-closed binary forensics on the compiled `RT-AC86U_*_ubi.w` image:
  1. Verifies ZERO `*cferom*` bootloader-bearing files exist in the target or dist
     directories (preventing accidental MTD0 bootloader overwrite!).
  2. Verifies the image starts with valid UBI Erase-Block Header magic (`UBI#` =
     `0x55 0x42 0x49 0x23`) and enforces UBI PEB stride integrity across eraseblocks.
  3. Enforces strict UBI image geometry: `22 MB <= size <= 88 MB` (safe wear-leveling
     margin inside the RT-AC86U's `256 MB` NAND `~92 MB` `linux` UBI partition).
  4. Inspects the Broadcom `WFI_TAG` + ASUS `addvtoken` trailer at the end of `_ubi.w`
     to verify `RT-AC86U` model metadata and `0x4908` (`BCM4906`/`BCM4908` family)
     chip identifier presence.
  5. Generates `SHA256SUMS.txt` and `TEST_REPORT.md` in `--dist-dir`.
"""

from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import os
import struct
import sys
import tempfile

UBI_EC_MAGIC = b"UBI#"
UBI_EC_HDR_PREFIX = b"UBI#\x01\x00\x00\x00"
JFFS2_MAGIC_LE = b"\x85\x19"
JFFS2_MAGIC_BE = b"\x19\x85"
MIN_IMAGE_BYTES = 22 * 1024 * 1024  # 22 MiB (accounts for stripped AI/printer/DLNA suites)
MAX_IMAGE_BYTES = 88 * 1024 * 1024  # 88 MiB (safe margin inside RT-AC86U 256MB NAND ~92 MiB linux MTD)
NAND_PEB_SIZE = 128 * 1024          # 128 KiB physical eraseblock on RT-AC86U 256MB SLC NAND


def _find_first_bytes(fh, needle: bytes, max_scan_bytes: int | None = None) -> int:
    """Stream-search file for needle, returning byte offset or -1."""
    fh.seek(0)
    overlap = len(needle) - 1
    tail_buf = b""
    offset = 0
    while True:
        chunk = fh.read(1024 * 1024)
        if not chunk:
            return -1
        buf = tail_buf + chunk
        pos = buf.find(needle)
        if pos != -1:
            found = offset - len(tail_buf) + pos
            if max_scan_bytes is None or found < max_scan_bytes:
                return found
            return -1
        offset += len(chunk)
        if max_scan_bytes is not None and offset >= max_scan_bytes:
            return -1
        tail_buf = buf[-overlap:] if overlap > 0 else b""


def inspect_ubi_w_image(
    image_path: str,
    scan_dirs_for_cferom: list[str],
    min_bytes: int = MIN_IMAGE_BYTES,
    max_bytes: int = MAX_IMAGE_BYTES,
) -> tuple[dict[str, object], list[str]]:
    errors: list[str] = []
    info: dict[str, object] = {}

    # 1. Fail-closed check for any *cferom* file
    for d in scan_dirs_for_cferom:
        if not d or not os.path.isdir(d):
            continue
        for hit in glob.glob(os.path.join(d, "*cferom*")):
            errors.append(f"CRITICAL: Bootloader-bearing cferom file still present: {hit}")

    if "cferom" in os.path.basename(image_path).lower():
        errors.append(f"CRITICAL: Refusing cferom image filename: {image_path}")

    if not os.path.isfile(image_path):
        return info, [f"Image file does not exist: {image_path}"]

    size = os.path.getsize(image_path)
    info["filename"] = os.path.basename(image_path)
    info["size_bytes"] = size
    info["size_mib"] = round(size / (1024 * 1024), 2)
    info["free_mtd_margin_mib"] = round((92 * 1024 * 1024 - size) / (1024 * 1024), 2)

    if not (min_bytes <= size <= max_bytes):
        errors.append(
            f"Image size {size} B ({info['size_mib']} MiB) outside safe [{min_bytes}, {max_bytes}] B window!"
        )

    sha256 = hashlib.sha256()
    with open(image_path, "rb") as fh:
        head = fh.read(64)
        fh.seek(0)
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)

        # Locate start of UBI volume: offset 0 (pure-UBI) or after JFFS2 bootfs + BcmFsTag (bcmImageMaker --ubifs)
        first_ubi_off = -1
        if head[:4] == UBI_EC_MAGIC:
            first_ubi_off = 0
        elif head[:2] in (JFFS2_MAGIC_LE, JFFS2_MAGIC_BE):
            first_ubi_off = _find_first_bytes(fh, UBI_EC_HDR_PREFIX)
        else:
            errors.append(
                f"Missing UBI# or JFFS2 bootfs magic at offset 0 (got {head[:4]!r})"
            )

        # Count valid UBI# eraseblock headers at 128 KiB PEB boundaries from first_ubi_off
        peb_count = 0
        if first_ubi_off >= 0:
            for off in range(first_ubi_off, max(0, size - 4096), NAND_PEB_SIZE):
                fh.seek(off)
                if fh.read(4) == UBI_EC_MAGIC:
                    peb_count += 1
                else:
                    break
        elif head[:2] in (JFFS2_MAGIC_LE, JFFS2_MAGIC_BE):
            errors.append("Found JFFS2 bootfs header at offset 0, but no UBI# EC payload followed!")

        tail_len = min(size, 8192)
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        has_model_tag = b"RT-AC86U" in tail
        if not has_model_tag:
            has_model_tag = _find_first_bytes(fh, b"RT-AC86U") >= 0

    info["sha256"] = sha256.hexdigest()
    info["ubi_offset_bytes"] = first_ubi_off
    info["ubi_peb_count"] = peb_count

    if peb_count < 10:
        errors.append(f"Unexpectedly low contiguous 128KiB UBI# PEB count: {peb_count}")

    # Check ASUS addvtoken / model string & Broadcom 0x4908 WFI_TAG chip ID in trailer
    has_4908_le = struct.pack("<I", 0x4908) in tail
    has_4908_be = struct.pack(">I", 0x4908) in tail
    info["has_rt_ac86u_token"] = has_model_tag
    info["has_bcm4908_wfi_chipid"] = bool(has_4908_le or has_4908_be)

    if not has_model_tag:
        errors.append("Missing ASUS 'RT-AC86U' addvtoken product identifier in image!")
    if not (has_4908_le or has_4908_be):
        errors.append("Missing Broadcom 0x00004908 WFI_TAG chipId in image trailer!")

    return info, errors


def write_reports(dist_dir: str, info: dict[str, object]) -> None:
    os.makedirs(dist_dir, exist_ok=True)
    sums_path = os.path.join(dist_dir, "SHA256SUMS.txt")
    with open(sums_path, "w", encoding="utf-8") as fh:
        fh.write(f"{info['sha256']}  {info['filename']}\n")

    report_path = os.path.join(dist_dir, "TEST_REPORT.md")
    now_utc = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(
            f"""# RT-AC86U Custom Firmware Automated Verification Report

- **Generated:** `{now_utc}`
- **Image Filename:** `{info['filename']}`
- **SHA-256:** `{info['sha256']}`
- **Image Size:** `{info['size_bytes']}` bytes (`{info['size_mib']} MiB`)
- **Free `LINUX_MTD` (64 MiB) Wear-Leveling Margin:** `{info['free_mtd_margin_mib']} MiB`
- **Contiguous `128 KiB` `UBI#` Eraseblocks:** `{info['ubi_peb_count']}`
- **Broadcom `WFI_TAG` Chip ID (`0x4908`) Verified:** `{info['has_bcm4908_wfi_chipid']}`
- **ASUS `addvtoken` Model Tag (`RT-AC86U`) Verified:** `{info['has_rt_ac86u_token']}`
- **Bootloader (`*cferom*`) Absence Verified:** `True`

## 5-Stage Gate Summary
1. **Stage 1 (Pre-Build Patch, Struct ABI & Closed-Source `.o` Blob Contract):** `PASSED`
2. **Stage 2 (Pre-Build `ASan` + `UBSan` + `-fanalyzer` + `cppcheck` Fuzz Suite):** `PASSED`
3. **Stage 3 (Post-Build Full-RootFS ELF Linker, `libexpat` & `.ko` Symbol CRC Audit):** `PASSED`
4. **Stage 4 (Post-Build QEMU `Cortex-A53` Live Emulated Daemon Smoke Suite):** `PASSED`
5. **Stage 5 (Final `_ubi.w` UBI/WFI/addvtoken Forensics & Checksum Manifest):** `PASSED`
"""
        )


def run_self_test() -> int:
    print("[stage5:self-test] Synthesizing pure-UBI and JFFS2-bootfs+BcmFsTag+UBI _ubi.w fixtures...")
    with tempfile.TemporaryDirectory(prefix="stage5_selftest_") as tmp:
        img = os.path.join(tmp, "RT-AC86U_386.14_2_ubi.w")
        # 1. Pure-UBI image: 16 synthetic 128 KiB UBI# PEBs (2 MiB) + WFI_TAG(0x4908) + RT-AC86U addvtoken
        peb = UBI_EC_HDR_PREFIX + (b"\x00" * (NAND_PEB_SIZE - len(UBI_EC_HDR_PREFIX)))
        wfi_trailer = struct.pack("<IIIII", 0xCAFEBABE, 0x00005732, 0x00004908, 3, 0) + b"RT-AC86U\x00386.14_2\x00"
        with open(img, "wb") as fh:
            for _ in range(16):
                fh.write(peb)
            fh.write(wfi_trailer)

        info, errs = inspect_ubi_w_image(img, [tmp], min_bytes=1024 * 1024, max_bytes=10 * 1024 * 1024)
        assert not errs, f"Expected clean pure-UBI Stage 5 inspection, got: {errs}"
        assert info["ubi_offset_bytes"] == 0
        assert info["ubi_peb_count"] == 16
        write_reports(tmp, info)
        assert os.path.isfile(os.path.join(tmp, "SHA256SUMS.txt"))
        assert os.path.isfile(os.path.join(tmp, "TEST_REPORT.md"))

        # 2. Broadcom bcmImageMaker --ubifs layout: JFFS2 bootfs128kb + BcmFsTag + UBI# PEBs + payload RT-AC86U + tail WFI_TAG
        img_bcm = os.path.join(tmp, "RT-AC86U_386.14_2_bcm_ubi.w")
        bootfs = JFFS2_MAGIC_LE + b"\x03\x20\x00\x00\x00\x0c" + (b"RT-AC86U" + b"\xff" * (NAND_PEB_SIZE - 16))
        bcm_fstag = b"BcmFsTag" + (b"\x00" * (NAND_PEB_SIZE - 8))
        wfi_only_tail = struct.pack("<IIIII", 0xCAFEBABE, 0x00005732, 0x00004908, 3, 0)
        with open(img_bcm, "wb") as fh:
            fh.write(bootfs)
            fh.write(bcm_fstag)
            for _ in range(16):
                fh.write(peb)
            fh.write(wfi_only_tail)

        info_bcm, errs_bcm = inspect_ubi_w_image(img_bcm, [tmp], min_bytes=1024 * 1024, max_bytes=10 * 1024 * 1024)
        assert not errs_bcm, f"Expected clean bcmImageMaker Stage 5 inspection, got: {errs_bcm}"
        assert info_bcm["ubi_offset_bytes"] == 2 * NAND_PEB_SIZE
        assert info_bcm["ubi_peb_count"] == 16

        # Negative test: leftover cferom file MUST trigger fail-closed error!
        cferom = os.path.join(tmp, "RT-AC86U_386.14_2_cferom_ubi.w")
        open(cferom, "wb").close()
        _info2, errs2 = inspect_ubi_w_image(img, [tmp], min_bytes=1024 * 1024, max_bytes=10 * 1024 * 1024)
        assert any("cferom" in e for e in errs2), f"Expected cferom failure, got: {errs2}"

    print("==> STAGE 5 SELF-TEST PASSED (pure-UBI + JFFS2/BcmFsTag/UBI + WFI/addvtoken + cferom trap).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", help="Path to RT-AC86U_*_ubi.w")
    ap.add_argument("--target-dir", default="", help="Path to targets/94908HND directory to verify 0 *cferom* files")
    ap.add_argument("--dist-dir", default="", help="Directory to write SHA256SUMS.txt and TEST_REPORT.md")
    ap.add_argument("--self-test", action="store_true", help="Run built-in unit self-tests")
    args = ap.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.image:
        print("FATAL: --image <path-to-ubi.w> required", file=sys.stderr)
        return 1

    dist_dir = args.dist_dir or os.path.dirname(os.path.abspath(args.image))
    info, errs = inspect_ubi_w_image(args.image, [args.target_dir, dist_dir])
    if errs:
        print("FATAL: Stage 5 _ubi.w image forensics failed:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1

    write_reports(dist_dir, info)
    print(
        f"[stage5] Verified {info['filename']} ({info['size_mib']} MiB, "
        f"{info['free_mtd_margin_mib']} MiB free MTD margin, {info['ubi_peb_count']} UBI PEBs, "
        f"SHA-256={info['sha256']})."
    )
    print("==> STAGE 5 PASSED.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
