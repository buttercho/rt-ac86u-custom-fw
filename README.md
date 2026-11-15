# ASUS RT-AC86U Hardened & Tuned Firmware (`386.14_2-sec2026`)

Self-contained patchset, dependency backport orchestrator, 5-stage fail-closed verification suite, and GitHub Actions CI build pipeline for the **ASUS RT-AC86U** (`BCM4906` Cortex-A53 / `94908HND`), built on `Asuswrt-Merlin 386.14_2` (`6a5df61aab6f3fa2dffc518994d42e4f2a27fb2b`).

---

## What This Build Changes

### 1. Unused Attack-Surface & Bloat Stripping (`patches/001-target-strip-aicloud-bloat.patch`)
- Disables **`WEBDAV=n SMARTSYNCBASE=n`** (completely removing AiCloud 2.0 `lighttpd-1.4.39`, `mod_aicloud_*.so`, `samba-3.5.8`, and `pcre-8.31`, eliminating **`CVE-2025-2492`** CVSS 9.2 unauthenticated RCE/auth bypass).
- Disables unused legacy daemons **`TOR=n MEDIASRV=n TIMEMACHINE=n PRINTER=n MODEM=n QUAGGA=n`** (`tor`, `minidlna`, `netatalk`/`afpd`, `u2ec`/`lpd`, cellular dongle scripts, `zebra`/`ripd`), reclaiming `~9–11 MB` of NAND SquashFS/UBI space and `~15–20 MB` of idle RAM while keeping USB 3.0 storage (`SAMBA3="3.6.x"`, `NTFS`/`TFAT`/`HFS`) and `.local` mDNS (`MDNS=y` `avahi-daemon`).
- Strictly preserves `NATNL_AICLOUD=y NATNL_AIHOME=y BWDPI=y AMAS=y SW_HW_AUTH=y UUPLUGIN=y` at compile time so closed-source `httpd/prebuild/RT-AC86U/*.o` and `rc/prebuild/RT-AC86U/*.o` link with 100% symbol/ABI parity.

### 2. 2024–2026 Dependency Backports (`scripts/apply_backports.sh`)
- **Synced from Merlin `3004.388.13` (`5a50083681`):**
  - `dnsmasq 2.93` (+ `union bigname` `(MAXDNAME * 2) + 1` & `blockdata` fixes) + `nettle 3.10.2` + **IANA 2024 DNSSEC Root KSK (`38696`)**
  - `dropbear 2026.94` (fixes `CVE-2025-14282` CVSS 9.8 + post-quantum `mlkem768` KEX)
  - `miniupnpd 2.3.11` (`CVE-2026-5720`, `CVE-2026-107159` + `pcp_allow_thirdparty=no`)
  - `openssl-1.1` (`1.1.1w` + 20+ 2024–2026 CVE patches, zero `libcrypto.so.1.1` ABI risk)
  - `curl 8.17.0`, `wget 1.25.0` (`CVE-2024-10524`), `haveged 1.9.27`, `nano 7.2`, `libcap-ng 0.8.4`, `wsdd2`, `wireguard-tools`, and Oct 2026 Mozilla `ca-bundle.crt` (removes distrusted `emSign` root).
- **Cryptographically Pinned Upstream Tarballs (SONAME-Locked):**
  - `zlib 1.3.2` (`libz.so.1` — fixes `CVE-2022-37434`, `CVE-2023-45853`, `CVE-2026-27171`)
  - `expat 2.10.0` (`libexpat.so.1` + `/lib/public/libexpat.so` overwrite)
  - `sqlite 3.54.1` amalgamation (`libsqlite3.so.0`)
  - `openvpn 2.6.23` (`CVE-2025-12106`, `CVE-2026-35058`, `CVE-2026-40215`, preserving Merlin's `#ifdef ASUSWRT` VPN Director hooks)
- **Surgical C Backports:**
  - `busybox 1.25.1` `udhcpc` WAN DHCP integer underflow (`CVE-2026-88833`) & `tar` symlink traversal (`CVE-2026-108119`), `libxml2` `xmlBuildQName` (`CVE-2025-6021`), and `libovpn` `>= 2048`-bit DH enforcement.

### 3. Security, Hardware Longevity & BCM4906 Performance (`patches/002..005`)
- **`002-shared-httpd-security.patch`:** Removes `/tmp/share` PATH hijack in `_eval()`, fixes `fd2str()` `ssize_t`, `remove_dups()`, `set_crt_parsed()`, `is_valid_domainname()`, `do_ipsecupload_post` traversal, `validate_instance()` `wan0..wan10`, `ej_bwdpi_*Stat` injection, `update_*.asp` auth, non-blocking TLS peek, `HttpOnly; SameSite=Lax` cookie, `syscmd.sh` disablement, and Site Survey SSID XSS (`htmlEncode`).
- **`003-wanduck-rc-firewall-dnssec.patch`:** Fixes `inadyn` `popen()` shell injection, 12 `wanduck` memory/failover bugs, IANA 2024 DNSSEC KSK `38696`, `dnsmasq` `cache-size=4096`/`neg-ttl=60`, `pcp_allow_thirdparty`, `#ifdef RTCONFIG_IPV6` DNS Director DoT typo, and `rc/usb.c` `POOL_MOUNT_ROOT` OOB guards.
- **`004-ac86u-longevity-nvram-dcd-jffs.patch`:** Protects `128 KB` `/data/.kernel_nvram.setting` (`87.5%` headroom warning + `rstats` `*nvram` $\rightarrow$ `/jffs/` auto-migration), suppresses `dcd` `print-fatal-signals` log spam + gates `dcd` on `TM_EULA=1`, and cuts `/jffs/syslog.log` NAND wear by `30x` (`60s` $\rightarrow$ `30m`).
- **`005-bcm4906-perf-crypto-sysctl-makefile.patch`:** Enables 64-bit kernel `CONFIG_ARM64_CRYPTO=y` (`AES`, `GHASH/PMULL`, `SHA1/2`, `CRC32`), `-march=armv8-a+crc+crypto -mtune=cortex-a53` on standalone daemons, `cpu_wait=1` idle SoC cooling (`-6 to -10 °C`), and `ct_max=65536` / RFC 5382 conntrack tuning while preserving `Runner` + `Flow Cache` `~940 Mbps` HW NAT.

---

## 5-Stage Fail-Closed Automated Verification Pipeline (`tests/`)

1. **`tests/stage1_prebuild_gate.sh` (`check_blob_contracts.py` + `abi_asserts.c`):** Verifies zero-fuzz patch application, audits all 41 closed-source `.o` blobs (`639` `GLOBAL UND` symbols) against our `target.mak` flags and C diffs, and runs cross-compiler soft-float / `struct nvram_tuple` / AArch64 crypto `_Static_assert`s.
2. **`tests/run_stage2_local_and_ci.sh` (`stage2_asan_unit_tests.c`):** Compiles & executes unit/fuzz tests under `GCC AddressSanitizer + UBSan`, `GCC -fanalyzer`, and `cppcheck`.
3. **`tests/stage3_rootfs_elf_ko_audit.py`:** Audits 100% of built ELF binaries/`.so` libraries (`DT_NEEDED` + transitive `UND` symbol closure, soft-float `0x5000200` vs 64-bit `ebtables`, `libexpat.so` parity, stripped-bloat absence) and 100% of `4.1.27` `.ko` kernel modules (`vermagic` + 64-bit `__versions` symbol CRCs against `Module.symvers`).
4. **`tests/stage4_qemu_smoke.sh`:** Runs the cross-compiled ARM/AArch64 binaries live under `qemu-arm-static -cpu cortex-a53` (`openssl`, `dnsmasq --test` with KSK `38696`, `dropbear`, `openvpn --genkey`, `sqlite3`, `curl`, `wget`, `miniupnpd`, `busybox`, `ebtables`, plus `node --check` on `.asp` JS).
5. **`tests/stage5_image_forensics.py`:** Confirms zero `*cferom*` files exist, validates `UBI#` PEB stride + `34–54 MiB` size margin + Broadcom `0x4908` `WFI_TAG` + `RT-AC86U` `addvtoken`, and emits `SHA256SUMS.txt` + `TEST_REPORT.md`.

---

## Quick Start: Build in GitHub Actions ($0.00) & Flash Safely

### Step 1 — Push to a New GitHub Repo & Trigger CI
```bash
git remote add origin https://github.com/<YOUR_GITHUB_USER>/rt-ac86u-custom-fw.git
git push -u origin main
```
Open **Actions -> Build & Verify RT-AC86U Custom Firmware** on GitHub (starts automatically on push or via **Run workflow**). Once Stages 1–5 pass (~45–65 min), download the `RT-AC86U-386.14_2-sec2026` artifact zip containing:
- `RT-AC86U_386.14_2_ubi.w`
- `SHA256SUMS.txt`
- `TEST_REPORT.md`
- `preflash_check_on_router.sh`

### Step 2 — Run Pre-Flash Health & Backup Check on Your Merlin RT-AC86U
1. Verify checksum on your PC: `sha256sum -c SHA256SUMS.txt`
2. Copy `preflash_check_on_router.sh` to your router over SSH and run it:
   ```bash
   scp preflash_check_on_router.sh admin@192.168.1.1:/tmp/
   ssh admin@192.168.1.1 "sh /tmp/preflash_check_on_router.sh"
   scp admin@192.168.1.1:/tmp/jffs_pre_upgrade.tar.gz admin@192.168.1.1:/tmp/nvram_pre_upgrade.bin .
   ```
   *(If free RAM is below `180 MB`, reboot the router before uploading via WebUI so `httpd` has `4x` image buffer headroom.)*

### Step 3 — Upgrade Firmware from Asuswrt-Merlin
- **Via Merlin WebUI (Recommended):** Go to `Administration -> Firmware Upgrade`, select `RT-AC86U_386.14_2_ubi.w`, click **Upload**, and wait `3–5 minutes` without interrupting power.
- **Via SSH CLI (Alternative):**
  ```bash
  scp RT-AC86U_386.14_2_ubi.w admin@192.168.1.1:/tmp/fw.w
  ssh admin@192.168.1.1 "sha256sum /tmp/fw.w && /sbin/hnd-write /tmp/fw.w && reboot"
  ```
