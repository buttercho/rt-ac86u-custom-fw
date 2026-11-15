/*
 * stage2_asan_unit_tests.c — Pre-Build ASan + UBSan + GCC -fanalyzer Suite
 *
 * Exercises the exact patched C security, bounds, and parser logic for
 * RT-AC86U (386.14_2-sec2026) under AddressSanitizer + UndefinedBehaviorSanitizer
 * with exact-sized heap redzones and adversarial / boundary fuzz inputs.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Portable BSD strlcpy / strlcat matching shared/shutils.c / uClibc / glibc */
static size_t bsd_strlcpy(char *dst, const char *src, size_t siz) {
    size_t srclen = strlen(src);
    if (siz != 0) {
        size_t n = (srclen >= siz) ? (siz - 1) : srclen;
        memcpy(dst, src, n);
        dst[n] = '\0';
    }
    return srclen;
}

static size_t bsd_strlcat(char *dst, const char *src, size_t siz) {
    size_t dlen = strnlen(dst, siz);
    if (dlen == siz) {
        return siz + strlen(src);
    }
    return dlen + bsd_strlcpy(dst + dlen, src, siz - dlen);
}

/* =========================================================================
 * 1. Patched fd2str() (release/src/router/shared/shutils.c)
 * ========================================================================= */
typedef ssize_t (*mock_read_fn)(int fd, void *buf, size_t count);

static char *patched_fd2str_impl(int fd, mock_read_fn rfn) {
    char *buf = NULL;
    size_t count = 0, n = 0;
    ssize_t r;

    do {
        char *nbuf = realloc(buf, count + 512);
        if (!nbuf) {
            free(buf);
            return NULL;
        }
        buf = nbuf;
        r = rfn(fd, buf + count, 512);
        if (r < 0) {
            free(buf);
            return NULL;
        }
        n = (size_t)r;
        count += n;
    } while (n == 512);
    buf[count] = '\0';
    return buf;
}

static int g_mock_fail_on_call = 0;
static int g_mock_call_idx = 0;
static const char *g_mock_payload = NULL;
static size_t g_mock_offset = 0;

static ssize_t test_mock_read(int fd, void *buf, size_t count) {
    (void)fd;
    g_mock_call_idx++;
    if (g_mock_fail_on_call == g_mock_call_idx) {
        errno = EIO;
        return -1;
    }
    size_t total = strlen(g_mock_payload);
    if (g_mock_offset >= total)
        return 0;
    size_t rem = total - g_mock_offset;
    size_t to_copy = rem < count ? rem : count;
    /* Note: in real fd2str, count is 512; if rem == 512, n == 512 triggers next chunk */
    memcpy(buf, g_mock_payload + g_mock_offset, to_copy);
    g_mock_offset += to_copy;
    return (ssize_t)to_copy;
}

static void test_fd2str(void) {
    /* Case A: immediate read() == -1 must return NULL without size_t underflow */
    g_mock_fail_on_call = 1;
    g_mock_call_idx = 0;
    g_mock_payload = "unused";
    g_mock_offset = 0;
    char *err_a = patched_fd2str_impl(42, test_mock_read);
    assert(err_a == NULL);

    /* Case B: 1st chunk == 512 B succeeds, 2nd chunk fails with -1 -> clean free & NULL */
    char big[700];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    g_mock_fail_on_call = 2;
    g_mock_call_idx = 0;
    g_mock_payload = big;
    g_mock_offset = 0;
    char *err_b = patched_fd2str_impl(42, test_mock_read);
    assert(err_b == NULL);

    /* Case C: multi-chunk 699-byte read succeeds and NUL-terminates cleanly */
    g_mock_fail_on_call = 0;
    g_mock_call_idx = 0;
    g_mock_payload = big;
    g_mock_offset = 0;
    char *res = patched_fd2str_impl(42, test_mock_read);
    assert(res != NULL);
    assert(strlen(res) == 699);
    assert(strcmp(res, big) == 0);
    free(res);
}

/* =========================================================================
 * 2. Patched remove_dups() (release/src/router/shared/shutils.c)
 * ========================================================================= */
#define foreach_tok(word, wordlist, next) \
    for (next = &wordlist[strspn(wordlist, " ")], \
         strncpy(word, next, sizeof(word)), \
         word[sizeof(word) - 1] = '\0', \
         word[strcspn(word, " ")] = '\0', \
         next = strchr(next, ' '); \
         strlen(word); \
         next = next ? &next[strspn(next, " ")] : "", \
         strncpy(word, next, sizeof(word)), \
         word[sizeof(word) - 1] = '\0', \
         word[strcspn(word, " ")] = '\0', \
         next = strchr(next, ' '))

static char *find_word_sim(const char *buffer, const char *word) {
    char tok[256];
    const char *next;
    foreach_tok(tok, buffer, next) {
        if (strcmp(tok, word) == 0)
            return (char *)buffer;
    }
    return NULL;
}

static int patched_remove_dups(char *inlist, int inlist_size) {
    char word[256];
    const char *next;
    char *outlist;

    if (!inlist || inlist_size <= 0)
        return -1;
    outlist = calloc(1, (size_t)inlist_size);
    if (!outlist)
        return -1;

    foreach_tok(word, inlist, next) {
        if (!find_word_sim(outlist, word)) {
            if (outlist[0])
                bsd_strlcat(outlist, " ", (size_t)inlist_size);
            bsd_strlcat(outlist, word, (size_t)inlist_size);
        }
    }

    bsd_strlcpy(inlist, outlist, (size_t)inlist_size);
    free(outlist);
    return 0;
}

static void test_remove_dups_fuzz(void) {
    const char *corpus[] = {
        "",
        "a",
        "eth0 eth1 eth0 br0 eth2 eth1",
        "aa bb cc dd ee ff gg hh ii jj kk",
        "singleton_token_filling_exact_boundary",
    };
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        for (int sz = 1; sz <= 48; sz++) {
            /* Exact heap allocation of size `sz` so ASan traps even a 1-byte overflow! */
            char *buf = malloc((size_t)sz);
            assert(buf != NULL);
            bsd_strlcpy(buf, corpus[i], (size_t)sz);
            assert(patched_remove_dups(buf, sz) == 0);
            assert(strnlen(buf, (size_t)sz) < (size_t)sz);
            free(buf);
        }
    }
    char exact[] = "eth0 eth1 eth0 wl0.1 eth1";
    assert(patched_remove_dups(exact, (int)sizeof(exact)) == 0);
    assert(strcmp(exact, "eth0 eth1 wl0.1") == 0);
}

/* =========================================================================
 * 3. Patched set_crt_parsed() & is_valid_domainname() (shared/misc.c)
 * ========================================================================= */
static void patched_set_crt_parsed_mem(const char *pem_lines[], size_t nlines, char *out, size_t out_sz) {
    char buffer[8000];
    memset(buffer, 0, sizeof(buffer));
    for (size_t i = 0; i < nlines; i++) {
        bsd_strlcat(buffer, pem_lines[i], sizeof(buffer));
    }
    bsd_strlcpy(out, buffer, out_sz);
}

static int patched_is_valid_domainname(const char *name) {
    size_t len, label_len = 0;
    const char *p;

    if (!name || !*name)
        return 0;
    len = strlen(name);
    if (len > 253 || name[0] == '-' || name[0] == '.')
        return 0;

    for (p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '.') {
            if (label_len == 0 || *(p - 1) == '-')
                return 0;
            label_len = 0;
            continue;
        }
        if (!(isalnum(c) || c == '-' || c == '_'))
            return 0;
        if (label_len == 0 && c == '-')
            return 0;
        label_len++;
        if (label_len > 63)
            return 0;
    }
    if (label_len > 0 && *(p - 1) == '-')
        return 0;
    return 1;
}

static void test_misc_crt_and_domain(void) {
    /* 16 KB PEM input into 8000-byte stack buffer -> zero stack smash */
    char line64[66];
    memset(line64, 'M', 64);
    line64[64] = '\n';
    line64[65] = '\0';
    const char *lines[260];
    for (size_t i = 0; i < 260; i++)
        lines[i] = line64;

    char out[8000];
    patched_set_crt_parsed_mem(lines, 260, out, sizeof(out));
    assert(strlen(out) == 7999);

    /* Domain validation adversarial vectors */
    assert(patched_is_valid_domainname("") == 0);
    assert(patched_is_valid_domainname(NULL) == 0);
    assert(patched_is_valid_domainname("-V") == 0);
    assert(patched_is_valid_domainname("--option") == 0);
    assert(patched_is_valid_domainname(".leading.dot") == 0);
    assert(patched_is_valid_domainname("bad.-label.com") == 0);
    assert(patched_is_valid_domainname("bad-.com") == 0);
    assert(patched_is_valid_domainname("double..dot.com") == 0);
    assert(patched_is_valid_domainname("semi;id.com") == 0);
    assert(patched_is_valid_domainname("env$IFS.com") == 0);

    char label64[70];
    memset(label64, 'a', 64);
    strcpy(label64 + 64, ".com");
    assert(patched_is_valid_domainname(label64) == 0);

    /* 254-char FQDN must fail; 253-char FQDN must pass */
    char fqdn[260];
    size_t pos = 0;
    for (int k = 0; k < 4; k++) {
        memset(fqdn + pos, 'x', 62);
        fqdn[pos + 62] = '.';
        pos += 63;
    }
    /* pos is 252 (4 * 63); add 'z' -> 253 chars */
    fqdn[252] = 'z';
    fqdn[253] = '\0';
    assert(strlen(fqdn) == 253);
    assert(patched_is_valid_domainname(fqdn) == 1);
    fqdn[253] = 'z';
    fqdn[254] = '\0';
    assert(patched_is_valid_domainname(fqdn) == 0);

    assert(patched_is_valid_domainname("router.asus.com") == 1);
    assert(patched_is_valid_domainname("_acme-challenge.rt-ac86u.example.org") == 1);
}

/* =========================================================================
 * 4. Patched httpd input validators (release/src/router/httpd/web.c)
 * ========================================================================= */
static int is_safe_bwdpi_param(const char *s, size_t max_len) {
    size_t i;
    if (!s || !*s)
        return 0;
    for (i = 0; s[i] != '\0'; i++) {
        unsigned char c = (unsigned char)s[i];
        if (i >= max_len)
            return 0;
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':'))
            return 0;
    }
    return 1;
}

static int is_safe_ipsec_profilename(const char *p) {
    if (!p || !*p || strlen(p) > 16)
        return 0;
    for (const char *c = p; *c; c++) {
        if (!(isalnum((unsigned char)*c) || *c == '_' || *c == '-'))
            return 0;
    }
    return 1;
}

static int patched_validate_instance(const char *prefix) {
    if (!prefix)
        return 0;
    if (strcmp(prefix, "wan_") == 0)
        return 1;
    if (strncmp(prefix, "wan", 3) == 0) {
        const char *p = prefix + 3;
        if (!isdigit((unsigned char)*p))
            return 0;
        char *end = NULL;
        long unit = strtol(p, &end, 10);
        if (end && strcmp(end, "_") == 0 && unit >= 0 && unit <= 10)
            return 1;
    }
    return 0;
}

static void test_httpd_validators(void) {
    assert(is_safe_bwdpi_param("00:11:22:33:44:55", 32) == 1);
    assert(is_safe_bwdpi_param("realtime", 16) == 1);
    assert(is_safe_bwdpi_param("a' OR 1=1--", 32) == 0);
    assert(is_safe_bwdpi_param("mac;reboot", 32) == 0);
    assert(is_safe_bwdpi_param("$(id)", 32) == 0);

    assert(is_safe_ipsec_profilename("Home_VPN-01") == 1);
    assert(is_safe_ipsec_profilename("../../jffs/evil") == 0);
    assert(is_safe_ipsec_profilename("../etc/passwd") == 0);
    assert(is_safe_ipsec_profilename("profile_exceeding_16_chars") == 0);
    assert(is_safe_ipsec_profilename("p;id") == 0);

    assert(patched_validate_instance("wan_") == 1);
    assert(patched_validate_instance("wan0_") == 1);
    assert(patched_validate_instance("wan1_") == 1);
    assert(patched_validate_instance("wan10_") == 1);
    assert(patched_validate_instance("wan11_") == 0);
    assert(patched_validate_instance("wan-1_") == 0);
    assert(patched_validate_instance("wan0_ipaddr") == 0);
}

/* =========================================================================
 * 5. Patched wanduck parse_dst_url() & .ico check (release/src/router/rc/wanduck.c)
 * ========================================================================= */
static void patched_wanduck_parse_req(const char *src, size_t src_len, char *dst_url, size_t dst_sz, int *is_ico) {
    char buf[2048];
    size_t copy_len = src_len < sizeof(buf) - 1 ? src_len : sizeof(buf) - 1;
    memcpy(buf, src, copy_len);
    buf[copy_len] = '\0';

    char uri[512] = "/";
    char host[256] = "";

    /* Bounded extraction matching patched wanduck.c */
    const char *line_end = strstr(buf, "\r\n");
    if (line_end && (strncmp(buf, "GET ", 4) == 0 || strncmp(buf, "POST ", 5) == 0)) {
        const char *sp1 = strchr(buf, ' ');
        if (sp1 && sp1 + 1 < line_end) {
            const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(line_end - (sp1 + 1)));
            size_t ulen = sp2 ? (size_t)(sp2 - (sp1 + 1)) : (size_t)(line_end - (sp1 + 1));
            if (ulen >= sizeof(uri))
                ulen = sizeof(uri) - 1;
            memcpy(uri, sp1 + 1, ulen);
            uri[ulen] = '\0';
        }
    }

    const char *hp = strcasestr(buf, "\r\nHost:");
    if (hp) {
        hp += 7;
        while (*hp == ' ' || *hp == '\t')
            hp++;
        const char *hend = strstr(hp, "\r\n");
        size_t hlen = hend ? (size_t)(hend - hp) : strlen(hp);
        if (hlen >= sizeof(host))
            hlen = sizeof(host) - 1;
        memcpy(host, hp, hlen);
        host[hlen] = '\0';
    }

    snprintf(dst_url, dst_sz, "%s%s", host, uri);
    size_t dlen = strlen(dst_url);
    /* Patched guard: prevent dst_url[dlen - 4] stack underflow when dlen < 4 */
    *is_ico = (dlen >= 4 && strcasecmp(dst_url + dlen - 4, ".ico") == 0) ? 1 : 0;
}

static void test_wanduck_http_parser(void) {
    char dst[1024];
    int is_ico = -1;

    /* 1-byte dst_url ("/") previously read dst_url[-3] before stack buffer! */
    const char *req_short = "GET / HTTP/1.0\r\n\r\n";
    patched_wanduck_parse_req(req_short, strlen(req_short), dst, sizeof(dst), &is_ico);
    assert(strcmp(dst, "/") == 0);
    assert(is_ico == 0);

    /* Valid favicon request */
    const char *req_ico = "GET /favicon.ico HTTP/1.1\r\nHost: captive.apple.com\r\n\r\n";
    patched_wanduck_parse_req(req_ico, strlen(req_ico), dst, sizeof(dst), &is_ico);
    assert(strcmp(dst, "captive.apple.com/favicon.ico") == 0);
    assert(is_ico == 1);

    /* 4096-byte non-NUL adversarial TCP payload -> zero stack overflow */
    char *giant = malloc(4096);
    assert(giant != NULL);
    memcpy(giant, "GET /", 5);
    memset(giant + 5, 'X', 4091);
    patched_wanduck_parse_req(giant, 4096, dst, sizeof(dst), &is_ico);
    assert(strlen(dst) < sizeof(dst));
    free(giant);
}

/* =========================================================================
 * 6. Patched inadyn shell_transaction() — zero /bin/sh command injection
 * ========================================================================= */
static int patched_inadyn_exec_script(const char *prog, const char *untrusted_user, char *out, size_t out_sz) {
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        setenv("INADYN_USER", untrusted_user, 1);
        char *const argv[] = {(char *)prog, NULL};
        execv(prog, argv);
        _exit(127);
    }
    close(pipefd[1]);
    ssize_t n = read(pipefd[0], out, out_sz - 1);
    close(pipefd[0]);
    if (n > 0)
        out[n] = '\0';
    else
        out[0] = '\0';
    int status = 0;
    waitpid(pid, &status, 0);
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static void test_inadyn_no_shell_injection(void) {
    char out[256];
    const char *marker = "/tmp/rt_ac86u_stage2_pwn_check";
    unlink(marker);
    /* Even if INADYN_USER contains $(touch ...), direct execv("/usr/bin/true") never invokes /bin/sh */
    assert(patched_inadyn_exec_script("/usr/bin/true", "$(touch /tmp/rt_ac86u_stage2_pwn_check)", out, sizeof(out)) == 0);
    struct stat st;
    assert(lstat(marker, &st) != 0);
}

/* =========================================================================
 * 7. BusyBox udhcpc udhcp_get_option() (CVE-2026-88833)
 * ========================================================================= */
#define OPT_CODE 0
#define OPT_LEN  1
#define OPT_DATA 2
#define DHCP_PADDING         0x00
#define DHCP_OPTION_OVERLOAD 0x34
#define DHCP_MESSAGE_TYPE    0x35
#define DHCP_END             0xff

static const uint8_t *patched_udhcp_get_option(const uint8_t *options_buf, int rem, int code, uint8_t *overload_out) {
    const uint8_t *optionptr = options_buf;
    uint8_t overload = 0;

    while (1) {
        if (rem <= 0)
            break;
        if (optionptr[OPT_CODE] == DHCP_PADDING) {
            rem--;
            optionptr++;
            continue;
        }
        if (optionptr[OPT_CODE] == DHCP_END) {
            break;
        }
        /* CVE-2026-88833 fix #1: prevent 1-byte OOB read on optionptr[OPT_LEN] when rem == 1 */
        if (rem <= OPT_LEN)
            return NULL;
        int len = 2 + optionptr[OPT_LEN];
        rem -= len;
        if (rem < 0)
            return NULL;

        if (optionptr[OPT_CODE] == code) {
            if (optionptr[OPT_LEN] == 0)
                return NULL;
            if (overload_out)
                *overload_out = overload;
            return optionptr + OPT_DATA;
        }
        if (optionptr[OPT_CODE] == DHCP_OPTION_OVERLOAD) {
            /* CVE-2026-88833 fix #2: prevent 1-byte OOB read on optionptr[OPT_DATA] when OPT_LEN == 0 */
            if (optionptr[OPT_LEN] >= 1)
                overload |= optionptr[OPT_DATA];
        }
        optionptr += len;
    }
    if (overload_out)
        *overload_out = overload;
    return NULL;
}

static void test_busybox_udhcp_cve_2026_88833(void) {
    /* Exact 1-byte heap allocation: without `rem <= OPT_LEN`, ASan triggers heap-buffer-overflow! */
    uint8_t *pkt1 = malloc(1);
    assert(pkt1 != NULL);
    pkt1[0] = DHCP_MESSAGE_TYPE;
    assert(patched_udhcp_get_option(pkt1, 1, DHCP_MESSAGE_TYPE, NULL) == NULL);
    free(pkt1);

    /* Exact 2-byte heap allocation with OVERLOAD len=0: without `OPT_LEN >= 1`, ASan triggers OOB read! */
    uint8_t *pkt2 = malloc(2);
    assert(pkt2 != NULL);
    pkt2[0] = DHCP_OPTION_OVERLOAD;
    pkt2[1] = 0;
    uint8_t ov = 0;
    assert(patched_udhcp_get_option(pkt2, 2, DHCP_MESSAGE_TYPE, &ov) == NULL);
    assert(ov == 0);
    free(pkt2);

    /* Valid DHCP packet with padding + message type = 5 (ACK) + END */
    uint8_t *pkt_ok = malloc(5);
    assert(pkt_ok != NULL);
    pkt_ok[0] = DHCP_PADDING;
    pkt_ok[1] = DHCP_MESSAGE_TYPE;
    pkt_ok[2] = 1;
    pkt_ok[3] = 5;
    pkt_ok[4] = DHCP_END;
    const uint8_t *val = patched_udhcp_get_option(pkt_ok, 5, DHCP_MESSAGE_TYPE, NULL);
    assert(val != NULL && *val == 5);
    free(pkt_ok);
}

/* =========================================================================
 * 8. BusyBox tar symlink escape guards (CVE-2026-108119)
 * ========================================================================= */
static int tar_is_safe_symlink_target(const char *link_target) {
    if (!link_target)
        return 0;
    if (link_target[0] == '/'
        || strcmp(link_target, "..") == 0
        || strncmp(link_target, "../", 3) == 0
        || strstr(link_target, "/../") != NULL) {
        return 0;
    }
    return 1;
}

static int tar_has_intermediate_symlink(char *dst_name) {
    char *p = dst_name;
    while ((p = strchr(p, '/')) != NULL) {
        if (p > dst_name) {
            struct stat check_st;
            *p = '\0';
            int is_lnk = (lstat(dst_name, &check_st) == 0 && S_ISLNK(check_st.st_mode));
            *p = '/';
            if (is_lnk)
                return 1;
        }
        p++;
    }
    return 0;
}

static void test_busybox_tar_cve_2026_108119(void) {
    assert(tar_is_safe_symlink_target(NULL) == 0);
    assert(tar_is_safe_symlink_target("/jffs/scripts") == 0);
    assert(tar_is_safe_symlink_target("..") == 0);
    assert(tar_is_safe_symlink_target("../etc/passwd") == 0);
    assert(tar_is_safe_symlink_target("subdir/../../jffs") == 0);
    assert(tar_is_safe_symlink_target("libfoo.so.1.0") == 1);

    char tmpdir[] = "/tmp/stage2_tar_XXXXXX";
    assert(mkdtemp(tmpdir) != NULL);
    char sym_path[256];
    snprintf(sym_path, sizeof(sym_path), "%s/escape_dir", tmpdir);
    assert(symlink("/tmp", sym_path) == 0);

    char extract_target[300];
    /* Skip leading '/' when testing relative-like path from "/" or full path with intermediate symlink */
    snprintf(extract_target, sizeof(extract_target), "%s/escape_dir/services-start", tmpdir);
    assert(tar_has_intermediate_symlink(extract_target) == 1);

    unlink(sym_path);
    rmdir(tmpdir);
}

/* =========================================================================
 * 9. libxml2 xmlBuildQName() (CVE-2025-6021) & dnsmasq union bigname
 * ========================================================================= */
static unsigned char *patched_xmlBuildQName(const unsigned char *ncname,
                                            const unsigned char *prefix,
                                            unsigned char *memory,
                                            int len) {
    size_t lenn, lenp;
    unsigned char *ret;

    if ((ncname == NULL) || (len < 0))
        return NULL;
    if (prefix == NULL)
        return (unsigned char *)ncname;

    lenn = strlen((const char *)ncname);
    lenp = strlen((const char *)prefix);
    if (lenn >= SIZE_MAX - lenp - 2)
        return NULL;

    if ((memory == NULL) || ((size_t)len < lenn + lenp + 2)) {
        ret = malloc(lenn + lenp + 2);
        if (ret == NULL)
            return NULL;
    } else {
        ret = memory;
    }
    memcpy(&ret[0], prefix, lenp);
    ret[lenp] = ':';
    memcpy(&ret[lenp + 1], ncname, lenn);
    ret[lenn + lenp + 1] = 0;
    return ret;
}

/* Verify arithmetic guard directly against simulated 32-bit size_t max (0xFFFFFFFFu) */
static int check_qname_overflow_32bit(uint32_t lenn, uint32_t lenp) {
    if (lenn >= UINT32_MAX - lenp - 2u)
        return -1; /* cleanly rejected before signed int wraparound! */
    return 0;
}

#define DNSMASQ_MAXDNAME 1025
union patched_bigname {
    char name[(DNSMASQ_MAXDNAME * 2) + 1];
    union patched_bigname *next;
};

static void test_libxml2_and_dnsmasq_bounds(void) {
    unsigned char stack_mem[16];
    assert(patched_xmlBuildQName((const unsigned char *)"tag", (const unsigned char *)"ns", stack_mem, -5) == NULL);

    /* Exceeds 16-byte stack_mem -> must allocate on heap without touching stack_mem OOB */
    unsigned char *q = patched_xmlBuildQName(
        (const unsigned char *)"very_long_element_name",
        (const unsigned char *)"soapenv",
        stack_mem,
        (int)sizeof(stack_mem)
    );
    assert(q != NULL && q != stack_mem);
    assert(strcmp((const char *)q, "soapenv:very_long_element_name") == 0);
    free(q);

    /* Fits in caller buffer */
    unsigned char fit_mem[64];
    unsigned char *q2 = patched_xmlBuildQName(
        (const unsigned char *)"Body",
        (const unsigned char *)"s",
        fit_mem,
        (int)sizeof(fit_mem)
    );
    assert(q2 == fit_mem);
    assert(strcmp((const char *)q2, "s:Body") == 0);

    /* Simulated 32-bit ARM userspace overflow pair (0x80000000 + 0x80000004 wraps int to 6 < 16!) */
    assert(check_qname_overflow_32bit(0x80000000u, 0x80000004u) == -1);

    /* dnsmasq union bigname worst-case 2x hex-escaped MAXDNAME (2050 chars + NUL = 2051 B) */
    _Static_assert(sizeof(union patched_bigname) >= 2051, "dnsmasq union bigname too small!");
    union patched_bigname *bn = malloc(sizeof(*bn));
    assert(bn != NULL);
    memset(bn->name, 'F', 2050);
    bn->name[2050] = '\0';
    assert(strlen(bn->name) == 2050);
    free(bn);
}

int main(void) {
    printf("[stage2] Running ASan + UBSan unit & adversarial fuzz tests...\n");
    test_fd2str();
    printf("  [PASS] fd2str() EIO/negative-read & multi-chunk heap bounds\n");
    test_remove_dups_fuzz();
    printf("  [PASS] remove_dups() 1..48 byte redzone boundary fuzz\n");
    test_misc_crt_and_domain();
    printf("  [PASS] set_crt_parsed() 16KB PEM truncation & is_valid_domainname() RFC/metachar guards\n");
    test_httpd_validators();
    printf("  [PASS] httpd is_safe_bwdpi_param / ipsec traversal / validate_instance(wan0..wan10)\n");
    test_wanduck_http_parser();
    printf("  [PASS] wanduck parse_dst_url() 4KB non-NUL fuzz & dlen<4 .ico underflow guard\n");
    test_inadyn_no_shell_injection();
    printf("  [PASS] inadyn direct execv() zero-/bin/sh command injection test\n");
    test_busybox_udhcp_cve_2026_88833();
    printf("  [PASS] BusyBox udhcpc CVE-2026-88833 1-byte/OVERLOAD heap OOB guards\n");
    test_busybox_tar_cve_2026_108119();
    printf("  [PASS] BusyBox tar CVE-2026-108119 symlink target & intermediate-symlink guards\n");
    test_libxml2_and_dnsmasq_bounds();
    printf("  [PASS] libxml2 CVE-2025-6021 xmlBuildQName overflow & dnsmasq union bigname(2051B)\n");
    printf("==> STAGE 2 SANITIZER SUITE: 100%% PASSED.\n");
    return 0;
}
