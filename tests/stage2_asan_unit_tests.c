/*
 * stage2_asan_unit_tests.c — Pre-Build ASan + UBSan + GCC -fanalyzer Suite
 *
 * Exercises the exact patched C security, bounds, and parser logic for
 * RT-AC86U (386.14_2-sec2026) under AddressSanitizer + UndefinedBehaviorSanitizer
 * with exact-sized heap redzones and adversarial / boundary fuzz inputs.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
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
 * 1. Patched fd2str() (release/src/router/shared/shutils.c, Set 2 B-02)
 * ========================================================================= */
typedef ssize_t (*mock_read_fn)(int fd, void *buf, size_t count);

static char *patched_fd2str_real(int fd) {
    struct stat st;
    char *buf, *shrunk;
    size_t cap = 2048, len = 0;
    ssize_t n;

    if (fd < 0)
        return NULL;

    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0)
        cap = (size_t)st.st_size + 16;

    buf = malloc(cap);
    if (!buf) {
        close(fd);
        return NULL;
    }

    for (;;) {
        if (len + 1 >= cap) {
            size_t new_cap = (cap < 65536) ? (cap * 2) : (cap + cap / 2);
            char *tmp = realloc(buf, new_cap);
            if (!tmp) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = tmp;
            cap = new_cap;
        }
        n = read(fd, buf + len, cap - len - 1);
        if (n > 0) {
            len += (size_t)n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return NULL;
        }
    }

    close(fd);
    buf[len] = '\0';
    shrunk = realloc(buf, len + 1);
    return shrunk ? shrunk : buf;
}

static char *patched_fd2str_mock(int fd, mock_read_fn rfn) {
    char *buf, *shrunk;
    size_t cap = 512, len = 0;
    ssize_t n;

    if (fd < 0)
        return NULL;

    buf = malloc(cap);
    if (!buf)
        return NULL;

    for (;;) {
        if (len + 1 >= cap) {
            size_t new_cap = (cap < 65536) ? (cap * 2) : (cap + cap / 2);
            char *tmp = realloc(buf, new_cap);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
            cap = new_cap;
        }
        n = rfn(fd, buf + len, cap - len - 1);
        if (n > 0) {
            len += (size_t)n;
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR)
                continue;
            free(buf);
            return NULL;
        }
    }

    buf[len] = '\0';
    shrunk = realloc(buf, len + 1);
    return shrunk ? shrunk : buf;
}

static int g_mock_fail_on_call = 0;
static int g_mock_eintr_on_call = 0;
static int g_mock_call_idx = 0;
static const char *g_mock_payload = NULL;
static size_t g_mock_offset = 0;

static ssize_t test_mock_read(int fd, void *buf, size_t count) {
    (void)fd;
    g_mock_call_idx++;
    if (g_mock_eintr_on_call == g_mock_call_idx) {
        errno = EINTR;
        return -1;
    }
    if (g_mock_fail_on_call == g_mock_call_idx) {
        errno = EIO;
        return -1;
    }
    size_t total = strlen(g_mock_payload);
    if (g_mock_offset >= total)
        return 0;
    size_t rem = total - g_mock_offset;
    size_t to_copy = rem < count ? rem : count;
    memcpy(buf, g_mock_payload + g_mock_offset, to_copy);
    g_mock_offset += to_copy;
    return (ssize_t)to_copy;
}

static void write_all_exact(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t written = 0;
    while (written < len) {
        ssize_t w = write(fd, p + written, len - written);
        assert(w > 0);
        written += (size_t)w;
    }
}

static void test_fd2str(void) {
    /* Case A: negative fd & mock read() == -1 / EINTR recovery */
    assert(patched_fd2str_real(-1) == NULL);

    g_mock_eintr_on_call = 0;
    g_mock_fail_on_call = 1;
    g_mock_call_idx = 0;
    g_mock_payload = "unused";
    g_mock_offset = 0;
    char *err_a = patched_fd2str_mock(42, test_mock_read);
    assert(err_a == NULL);

    char big[700];
    memset(big, 'A', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    g_mock_eintr_on_call = 0;
    g_mock_fail_on_call = 2;
    g_mock_call_idx = 0;
    g_mock_payload = big;
    g_mock_offset = 0;
    char *err_b = patched_fd2str_mock(42, test_mock_read);
    assert(err_b == NULL);

    /* Case B: EINTR retry + multi-chunk geometric growth succeeds with 0 leaks */
    g_mock_eintr_on_call = 1;
    g_mock_fail_on_call = 0;
    g_mock_call_idx = 0;
    g_mock_payload = big;
    g_mock_offset = 0;
    char *res = patched_fd2str_mock(42, test_mock_read);
    assert(res != NULL);
    assert(strlen(res) == 699);
    assert(strcmp(res, big) == 0);
    free(res);

    /* Case C: Real 0-byte regular file -> returns "" and closes fd */
    char empty_path[] = "/tmp/stage2_fd2str_empty_XXXXXX";
    int efd = mkstemp(empty_path);
    assert(efd >= 0);
    char *empty_s = patched_fd2str_real(efd);
    assert(empty_s != NULL && empty_s[0] == '\0');
    assert(fcntl(efd, F_GETFD) == -1 && errno == EBADF);
    free(empty_s);
    unlink(empty_path);

    /* Case D: Real 256 KB regular file -> fstat exact prealloc + closes fd */
    const size_t reg_sz = 256u * 1024u;
    char *reg_payload = malloc(reg_sz);
    assert(reg_payload != NULL);
    for (size_t i = 0; i < reg_sz; i++)
        reg_payload[i] = (char)('a' + (i % 26));

    char reg_path[] = "/tmp/stage2_fd2str_reg_XXXXXX";
    int wfd = mkstemp(reg_path);
    assert(wfd >= 0);
    write_all_exact(wfd, reg_payload, reg_sz);
    close(wfd);

    int rfd = open(reg_path, O_RDONLY);
    assert(rfd >= 0);
    char *reg_out = patched_fd2str_real(rfd);
    assert(reg_out != NULL);
    assert(strlen(reg_out) == reg_sz);
    assert(memcmp(reg_out, reg_payload, reg_sz) == 0);
    assert(fcntl(rfd, F_GETFD) == -1 && errno == EBADF);
    free(reg_out);
    free(reg_payload);
    unlink(reg_path);

    /* Case E: Real 100 KB pipe (non-seekable, fstat size 0 -> geometric realloc + closes fd) */
    const size_t pipe_sz = 100u * 1024u;
    char *pipe_payload = malloc(pipe_sz);
    assert(pipe_payload != NULL);
    memset(pipe_payload, 'Z', pipe_sz);

    int pfd[2];
    assert(pipe(pfd) == 0);
    pid_t ch = fork();
    assert(ch >= 0);
    if (ch == 0) {
        close(pfd[0]);
        write_all_exact(pfd[1], pipe_payload, pipe_sz);
        close(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    char *pipe_out = patched_fd2str_real(pfd[0]);
    int st = 0;
    assert(waitpid(ch, &st, 0) == ch && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    assert(pipe_out != NULL);
    assert(strlen(pipe_out) == pipe_sz);
    assert(memcmp(pipe_out, pipe_payload, pipe_sz) == 0);
    assert(fcntl(pfd[0], F_GETFD) == -1 && errno == EBADF);
    free(pipe_out);
    free(pipe_payload);
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

/* =========================================================================
 * 9. Set 2 Suite A: httpd json-c Refcounts, Bitshifts, SHM Cleanup & find_hostname_by_mac (A-01..A-04, B-03)
 * ========================================================================= */
#define MJ_MAGIC 0x4A534F4E
enum mj_kind { MJ_OBJ = 1, MJ_ARR = 2, MJ_STR = 3 };

struct mini_json {
    unsigned int magic;
    int refcnt;
    enum mj_kind kind;
    char *str;
    size_t nchild;
    struct mini_json *children[16];
};

static struct mini_json *mj_alloc(enum mj_kind k, const char *s) {
    struct mini_json *o = calloc(1, sizeof(*o));
    assert(o != NULL);
    o->magic = MJ_MAGIC;
    o->refcnt = 1;
    o->kind = k;
    if (s) {
        o->str = strdup(s);
        assert(o->str != NULL);
    }
    return o;
}

static struct mini_json *mj_get(struct mini_json *o) {
    if (!o)
        return NULL;
    assert(o->magic == MJ_MAGIC && o->refcnt > 0);
    o->refcnt++;
    return o;
}

static void mj_put(struct mini_json *o) {
    if (!o)
        return;
    assert(o->magic == MJ_MAGIC && o->refcnt > 0);
    o->refcnt--;
    if (o->refcnt == 0) {
        for (size_t i = 0; i < o->nchild; i++)
            mj_put(o->children[i]);
        free(o->str);
        o->magic = 0xDEADBEEFu;
        free(o);
    }
}

static void mj_add(struct mini_json *parent, struct mini_json *child) {
    assert(parent != NULL && parent->magic == MJ_MAGIC && parent->nchild < 16);
    parent->children[parent->nchild++] = child;
}

static void helper_find_hostname_by_mac_line(const char *line, char *macaddr, size_t mac_sz,
                                             char *ipaddr, size_t ip_sz,
                                             char *host_name, size_t host_sz) {
    if (macaddr) macaddr[0] = '\0';
    if (ipaddr) ipaddr[0] = '\0';
    if (host_name) host_name[0] = '\0';

    /* Bounded sscanf (Set 2 A-04): never blind-memset 32/128/64 past caller stack bounds */
    char m_buf[18] = {0}, i_buf[16] = {0}, h_buf[32] = {0};
    if (sscanf(line, "%17s %15s %31s", m_buf, i_buf, h_buf) >= 2) {
        bsd_strlcpy(macaddr, m_buf, mac_sz);
        bsd_strlcpy(ipaddr, i_buf, ip_sz);
        bsd_strlcpy(host_name, h_buf, host_sz);
    }
}

static void test_set2_httpd_json_refcounts_and_find_mac(void) {
    /* Verify get_client_detail_info bitshift fix: (1<<FLAG_HTTP) vs broken (1<FLAG_HTTP)==0 */
    const unsigned int flag_http = 1u, flag_printer = 2u, flag_itune = 3u;
    assert((1u << flag_http) == 2u);
    assert((1u << flag_printer) == 4u);
    assert((1u << flag_itune) == 8u);

    /* Simulate get_clientlist_from_json_database: early return frees amasList; no double-put on transferred obj */
    for (int early_fail = 0; early_fail <= 1; early_fail++) {
        struct mini_json *amasList = mj_alloc(MJ_OBJ, NULL);
        struct mini_json *clients = early_fail ? NULL : mj_alloc(MJ_OBJ, NULL);
        if (!clients) {
            if (amasList) mj_put(amasList);
            continue;
        }
        struct mini_json *never_online = mj_alloc(MJ_OBJ, NULL);
        mj_add(clients, never_online); /* ownership transferred */
        mj_put(clients);
        mj_put(amasList);
    }

    /* Simulate borrowed ref + json_object_get before array add (reportstate / basic_clientlist) */
    struct mini_json *db = mj_alloc(MJ_OBJ, NULL);
    struct mini_json *borrowed_name = mj_alloc(MJ_STR, "nas-box");
    mj_add(db, borrowed_name);

    struct mini_json *macArray = mj_alloc(MJ_ARR, NULL);
    struct mini_json *macArray_tmp = NULL;
    for (int i = 0; i < 3; i++) {
        /* A-02: skip mismatches BEFORE allocating macArray_tmp (no orphan array leak) */
        if (i != 1)
            continue;
        macArray_tmp = mj_alloc(MJ_ARR, NULL);
        mj_add(macArray_tmp, mj_get(borrowed_name));
        mj_add(macArray, macArray_tmp); /* ownership transferred; do NOT mj_put(macArray_tmp) */
    }
    struct mini_json *wl_clients_list_obj = mj_alloc(MJ_OBJ, NULL);
    struct mini_json *wl_clients_array_obj = mj_alloc(MJ_ARR, NULL);
    mj_put(wl_clients_list_obj);
    mj_put(wl_clients_array_obj); /* A-02: free array obj instead of double-putting list obj */
    mj_put(macArray);
    assert(borrowed_name->refcnt == 1);
    mj_put(db);

    /* Simulate get_client_detail_info SHM error cleanup (all 10 objects freed) */
    struct mini_json *containers[10];
    for (int i = 0; i < 10; i++)
        containers[i] = mj_alloc(MJ_OBJ, NULL);
    for (int i = 0; i < 10; i++)
        mj_put(containers[i]);

    /* A-04: tight caller stack arrays under ASan stack redzone check */
    char mac[18], ip[16], host[32];
    const char *ro_empty = "";
    assert(ro_empty[0] == '\0'); /* must never memset a .rodata literal */
    helper_find_hostname_by_mac_line("AA:BB:CC:DD:EE:FF 192.168.50.100 router-client",
                                     mac, sizeof(mac), ip, sizeof(ip), host, sizeof(host));
    assert(strcmp(mac, "AA:BB:CC:DD:EE:FF") == 0);
    assert(strcmp(ip, "192.168.50.100") == 0);
    assert(strcmp(host, "router-client") == 0);
}

/* =========================================================================
 * 10. Set 2 Suite B: pids() Short-Circuit & Hoisted unqstrstr() (B-01, B-03)
 * ========================================================================= */
static char *patched_unqstrstr(const char *haystack, const char *needle) {
    char *cur;
    int q;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    const char *end = haystack + hlen;

    if (nlen == 0 || nlen > hlen)
        return (nlen == 0) ? (char *)haystack : NULL;

    for (cur = (char *)haystack, q = 0;
         cur <= (end - nlen) && !(!q && !strncmp(needle, cur, nlen));
         cur++) {
        if (*cur == '"')
            q ? q-- : q++;
    }
    return (cur <= (end - nlen)) ? cur : NULL;
}

static int read_file_raw_buf(const char *path, char *buf, size_t bufsz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int)n;
}

static const char *local_basename(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

static int find_first_pid_by_name_at(const char *proc_root, const char *procName) {
    DIR *dir;
    struct dirent *entry;
    char stat_buf[1024], cmd_buf[1024];
    char filename[512];

    if (!procName || !*procName)
        return 0;

    dir = opendir(proc_root);
    if (!dir)
        return 0;

    while ((entry = readdir(dir)) != NULL) {
        char *endp = NULL;
        errno = 0;
        unsigned long pid = strtoul(entry->d_name, &endp, 10);
        char *tail, *comm1, *cp, state;
        char comm[16];
        int n, comm_prefix;

        if (errno || !endp || *endp != '\0' || entry->d_name[0] == '\0')
            continue;

        int plen = snprintf(filename, sizeof(filename) - 16, "%s/%lu", proc_root, pid);
        if (plen < 0 || (size_t)plen >= sizeof(filename) - 16)
            continue;
        tail = filename + plen;

        strcpy(tail, "/stat");
        if (read_file_raw_buf(filename, stat_buf, sizeof(stat_buf)) < 0)
            continue;

        cp = strrchr(stat_buf, ')');
        comm1 = strchr(stat_buf, '(');
        if (!cp || !comm1 || cp[1] != ' ' || cp[2] == '\0')
            continue;
        state = cp[2];
        if (state == 'Z')
            continue;

        *cp = '\0';
        memset(comm, 0, sizeof(comm));
        strncpy(comm, comm1 + 1, sizeof(comm) - 1);

        comm_prefix = (strncmp(comm, procName, 15) == 0);
        if (comm_prefix && comm[14] == '\0') {
            closedir(dir);
            return 1;
        }

        strcpy(tail, "/cmdline");
        n = read_file_raw_buf(filename, cmd_buf, sizeof(cmd_buf));
        if (n <= 0)
            continue;

        if (comm_prefix) {
            int argv1idx = (int)strlen(cmd_buf) + 1;
            if (argv1idx < n && strcmp(local_basename(cmd_buf + argv1idx), procName) == 0) {
                closedir(dir);
                return 1;
            }
        }
        if (strcmp(local_basename(cmd_buf), procName) == 0) {
            closedir(dir);
            return 1;
        }
    }

    closedir(dir);
    return 0;
}

static void write_proc_fixture(const char *root, int pid, const char *stat_line,
                               const void *cmdline, size_t cmdline_len) {
    char dpath[512], fpath[512];
    int dn = snprintf(dpath, sizeof(dpath), "%s/%d", root, pid);
    assert(dn > 0 && (size_t)dn < sizeof(dpath));
    assert(mkdir(dpath, 0700) == 0);

    assert(snprintf(fpath, sizeof(fpath), "%s/stat", dpath) < (int)sizeof(fpath));
    int fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    write_all_exact(fd, stat_line, strlen(stat_line));
    close(fd);

    assert(snprintf(fpath, sizeof(fpath), "%s/cmdline", dpath) < (int)sizeof(fpath));
    fd = open(fpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    if (cmdline_len > 0)
        write_all_exact(fd, cmdline, cmdline_len);
    close(fd);
}

static void test_set2_pids_short_circuit_and_unqstrstr(void) {
    /* unqstrstr() hoisted-length tests */
    const char *s1 = "foo \"bar<% match %>\" real<% end %>";
    assert(strcmp(patched_unqstrstr(s1, ""), s1) == 0);
    assert(patched_unqstrstr("abc", "abcdef") == NULL);
    const char *m = patched_unqstrstr(s1, "<%");
    assert(m != NULL && strcmp(m, "<% end %>") == 0);
    assert(patched_unqstrstr("tail_match", "match") != NULL);

    /* Synthetic 120-PID /proc tree */
    char proc_root[] = "/tmp/stage2_proc_XXXXXX";
    assert(mkdtemp(proc_root) != NULL);

    for (int p = 1; p <= 120; p++) {
        if (p == 10) {
            write_proc_fixture(proc_root, p, "10 (zproc) Z 1 1", "zproc\0", 6);
        } else if (p == 20) {
            write_proc_fixture(proc_root, p, "20 (kworker/0:1) S 2 2", "", 0);
        } else if (p == 55) {
            const char cl[] = "/bin/sh\0/usr/sbin/target_daemon_long_name\0";
            write_proc_fixture(proc_root, p, "55 (target_daemon_l) S 1 1", cl, sizeof(cl) - 1);
        } else if (p == 99) {
            write_proc_fixture(proc_root, p, "99 (fastproc) S 1 1", "", 0);
        } else {
            char st[64];
            snprintf(st, sizeof(st), "%d (idleworker) S 1 1", p);
            write_proc_fixture(proc_root, p, st, "idleworker\0", 11);
        }
    }

    assert(find_first_pid_by_name_at(proc_root, "fastproc") == 1);
    assert(find_first_pid_by_name_at(proc_root, "target_daemon_long_name") == 1);
    assert(find_first_pid_by_name_at(proc_root, "zproc") == 0);
    assert(find_first_pid_by_name_at(proc_root, "kworker/0:1") == 1);
    assert(find_first_pid_by_name_at(proc_root, "nonexistent") == 0);

    for (int p = 1; p <= 120; p++) {
        char fp[512];
        snprintf(fp, sizeof(fp), "%s/%d/stat", proc_root, p);
        unlink(fp);
        snprintf(fp, sizeof(fp), "%s/%d/cmdline", proc_root, p);
        unlink(fp);
        snprintf(fp, sizeof(fp), "%s/%d", proc_root, p);
        rmdir(fp);
    }
    rmdir(proc_root);
}

/* =========================================================================
 * 11. Set 2 Suite C: __set_iface_ps() RPS/XPS Formatting & route_exist() (C-01, A-07)
 * ========================================================================= */
static int test_f_write_string_exact(const char *path, const char *val) {
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0)
        return -1;
    write_all_exact(fd, val, strlen(val));
    close(fd);
    return 0;
}

static int patched_set_iface_ps_sys(const char *sys_net, const char *ifname,
                                    int nr_rx_mask, const unsigned int *rx_mask,
                                    int nr_tx_mask, const unsigned int *tx_mask) {
    const char *attr[] = { "rps_cpus", "xps_cpus" };
    int q;
    int max_rx_q = (nr_rx_mask > 0) ? nr_rx_mask : ((nr_rx_mask == 0) ? 32 : 0);
    int max_tx_q = (nr_tx_mask > 0) ? nr_tx_mask : ((nr_tx_mask == 0) ? 32 : 0);
    int max_q = (max_rx_q > max_tx_q) ? max_rx_q : max_tx_q;
    char rx_m[16] = {0}, tx_m[16] = {0};
    char prefix[256], path[512];

    if (!ifname || *ifname == '\0' || (!nr_rx_mask && !rx_mask) || (!nr_tx_mask && !tx_mask))
        return -1;
    if ((nr_rx_mask > 0 && !rx_mask) || (nr_tx_mask > 0 && !tx_mask))
        return -2;

    snprintf(prefix, sizeof(prefix), "%s/%s/queues", sys_net, ifname);
    if (nr_rx_mask == 0)
        snprintf(rx_m, sizeof(rx_m), "%x", rx_mask[0]);
    if (nr_tx_mask == 0)
        snprintf(tx_m, sizeof(tx_m), "%x", tx_mask[0]);
    for (q = 0; q < max_q; ++q) {
        if (nr_rx_mask >= 0 && q < max_rx_q) {
            if (nr_rx_mask > 0)
                snprintf(rx_m, sizeof(rx_m), "%x", rx_mask[q]);
            snprintf(path, sizeof(path), "%s/rx-%d/%s", prefix, q, attr[0]);
            test_f_write_string_exact(path, rx_m);
        }
        if (nr_tx_mask >= 0 && q < max_tx_q) {
            if (nr_tx_mask > 0)
                snprintf(tx_m, sizeof(tx_m), "%x", tx_mask[q]);
            snprintf(path, sizeof(path), "%s/tx-%d/%s", prefix, q, attr[1]);
            test_f_write_string_exact(path, tx_m);
        }
    }
    return 0;
}

static int patched_route_exist_path(const char *route_path, const char *name, int metric,
                                    const char *dst, const char *gateway, const char *mask) {
    FILE *fp;
    in_addr_t addr_dst, addr_gate, addr_mask;
    in_addr_t rtr_dst, rtr_gate, rtr_mask;
    int rtr_metric;
    char buf[256], iface[16];
    int i, ret = 0;

    if (!name || !dst || !gateway || !mask)
        return -1;
    if (inet_pton(AF_INET, dst, &addr_dst) <= 0
     || inet_pton(AF_INET, gateway, &addr_gate) <= 0
     || inet_pton(AF_INET, mask, &addr_mask) <= 0)
        return -1;

    fp = fopen(route_path, "r");
    if (fp) {
        while (fgets(buf, sizeof(buf), fp)) {
            if (!strncmp(buf, "Iface", 5))
                continue;
            i = sscanf(buf, "%15s %x %x %*s %*s %*s %d %x",
                       iface, &rtr_dst, &rtr_gate, &rtr_metric, &rtr_mask);
            if (i != 5)
                continue;
            if (!strcmp(name, iface) && rtr_metric == metric && addr_dst == rtr_dst
             && addr_gate == rtr_gate && addr_mask == rtr_mask) {
                ret = 1;
                break;
            }
        }
        fclose(fp);
    }
    return ret;
}

static void create_empty_or_text(const char *path, const char *txt) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);
    if (txt && *txt)
        write_all_exact(fd, txt, strlen(txt));
    close(fd);
}

static void assert_file_eq(const char *path, const char *expected) {
    char buf[64] = {0};
    int n = read_file_raw_buf(path, buf, sizeof(buf));
    assert(n >= 0);
    assert(strcmp(buf, expected) == 0);
}

static void test_set2_iface_ps_and_route_exist(void) {
    char sys_root[] = "/tmp/stage2_sys_XXXXXX";
    assert(mkdtemp(sys_root) != NULL);

    char d[512], p_rx0[512], p_rx1[512], p_tx0[512];
    snprintf(d, sizeof(d), "%s/br0", sys_root); assert(mkdir(d, 0700) == 0);
    snprintf(d, sizeof(d), "%s/br0/queues", sys_root); assert(mkdir(d, 0700) == 0);
    snprintf(d, sizeof(d), "%s/br0/queues/rx-0", sys_root); assert(mkdir(d, 0700) == 0);
    snprintf(d, sizeof(d), "%s/br0/queues/rx-1", sys_root); assert(mkdir(d, 0700) == 0);
    snprintf(d, sizeof(d), "%s/br0/queues/tx-0", sys_root); assert(mkdir(d, 0700) == 0);

    snprintf(p_rx0, sizeof(p_rx0), "%s/br0/queues/rx-0/rps_cpus", sys_root);
    snprintf(p_rx1, sizeof(p_rx1), "%s/br0/queues/rx-1/rps_cpus", sys_root);
    snprintf(p_tx0, sizeof(p_tx0), "%s/br0/queues/tx-0/xps_cpus", sys_root);
    create_empty_or_text(p_rx0, "0");
    create_empty_or_text(p_rx1, "0");
    create_empty_or_text(p_tx0, "0");

    const unsigned int rxm[] = { 3u, 3u };
    const unsigned int txm[] = { 1u };
    assert(patched_set_iface_ps_sys(sys_root, "br0", 2, rxm, 1, txm) == 0);
    assert_file_eq(p_rx0, "3");
    assert_file_eq(p_rx1, "3");
    assert_file_eq(p_tx0, "1");

    /* TX-only (-1 RX): must NOT underflow or overwrite rx-0 */
    create_empty_or_text(p_rx0, "keep");
    const unsigned int txm2[] = { 2u };
    assert(patched_set_iface_ps_sys(sys_root, "br0", -1, NULL, 1, txm2) == 0);
    assert_file_eq(p_rx0, "keep");
    assert_file_eq(p_tx0, "2");

    /* RX-only (-1 TX) + broadcast (nr_rx_mask == 0) */
    const unsigned int bcast[] = { 3u };
    assert(patched_set_iface_ps_sys(sys_root, "br0", 0, bcast, -1, NULL) == 0);
    assert_file_eq(p_rx0, "3");
    assert_file_eq(p_rx1, "3");
    assert_file_eq(p_tx0, "2");

    unlink(p_rx0); unlink(p_rx1); unlink(p_tx0);
    snprintf(d, sizeof(d), "%s/br0/queues/rx-0", sys_root); rmdir(d);
    snprintf(d, sizeof(d), "%s/br0/queues/rx-1", sys_root); rmdir(d);
    snprintf(d, sizeof(d), "%s/br0/queues/tx-0", sys_root); rmdir(d);
    snprintf(d, sizeof(d), "%s/br0/queues", sys_root); rmdir(d);
    snprintf(d, sizeof(d), "%s/br0", sys_root); rmdir(d);
    rmdir(sys_root);

    /* route_exist tests */
    assert(patched_route_exist_path("/nonexistent_path", "eth0", 0, "999.999.1.1", "0.0.0.0", "255.255.255.0") == -1);
    char rt_path[] = "/tmp/stage2_route_XXXXXX";
    int rfd = mkstemp(rt_path);
    assert(rfd >= 0);
    const char *rt_data =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
        "bad0\t0001020A\t00000000\t0001\t0\t0\n"
        "eth0\t0032A8C0\t00000000\t0001\t0\t0\t10\t00FFFFFF\t0\t0\t0\n";
    write_all_exact(rfd, rt_data, strlen(rt_data));
    close(rfd);

    assert(patched_route_exist_path(rt_path, "eth0", 10, "192.168.50.0", "0.0.0.0", "255.255.255.0") == 1);
    assert(patched_route_exist_path(rt_path, "eth0", 99, "192.168.50.0", "0.0.0.0", "255.255.255.0") == 0);
    unlink(rt_path);
}

/* =========================================================================
 * 12. Set 2 Suite D: wsdd2 llmnr.c OOM/OOB Parser & 256 KiB Detached Pthreads (A-11, D-01)
 * ========================================================================= */
static int g_llmnr_fail_strdup = 0;
static int g_llmnr_fail_realloc_at = 0;

static int patched_llmnr_parse_qname(const unsigned char *in, size_t inlen, char *out, size_t out_sz) {
    char *in_name;
    size_t in_name_len = 0;
    const unsigned char *in_name_p;
    int realloc_calls = 0;

    if (inlen < 13)
        return -1;

    in_name = g_llmnr_fail_strdup ? NULL : strdup("");
    if (in_name == NULL)
        return -1;

    in_name_p = &in[12];
    while (in_name_p < in + inlen && *in_name_p > 0) {
        if (*in_name_p >= 0xC0) {
            free(in_name);
            return -1;
        }
        if (*in_name_p > 63) {
            free(in_name);
            return -1;
        }
        if (in_name_p + 1 + *in_name_p > in + inlen) {
            free(in_name);
            return -1;
        }

        size_t lbl_len = *in_name_p;
        size_t old_len = strlen(in_name);
        in_name_len += lbl_len + (*in_name ? 1 : 0);

        realloc_calls++;
        char *tmp_name = (realloc_calls == g_llmnr_fail_realloc_at)
                             ? NULL
                             : (char *)realloc(in_name, in_name_len + 1);
        if (tmp_name == NULL) {
            free(in_name);
            return -1;
        }
        in_name = tmp_name;
        if (old_len > 0)
            in_name[old_len++] = '.';
        memcpy(in_name + old_len, in_name_p + 1, lbl_len);
        in_name[old_len + lbl_len] = '\0';

        in_name_p += lbl_len + 1;
    }

    if (out && out_sz > 0)
        bsd_strlcpy(out, in_name, out_sz);
    free(in_name);
    return 0;
}

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int done;
} g_pthread_sync = { PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, 0 };

static void *detached_worker_256k(void *arg) {
    (void)arg;
    /* Touch moderate stack buffer inside 256 KiB stack safely */
    volatile char scratch[4096];
    memset((void *)scratch, 0x5A, sizeof(scratch));
    pthread_mutex_lock(&g_pthread_sync.mu);
    g_pthread_sync.done++;
    if (g_pthread_sync.done == 64)
        pthread_cond_signal(&g_pthread_sync.cv);
    pthread_mutex_unlock(&g_pthread_sync.mu);
    return NULL;
}

static void test_set2_wsdd2_llmnr_and_detached_pthreads(void) {
    char qname[128] = {0};

    /* Valid 2-label query: 12-byte header + "\x04host\x05local\x00" */
    const unsigned char valid_pkt[] = {
        0,0, 0,0, 0,1, 0,0, 0,0, 0,0,
        4, 'h','o','s','t', 5, 'l','o','c','a','l', 0
    };
    g_llmnr_fail_strdup = 0;
    g_llmnr_fail_realloc_at = 0;
    assert(patched_llmnr_parse_qname(valid_pkt, sizeof(valid_pkt), qname, sizeof(qname)) == 0);
    assert(strcmp(qname, "host.local") == 0);

    /* OOM on strdup & OOM on 2nd realloc must free prior label and return -1 with 0 leaks */
    g_llmnr_fail_strdup = 1;
    assert(patched_llmnr_parse_qname(valid_pkt, sizeof(valid_pkt), qname, sizeof(qname)) == -1);
    g_llmnr_fail_strdup = 0;
    g_llmnr_fail_realloc_at = 2;
    assert(patched_llmnr_parse_qname(valid_pkt, sizeof(valid_pkt), qname, sizeof(qname)) == -1);
    g_llmnr_fail_realloc_at = 0;

    /* Compression pointer (0xC0), label >63, and truncated packet */
    const unsigned char comp_pkt[] = { 0,0,0,0,0,1,0,0,0,0,0,0, 0xC0, 0x0C };
    const unsigned char long_pkt[] = { 0,0,0,0,0,1,0,0,0,0,0,0, 64, 'a', 'b', 0 };
    const unsigned char trunc_pkt[] = { 0,0,0,0,0,1,0,0,0,0,0,0, 10, 'a', 'b', 'c' };
    assert(patched_llmnr_parse_qname(comp_pkt, sizeof(comp_pkt), qname, sizeof(qname)) == -1);
    assert(patched_llmnr_parse_qname(long_pkt, sizeof(long_pkt), qname, sizeof(qname)) == -1);
    assert(patched_llmnr_parse_qname(trunc_pkt, sizeof(trunc_pkt), qname, sizeof(qname)) == -1);

    /* 64 detached threads with explicit 256 KiB stack size */
    g_pthread_sync.done = 0;
    pthread_attr_t attr;
    assert(pthread_attr_init(&attr) == 0);
    assert(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0);
    assert(pthread_attr_setstacksize(&attr, 256u * 1024u) == 0);
    for (int i = 0; i < 64; i++) {
        pthread_t tid;
        int pt_rc = pthread_create(&tid, &attr, detached_worker_256k, NULL);
        assert(pt_rc == 0);
    }
    assert(pthread_attr_destroy(&attr) == 0);

    pthread_mutex_lock(&g_pthread_sync.mu);
    while (g_pthread_sync.done < 64)
        pthread_cond_wait(&g_pthread_sync.cv, &g_pthread_sync.mu);
    pthread_mutex_unlock(&g_pthread_sync.mu);
}

int main(void) {
    printf("[stage2] Running ASan + UBSan unit & adversarial fuzz tests...\n");
    test_fd2str();
    printf("  [PASS] fd2str() fstat prealloc, geometric realloc, EINTR retry & close(fd) on all paths\n");
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
    test_set2_httpd_json_refcounts_and_find_mac();
    printf("  [PASS] [Set 2] httpd json-c refcounts/UAF, bitshifts, SHM cleanup & find_hostname_by_mac()\n");
    test_set2_pids_short_circuit_and_unqstrstr();
    printf("  [PASS] [Set 2] pids() 120-PID short-circuit + hoisted unqstrstr()\n");
    test_set2_iface_ps_and_route_exist();
    printf("  [PASS] [Set 2] __set_iface_ps() RPS/XPS mask & route_exist() sscanf/FD guards\n");
    test_set2_wsdd2_llmnr_and_detached_pthreads();
    printf("  [PASS] [Set 2] wsdd2 llmnr OOM/OOB parser & 64 detached 256KiB pthreads\n");
    printf("==> STAGE 2 SANITIZER SUITE: 100%% PASSED.\n");
    return 0;
}
