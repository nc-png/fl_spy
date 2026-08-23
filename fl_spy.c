/* fl_spy — terminal spy for a running fluffer (or glftpd) daemon.
 *
 * Data sources:
 *   - the glftpd-compatible ONLINE SysV shared-memory segment (live sessions,
 *     transfer counters).  Slot count is derived from the segment size, so a
 *     config/daemon max_users mismatch cannot skew the view.  The segment is
 *     re-attached automatically after a daemon restart.
 *   - the daemon config (rootpath / datapath / ipc_key / log paths), so the
 *     xferlog and text logs can be tailed from the host side.
 *
 * Views:   [1] users (aggregated by username)   [2] active transfers
 *          [3] activity log (glftpd.log + login.log + sysop.log merged)
 * Overlay: Enter on a user = their sessions + recent xferlog files.
 * Speeds are a ~2 s sliding window sampled every tick — a stall shows as an
 * immediate dip to 0 instead of being averaged away.
 *
 * Transfer abort/kick uses the daemon's realtime-signal protocol:
 *   tgkill(shm_cpid, slot.procid, SIGRTMIN)   = abort transfer
 *   tgkill(shm_cpid, slot.procid, SIGRTMIN+1) = kick session
 * procid is a live TID only while a transfer is running, so both actions are
 * only offered mid-transfer.  Requires the daemon's uid or root.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <langinfo.h>
#include <limits.h>
#include <locale.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <curses.h>

#include "online.h"

#define VERSION      "1.0"
#define DEF_CONF     "/etc/fluffer.conf"
#define TICK_MIN_MS  100
#define TICK_MAX_MS  2000
#define SPEED_WIN_MS 2000          /* sliding speed window */
#define SWIN         40            /* samples kept per slot */
#define GSECS        600           /* graph history, seconds */
#define XFN          4096          /* xferlog entries kept */
#define ACTN         1024          /* activity lines kept */
#define ACTW         240
#define MAXGROUPS    512

/* ── color pairs ─────────────────────────────────────────────────────── */
enum { P_DEF = 1, P_TITLE, P_UL, P_DL, P_OK, P_WARN, P_ERR, P_HDR };

/* ── small helpers ───────────────────────────────────────────────────── */
static long now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static char *fmt_size(double b, char *buf, size_t sz) {
    const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int i = 0;
    while (b >= 1000.0 && i < 4) { b /= 1024.0; i++; }
    snprintf(buf, sz, b >= 100 ? "%.0f%s" : b >= 10 ? "%.1f%s" : "%.2f%s",
             b, u[i]);
    return buf;
}

static int g_bits;      /* 'b': speeds in decimal bit/s instead of GiB/s */

static char *fmt_speed(double bps, char *buf, size_t sz) {
    if (g_bits) {
        const char *u[] = {"bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"};
        double v = bps * 8.0;
        int i = 0;
        while (v >= 1000.0 && i < 4) { v /= 1000.0; i++; }
        snprintf(buf, sz, v >= 100 ? "%.0f%s" : v >= 10 ? "%.1f%s" : "%.2f%s",
                 v, u[i]);
        return buf;
    }
    char t[16];
    fmt_size(bps, t, sizeof(t));
    snprintf(buf, sz, "%s/s", t);
    return buf;
}

static char *fmt_dur(long s, char *buf, size_t sz) {
    if (s < 0) s = 0;
    if (s >= 86400)    snprintf(buf, sz, "%ldd%02ldh", s / 86400, (s % 86400) / 3600);
    else if (s >= 3600) snprintf(buf, sz, "%ldh%02ldm", s / 3600, (s % 3600) / 60);
    else if (s >= 60)   snprintf(buf, sz, "%ldm%02lds", s / 60, s % 60);
    else                snprintf(buf, sz, "%lds", s);
    return buf;
}

static int strcasestr_p(const char *hay, const char *needle) {
    if (!needle[0]) return 1;
    size_t nl = strlen(needle);
    for (; *hay; hay++)
        if (!strncasecmp(hay, needle, nl)) return 1;
    return 0;
}

static const char *basename_of(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

/* ── config (fluffer.conf / glftpd.conf style key value, include, #) ─── */
typedef struct { char k[64]; char v[512]; } kv_t;
static kv_t g_cfg[512];
static int  g_ncfg;

static void cfg_parse_file(const char *path, int depth) {
    if (depth > 4) return;
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *h = strchr(line, '#');
        if (h) *h = '\0';
        char *p = line;
        while (isspace((unsigned char)*p)) p++;
        if (!*p) continue;
        char *key = p;
        while (*p && !isspace((unsigned char)*p)) { *p = (char)tolower((unsigned char)*p); p++; }
        if (*p) *p++ = '\0';
        while (isspace((unsigned char)*p)) p++;
        char *val = p;
        char *e = val + strlen(val);
        while (e > val && isspace((unsigned char)e[-1])) *--e = '\0';
        if (!strcmp(key, "include")) { cfg_parse_file(val, depth + 1); continue; }
        if (g_ncfg < (int)(sizeof(g_cfg) / sizeof(g_cfg[0]))) {
            snprintf(g_cfg[g_ncfg].k, sizeof(g_cfg[0].k), "%.63s", key);
            snprintf(g_cfg[g_ncfg].v, sizeof(g_cfg[0].v), "%.511s", val);
            g_ncfg++;
        }
    }
    fclose(f);
}

static const char *cfg_get(const char *k, const char *def) {
    for (int i = 0; i < g_ncfg; i++)          /* first match wins, like the daemon */
        if (!strcmp(g_cfg[i].k, k)) return g_cfg[i].v;
    return def;
}

/* ── host-side log paths (rootpath + datapath rebase) ────────────────── */
static char g_root[512];
static char g_datapath[128];

static void host_log_path(char *out, size_t sz, const char *key, const char *def) {
    const char *v = cfg_get(key, def);
    char reb[640];
    if (strcmp(g_datapath, "/ftp-data") != 0 &&
        !strncmp(v, "/ftp-data", 9) && (v[9] == '/' || v[9] == '\0')) {
        snprintf(reb, sizeof(reb), "%s%s", g_datapath, v + 9);
        v = reb;
    }
    snprintf(out, sz, "%s%s", g_root, v);
}

/* ── gid → group name (from <rootpath>/etc/group, "name:desc:gid:") ──── */
static struct { int32_t gid; char name[16]; } g_groups[MAXGROUPS];
static int g_ngroups;

static void groups_load(void) {
    char path[1200];
    snprintf(path, sizeof(path), "%s%s", g_root, cfg_get("grp_path", "/etc/group"));
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f) && g_ngroups < MAXGROUPS) {
        char *c1 = strchr(line, ':');
        if (!c1) continue;
        *c1 = '\0';
        char *c2 = strchr(c1 + 1, ':');
        if (!c2) continue;
        g_groups[g_ngroups].gid = (int32_t)strtol(c2 + 1, NULL, 10);
        snprintf(g_groups[g_ngroups].name, 16, "%.15s", line);
        g_ngroups++;
    }
    fclose(f);
}

static const char *group_name(int32_t gid) {
    for (int i = 0; i < g_ngroups; i++)
        if (g_groups[i].gid == gid) return g_groups[i].name;
    static char b[12];
    snprintf(b, sizeof(b), "%d", gid);
    return b;
}

/* ── shared memory ───────────────────────────────────────────────────── */
static key_t g_key = FL_SHM_DEFAULT_KEY;
static int   g_shmid = -1;
static const struct ONLINE *g_map;
static int   g_slots;
static pid_t g_tgid;

static void shm_detach(void) {
    if (g_map) shmdt((const void *)g_map);
    g_map = NULL; g_shmid = -1; g_slots = 0; g_tgid = 0;
}

static int shm_attach(void) {
    int id = shmget(g_key, 0, 0);
    if (id < 0) return -1;
    struct shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) < 0) return -1;
    const void *p = shmat(id, NULL, SHM_RDONLY);
    if (p == (const void *)-1) return -1;
    g_map = p;
    g_shmid = id;
    g_slots = (int)(ds.shm_segsz / sizeof(struct ONLINE));
    g_tgid  = ds.shm_cpid;
    return 0;
}

/* Segment gone (daemon restart) = EIDRM/EINVAL on IPC_STAT → reattach. */
static void shm_check(void) {
    struct shmid_ds ds;
    if (g_shmid >= 0 && shmctl(g_shmid, IPC_STAT, &ds) == 0) { g_tgid = ds.shm_cpid; return; }
    shm_detach();
    shm_attach();
}

/* ── generic log tailer (rotation/truncation aware) ──────────────────── */
typedef struct {
    char  path[1200];
    FILE *f;
    ino_t ino;
    off_t off;
} tailf_t;

typedef void (*tail_cb)(const char *line, void *arg);

static void tail_close(tailf_t *t) { if (t->f) fclose(t->f); t->f = NULL; }

static void tail_poll(tailf_t *t, off_t seed_back, tail_cb cb, void *arg) {
    struct stat st;
    if (stat(t->path, &st) < 0) { tail_close(t); return; }
    if (t->f && (st.st_ino != t->ino || st.st_size < t->off)) tail_close(t);
    if (!t->f) {
        t->f = fopen(t->path, "r");
        if (!t->f) return;
        t->ino = st.st_ino;
        t->off = 0;
        if (seed_back >= 0 && st.st_size > seed_back) {       /* first open: seed tail */
            fseeko(t->f, st.st_size - seed_back, SEEK_SET);
            char skip[1024];
            if (!fgets(skip, sizeof(skip), t->f)) { /* eof */ }
            t->off = ftello(t->f);
        }
    }
    fseeko(t->f, t->off, SEEK_SET);
    char line[1024];
    while (fgets(line, sizeof(line), t->f)) {
        size_t n = strlen(line);
        if (n && line[n - 1] != '\n' && !feof(t->f)) break;   /* partial write, retry next tick */
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        if (n) cb(line, arg);
        t->off = ftello(t->f);
    }
}

/* ── xferlog: per-user recent files ──────────────────────────────────── */
typedef struct {
    time_t   when;
    char     dirch;     /* 'i' up, 'o' down */
    char     status;    /* c/i/x */
    uint64_t size;
    uint64_t dur_ms;
    char     user[25];
    char     file[200];
} xfent_t;

static int g_xl_ms;     /* xferlog_millisecs: transfer-time field unit */

static xfent_t g_xf[XFN];
static int     g_xfn, g_xfh;      /* count, head (next write) */
static tailf_t g_xftail;

static void xferlog_line(const char *line, void *arg) {
    (void)arg;
    /* wu-ftpd layout: 0-4 date, 5 dur, 6 ip, 7 size, 8 path, 9 type,
     * 10 '_', 11 direction, 12 mode, 13 user, 14 group, [17 status] */
    char buf[1024];
    snprintf(buf, sizeof(buf), "%s", line);
    char *f[24];
    int nf = 0;
    for (char *p = strtok(buf, " \t"); p && nf < 24; p = strtok(NULL, " \t"))
        f[nf++] = p;
    if (nf < 15) return;
    xfent_t *e = &g_xf[g_xfh];
    memset(e, 0, sizeof(*e));
    char datebuf[64];
    snprintf(datebuf, sizeof(datebuf), "%s %s %s %s %s", f[0], f[1], f[2], f[3], f[4]);
    struct tm tm = {0};
    tm.tm_isdst = -1;
    if (strptime(datebuf, "%a %b %d %H:%M:%S %Y", &tm))
        e->when = mktime(&tm);
    else
        e->when = time(NULL);
    e->dur_ms = strtoull(f[5], NULL, 10) * (g_xl_ms ? 1 : 1000);
    e->size   = strtoull(f[7], NULL, 10);
    e->dirch  = f[11][0];
    e->status = nf >= 18 ? f[17][0] : 0;   /* glftpd logs no completion status */
    snprintf(e->user, sizeof(e->user), "%s", f[13]);
    snprintf(e->file, sizeof(e->file), "%s", f[8]);
    g_xfh = (g_xfh + 1) % XFN;
    if (g_xfn < XFN) g_xfn++;
}

/* ── activity log (merged tails) ─────────────────────────────────────── */
static struct { char tag; char text[ACTW]; } g_act[ACTN];
static int g_actn, g_acth;
static unsigned long g_actgen;    /* bumped per line, to notice new entries */

static tailf_t g_gltail, g_lgtail, g_sytail;

static void act_line(const char *line, void *arg) {
    char tag = *(char *)arg;
    g_act[g_acth].tag = tag;
    snprintf(g_act[g_acth].text, ACTW, "%s", line);
    g_acth = (g_acth + 1) % ACTN;
    if (g_actn < ACTN) g_actn++;
    g_actgen++;
}

static void tails_poll(int first) {
    static char tg = 'G', tl = 'L', ts = 'S';
    off_t seed = first ? 16 * 1024 : -1;
    tail_poll(&g_xftail, first ? 256 * 1024 : -1, xferlog_line, NULL);
    tail_poll(&g_gltail, seed, act_line, &tg);
    tail_poll(&g_lgtail, seed, act_line, &tl);
    tail_poll(&g_sytail, seed, act_line, &ts);
}

/* ── sampling: per-slot windowed speed + per-second buckets ──────────── */
typedef struct { uint64_t bytes; long ms; } samp_t;

typedef struct {
    char     user[25];
    char     cls;        /* 'U', 'D' or 0 */
    uint64_t last_bytes;
    samp_t   ring[SWIN];
    int      rn, rh;
    double   spd;        /* windowed B/s */
} slotstat_t;

static slotstat_t   *g_ss;
static struct ONLINE *g_snap;
static int            g_snap_slots;

static uint64_t g_bup[GSECS], g_bdn[GSECS];
static time_t   g_bstamp[GSECS];

static void bucket_add(time_t sec, char cls, uint64_t d) {
    int i = (int)(sec % GSECS);
    if (g_bstamp[i] != sec) { g_bup[i] = g_bdn[i] = 0; g_bstamp[i] = sec; }
    if (cls == 'U') g_bup[i] += d; else g_bdn[i] += d;
}

static void bucket_get(time_t sec, uint64_t *up, uint64_t *dn) {
    int i = (int)(sec % GSECS);
    if (g_bstamp[i] == sec) { *up = g_bup[i]; *dn = g_bdn[i]; }
    else                    { *up = 0;        *dn = 0; }
}

/* SHM contract: transferring iff status says RETR/STOR/APPE AND
 * currentdir ends with the status filename (the daemon points
 * currentdir at the file for the duration of the transfer). */
static char slot_class(const struct ONLINE *o) {
    char c;
    if      (!strncasecmp(o->status, "RETR", 4)) c = 'D';
    else if (!strncasecmp(o->status, "STOR", 4)) c = 'U';
    else if (!strncasecmp(o->status, "APPE", 4)) c = 'U';
    else return 0;

    char fn[256];
    const char *a = o->status + 4;
    while (*a == ' ') a++;
    snprintf(fn, sizeof(fn), "%s", basename_of(a));
    size_t fl = strlen(fn);
    while (fl && (fn[fl - 1] == '\r' || fn[fl - 1] == '\n' || fn[fl - 1] == ' '))
        fn[--fl] = '\0';
    if (!fl) return 0;

    size_t dl = strlen(o->currentdir);
    if (dl < fl || strcmp(o->currentdir + dl - fl, fn) != 0) return 0;
    if (dl > fl && o->currentdir[dl - fl - 1] != '/') return 0;
    return c;
}

static void slot_reset(slotstat_t *s) {
    s->rn = s->rh = 0;
    s->last_bytes = 0;
    s->spd = 0;
    s->cls = 0;
}

static void sample(void) {
    if (!g_map) return;
    if (g_snap_slots != g_slots) {
        free(g_snap); free(g_ss);
        g_snap = calloc((size_t)g_slots, sizeof(struct ONLINE));
        g_ss   = calloc((size_t)g_slots, sizeof(slotstat_t));
        g_snap_slots = g_slots;
        if (!g_snap || !g_ss) { endwin(); fprintf(stderr, "oom\n"); exit(1); }
    }
    memcpy(g_snap, g_map, (size_t)g_slots * sizeof(struct ONLINE));

    long   ms  = now_ms();
    time_t sec = time(NULL);

    for (int i = 0; i < g_slots; i++) {
        struct ONLINE *o = &g_snap[i];
        /* fields are snprintf'd by the daemon but writes can tear — refence */
        o->username[sizeof(o->username) - 1] = '\0';
        o->status[sizeof(o->status) - 1] = '\0';
        o->host[sizeof(o->host) - 1] = '\0';
        o->currentdir[sizeof(o->currentdir) - 1] = '\0';
        o->tagline[sizeof(o->tagline) - 1] = '\0';

        slotstat_t *s = &g_ss[i];
        char cls = o->username[0] ? slot_class(o) : 0;
        if (!cls) { slot_reset(s); s->user[0] = '\0'; continue; }

        if (strcmp(s->user, o->username) || s->cls != cls ||
            o->bytes_xfer < s->last_bytes) {
            /* new user in slot, or a new transfer started */
            slot_reset(s);
            snprintf(s->user, sizeof(s->user), "%s", o->username);
            s->cls = cls;
        }
        uint64_t d = o->bytes_xfer - s->last_bytes;
        if (s->rn == 0) d = 0;    /* don't credit pre-attach history to one tick */
        s->last_bytes = o->bytes_xfer;
        if (d) bucket_add(sec, cls, d);

        s->ring[s->rh] = (samp_t){o->bytes_xfer, ms};
        s->rh = (s->rh + 1) % SWIN;
        if (s->rn < SWIN) s->rn++;

        /* windowed speed: newest sample that is >= SPEED_WIN_MS old,
         * else the oldest we have */
        int newest = (s->rh - 1 + SWIN) % SWIN;
        int base   = (s->rh - s->rn + SWIN) % SWIN;
        for (int k = s->rn - 1; k >= 1; k--) {
            int idx = (s->rh - 1 - k + SWIN) % SWIN;
            if (ms - s->ring[idx].ms >= SPEED_WIN_MS) { base = idx; break; }
        }
        long dt = s->ring[newest].ms - s->ring[base].ms;
        s->spd = dt > 200
               ? (double)(s->ring[newest].bytes - s->ring[base].bytes) * 1000.0 / (double)dt
               : 0.0;
    }
}

/* ── per-user aggregation ────────────────────────────────────────────── */
typedef struct {
    char    name[25];
    int32_t gid;
    int     sess, nup, ndn;
    double  upspd, dnspd;
    long    idle;               /* min idle across sessions, seconds */
    int     slots[64];
    int     nslots;
} uagg_t;

static uagg_t *g_users;
static int     g_nusers, g_users_cap;

static long slot_idle(const struct ONLINE *o, time_t nowt) {
    time_t last = o->login_time;
    if (o->tstart.tv_sec > last) last = o->tstart.tv_sec;
    if (o->txfer.tv_sec  > last) last = o->txfer.tv_sec;
    return (long)(nowt - last);
}

static void aggregate(void) {
    if (g_users_cap < g_slots + 1) {
        free(g_users);
        g_users_cap = g_slots + 1;
        g_users = calloc((size_t)g_users_cap, sizeof(uagg_t));
        if (!g_users) { endwin(); fprintf(stderr, "oom\n"); exit(1); }
    }
    g_nusers = 0;
    time_t nowt = time(NULL);
    for (int i = 0; i < g_snap_slots; i++) {
        struct ONLINE *o = &g_snap[i];
        if (!o->username[0]) continue;
        uagg_t *u = NULL;
        for (int j = 0; j < g_nusers; j++)
            if (!strcmp(g_users[j].name, o->username)) { u = &g_users[j]; break; }
        if (!u) {
            u = &g_users[g_nusers++];
            memset(u, 0, sizeof(*u));
            snprintf(u->name, sizeof(u->name), "%s", o->username);
            u->gid  = o->groupid;
            u->idle = LONG_MAX;
        }
        u->sess++;
        if (u->nslots < 64) u->slots[u->nslots++] = i;
        long idle = slot_idle(o, nowt);
        if (idle < u->idle) u->idle = idle;
        char cls = g_ss[i].cls;
        if (cls == 'U') { u->nup++; u->upspd += g_ss[i].spd; }
        if (cls == 'D') { u->ndn++; u->dnspd += g_ss[i].spd; }
    }
}

/* ── UI state ────────────────────────────────────────────────────────── */
enum view { V_USERS, V_XFERS, V_LOG };
static int  g_view = V_USERS;
static int  g_tick_ms = 250;
static int  g_graph_on = 1;
static int  g_sort[3];              /* per-view sort mode */
static char g_filter[48];
static int  g_filter_edit;
static int  g_cursor;               /* index into current view's row list */
static int  g_scroll;
static int  g_log_follow = 1;
static char g_sel_user[25];         /* sticky selection across re-sorts */
static int  g_sel_slot = -1;

static int  g_ov_open;              /* user detail overlay */
static char g_ov_user[25];
static int  g_ov_sel;
static int  g_ov_scroll;
static int  g_ov_focus;             /* 0 sessions pane, 1 transfers pane */
static int  g_ov_tscroll;           /* transfers pane scroll offset */
static int  g_ov_tsel;              /* transfers pane selected row */

static int  g_help_open;
static int  g_confirm;              /* 0 none, SIGRTMIN or SIGRTMIN+1 */
static int  g_confirm_slot = -1;
static char g_status_msg[128];
static long g_status_ms;

static int  g_utf8;

static void status_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vsnprintf(g_status_msg, sizeof(g_status_msg), fmt, ap);
    va_end(ap);
    g_status_ms = now_ms();
}

/* ── row lists for the two list views ────────────────────────────────── */
static int g_rows[4096];    /* users: index into g_users; xfers: slot index */
static int g_nrows;

static int g_sortmode;      /* set before qsort */

static int cmp_users(const void *a, const void *b) {
    const uagg_t *x = &g_users[*(const int *)a], *y = &g_users[*(const int *)b];
    double xs = x->upspd + x->dnspd, ys = y->upspd + y->dnspd;
    int xa = x->nup + x->ndn > 0, ya = y->nup + y->ndn > 0;
    switch (g_sortmode) {
    case 1: return strcasecmp(x->name, y->name);
    case 2: if (x->sess != y->sess) return y->sess - x->sess;
            return strcasecmp(x->name, y->name);
    default:
        if (xa != ya) return ya - xa;
        if (xs != ys) return ys > xs ? 1 : -1;
        return strcasecmp(x->name, y->name);
    }
}

static int cmp_xfers(const void *a, const void *b) {
    int sa = *(const int *)a, sb = *(const int *)b;
    switch (g_sortmode) {
    case 1: {
        int c = strcasecmp(g_snap[sa].username, g_snap[sb].username);
        return c ? c : sa - sb;
    }
    case 2: {   /* longest running first */
        int32_t ta = g_snap[sa].tstart.tv_sec, tb = g_snap[sb].tstart.tv_sec;
        return ta != tb ? (ta > tb ? 1 : -1) : sa - sb;
    }
    default:
        return g_ss[sb].spd > g_ss[sa].spd ? 1 :
               g_ss[sb].spd < g_ss[sa].spd ? -1 : sa - sb;
    }
}

static void build_rows(void) {
    g_nrows = 0;
    if (g_view == V_USERS) {
        for (int i = 0; i < g_nusers && g_nrows < 4096; i++)
            if (strcasestr_p(g_users[i].name, g_filter)) g_rows[g_nrows++] = i;
        g_sortmode = g_sort[V_USERS];
        qsort(g_rows, (size_t)g_nrows, sizeof(int), cmp_users);
    } else if (g_view == V_XFERS) {
        for (int i = 0; i < g_snap_slots && g_nrows < 4096; i++)
            if (g_ss[i].cls &&
                (strcasestr_p(g_snap[i].username, g_filter) ||
                 strcasestr_p(g_snap[i].status, g_filter)))
                g_rows[g_nrows++] = i;
        g_sortmode = g_sort[V_XFERS];
        qsort(g_rows, (size_t)g_nrows, sizeof(int), cmp_xfers);
    }
    /* sticky selection */
    if (g_view == V_USERS && g_sel_user[0]) {
        for (int i = 0; i < g_nrows; i++)
            if (!strcmp(g_users[g_rows[i]].name, g_sel_user)) { g_cursor = i; break; }
    } else if (g_view == V_XFERS && g_sel_slot >= 0) {
        for (int i = 0; i < g_nrows; i++)
            if (g_rows[i] == g_sel_slot) { g_cursor = i; break; }
    }
    if (g_cursor >= g_nrows) g_cursor = g_nrows ? g_nrows - 1 : 0;
    if (g_cursor < 0) g_cursor = 0;
}

static void remember_sel(void) {
    if (g_nrows == 0) return;
    if (g_view == V_USERS)
        snprintf(g_sel_user, sizeof(g_sel_user), "%s", g_users[g_rows[g_cursor]].name);
    else if (g_view == V_XFERS)
        g_sel_slot = g_rows[g_cursor];
}

/* ── totals for the header ───────────────────────────────────────────── */
static void totals(int *users, int *sess, int *nup, int *ndn,
                   double *up, double *dn) {
    *users = g_nusers; *sess = 0; *nup = 0; *ndn = 0; *up = 0; *dn = 0;
    for (int i = 0; i < g_nusers; i++) *sess += g_users[i].sess;
    for (int i = 0; i < g_snap_slots; i++) {
        if (g_ss[i].cls == 'U') { (*nup)++; *up += g_ss[i].spd; }
        if (g_ss[i].cls == 'D') { (*ndn)++; *dn += g_ss[i].spd; }
    }
}

/* ── drawing ─────────────────────────────────────────────────────────── */
static void draw_box(int y, int x, int h, int w) {
    mvaddch(y, x, ACS_ULCORNER);
    mvhline(y, x + 1, ACS_HLINE, w - 2);
    mvaddch(y, x + w - 1, ACS_URCORNER);
    mvaddch(y + h - 1, x, ACS_LLCORNER);
    mvhline(y + h - 1, x + 1, ACS_HLINE, w - 2);
    mvaddch(y + h - 1, x + w - 1, ACS_LRCORNER);
    mvvline(y + 1, x, ACS_VLINE, h - 2);
    mvvline(y + 1, x + w - 1, ACS_VLINE, h - 2);
    for (int r = 1; r < h - 1; r++) mvhline(y + r, x + 1, ' ', w - 2);
}

static void box_sep(int y, int x, int w) {          /* ├────┤ divider */
    mvaddch(y, x, ACS_LTEE);
    mvhline(y, x + 1, ACS_HLINE, w - 2);
    mvaddch(y, x + w - 1, ACS_RTEE);
}

static void box_title(int y, int x, int w, const char *s) {
    int n = (int)strlen(s);
    if (n > w - 6) n = w - 6;
    if (n <= 0) return;
    attron(A_BOLD);
    mvprintw(y, x + 2, " %.*s ", n, s);
    attroff(A_BOLD);
}

static void draw_bar_row(int y, int x, int w, const uint64_t *v, int n,
                         uint64_t vmax, int rows, int color) {
    /* n columns of data rendered as vertical bars of height `rows`,
     * eighth-block resolution when UTF-8 is available */
    static const char *eighth[8] =
        {"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"};
    attron(COLOR_PAIR(color));
    for (int c = 0; c < n && c < w; c++) {
        int lvl = 0;
        if (vmax > 0) {
            double frac = (double)v[c] / (double)vmax;
            if (frac > 1.0) frac = 1.0;
            lvl = (int)(frac * rows * 8.0 + 0.5);
            if (v[c] > 0 && lvl == 0) lvl = 1;
        }
        for (int r = 0; r < rows; r++) {
            int cell = lvl - 8 * (rows - 1 - r);     /* bottom row = last */
            int yy = y + r;
            if (cell >= 8) mvaddstr(yy, x + c, g_utf8 ? "█" : "#");
            else if (cell > 0)
                mvaddstr(yy, x + c, g_utf8 ? eighth[cell - 1] : (cell >= 4 ? "=" : "."));
        }
    }
    attroff(COLOR_PAIR(color));
}

static void draw_graph(int top, int h, int w) {
    /* h rows total: border + UP rows + DN rows + border */
    int gr = (h - 2) / 2;
    int gx = 15;                       /* bars start after the label gutter */
    int n  = w - gx - 1;
    if (n > GSECS) n = GSECS;
    if (n < 1 || gr < 1) return;

    time_t nowt = time(NULL);
    uint64_t vu[GSECS], vd[GSECS], mu = 0, md = 0, mt = 0;
    for (int c = 0; c < n; c++) {
        /* rightmost column = previous full second (current one is partial) */
        time_t sec = nowt - 1 - (n - 1 - c);
        bucket_get(sec, &vu[c], &vd[c]);
        if (vu[c] > mu) mu = vu[c];
        if (vd[c] > md) md = vd[c];
        if (vu[c] + vd[c] > mt) mt = vu[c] + vd[c];
    }
    char b1[24], b2[24], b3[24], b4[24], b5[24], b6[24];
    uint64_t cu, cd;
    bucket_get(nowt - 1, &cu, &cd);
    draw_box(top, 0, h, w);
    char hdr[200];
    snprintf(hdr, sizeof(hdr),
             "Bandwidth  UP %s peak %s | DN %s peak %s | Tot %s peak %s",
             fmt_speed((double)cu, b1, sizeof(b1)), fmt_speed((double)mu, b2, sizeof(b2)),
             fmt_speed((double)cd, b3, sizeof(b3)), fmt_speed((double)md, b4, sizeof(b4)),
             fmt_speed((double)(cu + cd), b5, sizeof(b5)),
             fmt_speed((double)mt, b6, sizeof(b6)));
    box_title(top, 0, w, hdr);
    attron(COLOR_PAIR(P_UL) | A_BOLD);
    mvprintw(top + 1, 2, "UP");
    attroff(COLOR_PAIR(P_UL) | A_BOLD);
    attron(COLOR_PAIR(P_DL) | A_BOLD);
    mvprintw(top + 1 + gr, 2, "DN");
    attroff(COLOR_PAIR(P_DL) | A_BOLD);
    mvprintw(top + 1, 5, "%9.9s", fmt_speed((double)mu, b1, sizeof(b1)));
    mvprintw(top + 1 + gr, 5, "%9.9s", fmt_speed((double)md, b2, sizeof(b2)));
    draw_bar_row(top + 1,      gx, n, vu, n, mu, gr, P_UL);
    draw_bar_row(top + 1 + gr, gx, n, vd, n, md, gr, P_DL);
}

static void draw_header(int w) {
    char t[16];
    time_t nowt = time(NULL);
    struct tm tm; localtime_r(&nowt, &tm);
    strftime(t, sizeof(t), "%H:%M:%S", &tm);

    attron(COLOR_PAIR(P_TITLE) | A_BOLD);
    mvhline(0, 0, ' ', w);
    mvprintw(0, 1, "fl_spy %s", VERSION);
    if (g_map) {
        mvprintw(0, 12, "key 0x%08X  pid %d  slots %d",
                 (unsigned)g_key, (int)g_tgid, g_slots);
    } else {
        attron(COLOR_PAIR(P_ERR));
        mvprintw(0, 12, " NO SHM SEGMENT — daemon not running? retrying ");
        attron(COLOR_PAIR(P_TITLE));
    }
    mvprintw(0, w - 9, "%s", t);
    attroff(COLOR_PAIR(P_TITLE) | A_BOLD);

    int users, sess, nup, ndn; double up, dn;
    totals(&users, &sess, &nup, &ndn, &up, &dn);
    char su[20], sd[20], st[20];
    mvhline(1, 0, ' ', w);
    mvprintw(1, 1, "Users %d  Sess %d/%d", users, sess, g_slots);
    attron(COLOR_PAIR(P_UL) | A_BOLD);
    mvprintw(1, 28, "UL %d @ %s", nup, fmt_speed(up, su, sizeof(su)));
    attroff(COLOR_PAIR(P_UL) | A_BOLD);
    attron(COLOR_PAIR(P_DL) | A_BOLD);
    mvprintw(1, 48, "DL %d @ %s", ndn, fmt_speed(dn, sd, sizeof(sd)));
    attroff(COLOR_PAIR(P_DL) | A_BOLD);
    attron(A_BOLD);
    mvprintw(1, 68, "Tot %s", fmt_speed(up + dn, st, sizeof(st)));
    attroff(A_BOLD);
    if (g_filter[0] || g_filter_edit) {
        attron(COLOR_PAIR(P_WARN));
        mvprintw(1, w - (int)strlen(g_filter) - 12, "filter:%s%s",
                 g_filter, g_filter_edit ? "_" : "");
        attroff(COLOR_PAIR(P_WARN));
    }
}

/* Selection bar: rows end at their own last character, so plain A_REVERSE
 * gives a ragged highlight that jumps as you arrow through.  Repaint the
 * cursor row's tail so every selection is the same width: widest visible
 * row + 1, never narrower than minw. */
static void sel_extend(int y, int x0, int maxend, int minw, int w) {
    int end = maxend + 1;
    if (end < minw) end = minw;
    if (end > w) end = w;
    if (end > x0) mvchgat(y, x0, end - x0, A_REVERSE, 0, NULL);
}

static void draw_users(int top, int h, int w) {
    static const char *sortname[] = {"speed", "name", "sessions"};
    attron(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);
    mvhline(top, 0, ' ', w);
    mvprintw(top, 0, " %-14s %-9s %4s %3s %3s %11s %11s  %-6s %s",
             "USER", "GROUP", "SESS", "UL", "DL", "UP-SPD", "DN-SPD", "IDLE",
             "WHERE/WHAT");
    int hdrend = getcurx(stdscr) + 8;   /* selection bar floor: past the header */
    mvprintw(top, w - 14, "sort:%s", sortname[g_sort[V_USERS]]);
    attroff(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);

    int lh = h - 1;
    if (g_cursor < g_scroll) g_scroll = g_cursor;
    if (g_cursor >= g_scroll + lh) g_scroll = g_cursor - lh + 1;

    int maxend = 0, curend = -1, cury = 0;
    for (int r = 0; r < lh; r++) {
        int i = g_scroll + r;
        int y = top + 1 + r;
        move(y, 0); clrtoeol();
        if (i >= g_nrows) continue;
        uagg_t *u = &g_users[g_rows[i]];
        int active = u->nup + u->ndn > 0;
        char su[20] = "-", sd[20] = "-", si[24];
        if (u->nup) fmt_speed(u->upspd, su, sizeof(su));
        if (u->ndn) fmt_speed(u->dnspd, sd, sizeof(sd));
        fmt_dur(u->idle == LONG_MAX ? 0 : u->idle, si, sizeof(si));

        /* pick something informative for the tail column: an active file,
         * else the current dir of the least idle session */
        char what[256] = "";
        for (int k = 0; k < u->nslots; k++) {
            int s = u->slots[k];
            if (g_ss[s].cls) {
                snprintf(what, sizeof(what), "%s", basename_of(g_snap[s].currentdir));
                break;
            }
        }
        if (!what[0] && u->nslots > 0)
            snprintf(what, sizeof(what), "%s", g_snap[u->slots[0]].currentdir);

        if (i == g_cursor) attron(A_REVERSE);
        if (!active && i != g_cursor) attron(A_DIM);
        mvprintw(y, 0, " %-14.14s %-9.9s %4d ", u->name, group_name(u->gid), u->sess);
        attron(COLOR_PAIR(P_UL));
        printw("%3d ", u->nup);
        attroff(COLOR_PAIR(P_UL));
        attron(COLOR_PAIR(P_DL));
        printw("%3d ", u->ndn);
        attroff(COLOR_PAIR(P_DL));
        printw("%11s %11s  %-6s %.*s", su, sd, si,
               w - 72 > 0 ? w - 72 : 0, what);
        if (!active && i != g_cursor) attroff(A_DIM);
        if (i == g_cursor) { attroff(A_REVERSE); curend = getcurx(stdscr); cury = y; }
        if (getcurx(stdscr) > maxend) maxend = getcurx(stdscr);
    }
    if (curend >= 0) sel_extend(cury, curend, maxend, hdrend, w);
}

static void draw_xfers(int top, int h, int w) {
    static const char *sortname[] = {"speed", "user", "elapsed"};
    attron(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);
    mvhline(top, 0, ' ', w);
    mvprintw(top, 0, " %-14s %-3s %11s %9s %8s  %s",
             "USER", "DIR", "SPEED", "XFERRED", "ELAPSED", "FILE");
    int hdrend = getcurx(stdscr) + 8;   /* selection bar floor: past the header */
    mvprintw(top, w - 14, "sort:%s", sortname[g_sort[V_XFERS]]);
    attroff(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);

    int lh = h - 1;
    if (g_cursor < g_scroll) g_scroll = g_cursor;
    if (g_cursor >= g_scroll + lh) g_scroll = g_cursor - lh + 1;

    time_t nowt = time(NULL);
    int maxend = 0, curend = -1, cury = 0;
    for (int r = 0; r < lh; r++) {
        int i = g_scroll + r;
        int y = top + 1 + r;
        move(y, 0); clrtoeol();
        if (i >= g_nrows) continue;
        int s = g_rows[i];
        struct ONLINE *o = &g_snap[s];
        char cls = g_ss[s].cls;
        char sp[20], sz[20], el[24];
        fmt_speed(g_ss[s].spd, sp, sizeof(sp));
        fmt_size((double)o->bytes_xfer, sz, sizeof(sz));
        fmt_dur(nowt - o->tstart.tv_sec, el, sizeof(el));
        const char *file = o->status + (o->status[4] == ' ' ? 5 : 4);

        if (i == g_cursor) attron(A_REVERSE);
        mvprintw(y, 0, " %-14.14s ", o->username);
        attron(COLOR_PAIR(cls == 'U' ? P_UL : P_DL) | A_BOLD);
        printw("%-3s ", cls == 'U' ? "UL" : "DL");
        attroff(COLOR_PAIR(cls == 'U' ? P_UL : P_DL) | A_BOLD);
        int stalled = g_ss[s].spd < 1024.0;
        if (stalled) attron(COLOR_PAIR(P_ERR) | A_BOLD);
        printw("%11s", sp);
        if (stalled) attroff(COLOR_PAIR(P_ERR) | A_BOLD);
        printw(" %9s %8s  %.*s", sz, el, w - 54 > 0 ? w - 54 : 0, file);
        if (i == g_cursor) { attroff(A_REVERSE); curend = getcurx(stdscr); cury = y; }
        if (getcurx(stdscr) > maxend) maxend = getcurx(stdscr);
    }
    if (curend >= 0) sel_extend(cury, curend, maxend, hdrend, w);
}

static void draw_log(int top, int h, int w) {
    attron(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);
    mvhline(top, 0, ' ', w);
    mvprintw(top, 0, " ACTIVITY  (glftpd.log + login.log + sysop.log)%s",
             g_log_follow ? "  [follow]" : "  [scroll — End to follow]");
    attroff(COLOR_PAIR(P_HDR) | A_BOLD | A_UNDERLINE);

    int lh = h - 1;
    int total = g_actn;
    int max_scroll = total > lh ? total - lh : 0;
    if (g_log_follow) g_scroll = max_scroll;
    if (g_scroll > max_scroll) g_scroll = max_scroll;
    if (g_scroll < 0) g_scroll = 0;

    for (int r = 0; r < lh; r++) {
        int idx = g_scroll + r;
        int y = top + 1 + r;
        move(y, 0); clrtoeol();
        if (idx >= total) continue;
        int pos = (g_acth - total + idx + ACTN) % ACTN;
        char tag = g_act[pos].tag;
        int cp = tag == 'L' ? P_OK : tag == 'S' ? P_WARN : P_DEF;
        attron(COLOR_PAIR(cp));
        mvaddch(y, 1, tag);
        attroff(COLOR_PAIR(cp));
        if (g_filter[0] && strcasestr_p(g_act[pos].text, g_filter))
            attron(A_BOLD);
        mvprintw(y, 3, "%.*s", w - 4, g_act[pos].text);
        attroff(A_BOLD);
    }
}

static void draw_overlay(int H, int W) {
    uagg_t *u = NULL;
    for (int i = 0; i < g_nusers; i++)
        if (!strcmp(g_users[i].name, g_ov_user)) { u = &g_users[i]; break; }

    /* fixed geometry regardless of session count */
    int bw = W - 4 < 160 ? W - 4 : 160;
    if (bw < 50) bw = W - 2;
    int bh = H - 4 < 40 ? H - 4 : 40;
    if (bh < 14) bh = H - 2;
    int by = (H - bh) / 2, bx = (W - bw) / 2;
    int inner = bh - 2;
    int SH = (inner - 5) * 2 / 5;      /* sessions pane rows */
    if (SH < 3) SH = 3;
    int TH = inner - 5 - SH;           /* transfers pane rows (one spacer row) */

    int nsess = u ? u->nslots : 0;
    if (g_ov_sel >= nsess) g_ov_sel = nsess ? nsess - 1 : 0;
    if (g_ov_sel < 0) g_ov_sel = 0;
    if (g_ov_sel < g_ov_scroll) g_ov_scroll = g_ov_sel;
    if (g_ov_sel >= g_ov_scroll + SH) g_ov_scroll = g_ov_sel - SH + 1;
    if (g_ov_scroll > nsess - SH) g_ov_scroll = nsess > SH ? nsess - SH : 0;
    if (g_ov_scroll < 0) g_ov_scroll = 0;

    int reci[512], nrec = 0;
    for (int k = 0; k < g_xfn && nrec < 512; k++) {
        int pos = (g_xfh - 1 - k + XFN) % XFN;
        if (!strcmp(g_xf[pos].user, g_ov_user)) reci[nrec++] = pos;
    }

    draw_box(by, bx, bh, bw);
    char title[128];
    snprintf(title, sizeof(title), "%s — %s  (%d session%s)",
             g_ov_user, u ? group_name(u->gid) : "?", nsess,
             nsess == 1 ? "" : "s");
    box_title(by, bx, bw, title);
    box_title(by + bh - 1, bx, bw,
              "Esc close · Tab pane · up/dn scroll · x abort · k kick");

    int y = by + 1;
    if (u && u->nslots > 0)
        mvprintw(y, bx + 2, "tag: %.*s", bw - 10, g_snap[u->slots[0]].tagline);
    else
        mvprintw(y, bx + 2, "(user no longer online)");
    y++;

    char sesst[64];
    if (nsess > SH)
        snprintf(sesst, sizeof(sesst), "%sSessions %d-%d of %d",
                 g_ov_focus == 0 ? "> " : "",
                 g_ov_scroll + 1, g_ov_scroll + SH < nsess ? g_ov_scroll + SH : nsess,
                 nsess);
    else
        snprintf(sesst, sizeof(sesst), "%sSessions",
                 g_ov_focus == 0 ? "> " : "");
    box_sep(y, bx, bw);
    box_title(y, bx, bw, sesst);
    y++;
    attron(A_BOLD);
    mvprintw(y++, bx + 2, "%-5s %-22s %-4s %-8s %-7s %s",
             "SLOT", "HOST", "SSL", "ONLINE", "IDLE", "ACTION");
    attroff(A_BOLD);

    time_t nowt = time(NULL);
    for (int r = 0; r < SH; r++, y++) {
        int k = g_ov_scroll + r;
        if (k >= nsess) continue;
        int s = u->slots[k];
        struct ONLINE *o = &g_snap[s];
        char on[24], idl[24], act[160];
        snprintf(act, sizeof(act), "IDLE in %.128s", o->currentdir);
        fmt_dur(nowt - o->login_time, on, sizeof(on));
        fmt_dur(slot_idle(o, nowt), idl, sizeof(idl));
        if (g_ss[s].cls) {
            char sp[24], sz[20];
            snprintf(act, sizeof(act), "%s %s @ %s  %.80s",
                     g_ss[s].cls == 'U' ? "UL" : "DL",
                     fmt_size((double)o->bytes_xfer, sz, sizeof(sz)),
                     fmt_speed(g_ss[s].spd, sp, sizeof(sp)),
                     basename_of(o->status + (o->status[4] == ' ' ? 5 : 4)));
        } else if (strncasecmp(o->status, "IDLE", 4)) {
            snprintf(act, sizeof(act), "%.80s", o->status);
        }
        int hi = g_ov_focus == 0 && k == g_ov_sel;
        if (hi) attron(A_REVERSE);
        mvprintw(y, bx + 2, "%-5d %-22.22s %-4s %-8s %-7s %-*.*s",
                 s, o->host,
                 o->ssl_flag == 2 ? "both" : o->ssl_flag == 1 ? "ctrl" : "none",
                 on, idl, bw - 54, bw - 54, act);
        if (hi) attroff(A_REVERSE);
    }
    y++;                               /* spacer before the transfers pane */

    /* transfers pane: Tab moves focus here; selection follows arrows */
    if (g_ov_tsel >= nrec) g_ov_tsel = nrec ? nrec - 1 : 0;
    if (g_ov_tsel < 0) g_ov_tsel = 0;
    if (g_ov_tsel < g_ov_tscroll) g_ov_tscroll = g_ov_tsel;
    if (g_ov_tsel >= g_ov_tscroll + TH) g_ov_tscroll = g_ov_tsel - TH + 1;
    if (g_ov_tscroll > nrec - TH) g_ov_tscroll = nrec > TH ? nrec - TH : 0;
    if (g_ov_tscroll < 0) g_ov_tscroll = 0;
    char xft[64];
    if (nrec > TH)
        snprintf(xft, sizeof(xft), "%sTransfers %d-%d of %d",
                 g_ov_focus == 1 ? "> " : "",
                 g_ov_tscroll + 1,
                 g_ov_tscroll + TH < nrec ? g_ov_tscroll + TH : nrec, nrec);
    else
        snprintf(xft, sizeof(xft), "%sTransfers",
                 g_ov_focus == 1 ? "> " : "");
    box_sep(y, bx, bw);
    box_title(y, bx, bw, xft);
    y++;
    if (!nrec)
        mvprintw(y, bx + 2, "none seen in xferlog");
    for (int r = 0; r < TH && g_ov_tscroll + r < nrec; r++, y++) {
        int k = g_ov_tscroll + r;
        xfent_t *e = &g_xf[reci[k]];
        char tbuf[12], sz[20], sp[24] = "-";
        struct tm tm; localtime_r(&e->when, &tm);
        strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tm);
        if (e->dur_ms > 0)
            fmt_speed((double)e->size * 1000.0 / (double)e->dur_ms, sp, sizeof(sp));
        int cp = e->dirch == 'i' ? P_UL : P_DL;
        int hi = g_ov_focus == 1 && k == g_ov_tsel;
        if (hi) attron(A_REVERSE);
        mvprintw(y, bx + 2, "%s ", tbuf);
        attron(COLOR_PAIR(cp) | A_BOLD);
        printw("%s", e->dirch == 'i' ? "UL" : "DL");
        attroff(COLOR_PAIR(cp) | A_BOLD);
        printw(" %8s %11s %c  %-*.*s",
               fmt_size((double)e->size, sz, sizeof(sz)), sp,
               e->status ? e->status : ' ',
               bw - 46 > 0 ? bw - 46 : 0, bw - 46 > 0 ? bw - 46 : 0,
               basename_of(e->file));
        if (hi) attroff(A_REVERSE);
    }
}

static void draw_help(int H, int W) {
    static const char *lines[] = {
        "1/u  users view (aggregated)      Enter  user detail overlay",
        "2/t  transfers view               x      abort selected transfer",
        "3/a  activity log view            k      kick selected session",
        "Tab  cycle views                  /      filter (Esc clears)",
        "s    cycle sort                   g      toggle bandwidth graph",
        "b    speeds in GiB/s <-> bit/s    +/-    faster/slower refresh",
        "r    redraw                       q      quit",
        "arrows/PgUp/PgDn/Home/End  move",
        "",
        "Speeds are a 2s sliding window.  Graph: 1s per column.",
        "abort/kick use SIGRTMIN tgkill and work only during a transfer",
        "(needs the daemon's uid or root).",
    };
    int n = (int)(sizeof(lines) / sizeof(lines[0]));
    int bw = 74, bh = n + 3;
    int by = (H - bh) / 2, bx = (W - bw) / 2;
    if (by < 0) by = 0;
    if (bx < 0) bx = 0;
    for (int y = 0; y < bh; y++) mvhline(by + y, bx, ' ', bw);
    attron(COLOR_PAIR(P_TITLE));
    mvhline(by, bx, ' ', bw);
    mvprintw(by, bx + 1, " fl_spy %s — keys ", VERSION);
    attroff(COLOR_PAIR(P_TITLE));
    for (int i = 0; i < n; i++)
        mvprintw(by + 2 + i, bx + 2, "%s", lines[i]);
}

static void draw_hotbar(int y, int w) {
    move(y, 0); clrtoeol();
    if (g_confirm) {
        struct ONLINE *o = &g_snap[g_confirm_slot];
        attron(COLOR_PAIR(P_ERR) | A_BOLD);
        mvprintw(y, 1, "%s %s (slot %d)?  y/N",
                 g_confirm == SIGRTMIN ? "ABORT transfer of" : "KICK session of",
                 o->username, g_confirm_slot);
        attroff(COLOR_PAIR(P_ERR) | A_BOLD);
        return;
    }
    if (g_status_msg[0] && now_ms() - g_status_ms < 4000) {
        attron(COLOR_PAIR(P_WARN) | A_BOLD);
        mvprintw(y, 1, "%s", g_status_msg);
        attroff(COLOR_PAIR(P_WARN) | A_BOLD);
        return;
    }
    if (g_filter_edit) {
        attron(COLOR_PAIR(P_WARN));
        mvprintw(y, 1, "filter: %s_   (Enter apply, Esc clear)", g_filter);
        attroff(COLOR_PAIR(P_WARN));
        return;
    }
    static const struct { const char *k, *d; } keys[] = {
        {"q", "quit"}, {"1", "users"}, {"2", "xfers"}, {"3", "log"},
        {"↵", "detail"}, {"/", "filter"}, {"s", "sort"}, {"g", "graph"},
        {"b", "units"}, {"x", "abort"}, {"k", "kick"}, {"+-", "rate"},
        {"?", "help"},
    };
    int x = 1;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        const char *kk = keys[i].k;
        if (!g_utf8 && !strcmp(kk, "↵")) kk = "CR";
        if (x + (int)(strlen(kk) + strlen(keys[i].d)) + 3 >= w) break;
        attron(A_BOLD | A_REVERSE);
        mvprintw(y, x, " %s ", kk);
        attroff(A_BOLD | A_REVERSE);
        x += (int)strlen(kk) + 2;
        mvprintw(y, x, "%s ", keys[i].d);
        x += (int)strlen(keys[i].d) + 2;
    }
}

static void render(void) {
    int H = LINES, W = COLS;
    if (H < 12 || W < 60) {
        erase();
        mvprintw(0, 0, "terminal too small (%dx%d, need 60x12)", W, H);
        refresh();
        return;
    }
    erase();
    draw_header(W);
    int gh = 0;
    if (g_graph_on) {           /* scale with the terminal: 8..14 rows */
        gh = H / 4;
        if (gh < 8)  gh = 8;
        if (gh > 14) gh = 14;
        gh &= ~1;               /* even interior → UP and DN halves equal */
    }
    int list_top = 3;           /* blank row: summary line needs air */
    int list_h = H - list_top - gh - 1;
    switch (g_view) {
    case V_USERS: draw_users(list_top, list_h, W); break;
    case V_XFERS: draw_xfers(list_top, list_h, W); break;
    case V_LOG:   draw_log(list_top, list_h, W);   break;
    }
    if (gh) draw_graph(H - gh - 1, gh, W);
    if (g_ov_open)  draw_overlay(H, W);
    if (g_help_open) draw_help(H, W);
    draw_hotbar(H - 1, W);
    refresh();
}

/* ── actions ─────────────────────────────────────────────────────────── */
static int action_target_slot(void) {
    /* slot the abort/kick keys act on, per current context */
    if (g_ov_open) {
        for (int i = 0; i < g_nusers; i++)
            if (!strcmp(g_users[i].name, g_ov_user))
                return g_ov_sel < g_users[i].nslots ? g_users[i].slots[g_ov_sel] : -1;
        return -1;
    }
    if (g_view == V_XFERS && g_nrows > 0) return g_rows[g_cursor];
    if (g_view == V_USERS && g_nrows > 0) {
        /* act on the user's single active transfer, if unambiguous */
        uagg_t *u = &g_users[g_rows[g_cursor]];
        int found = -1, n = 0;
        for (int k = 0; k < u->nslots; k++)
            if (g_ss[u->slots[k]].cls) { found = u->slots[k]; n++; }
        if (n == 1) return found;
        if (n > 1) status_msg("%d active transfers — pick one in the detail view (Enter)", n);
        return n == 1 ? found : -1;
    }
    return -1;
}

static void request_signal(int sig) {
    int s = action_target_slot();
    if (s < 0 || s >= g_snap_slots) return;
    if (!g_ss[s].cls) { status_msg("no active transfer on that session"); return; }
    g_confirm = sig;
    g_confirm_slot = s;
}

static void fire_signal(void) {
    int s = g_confirm_slot;
    int sig = g_confirm;
    g_confirm = 0; g_confirm_slot = -1;
    if (s < 0 || s >= g_snap_slots || !g_ss[s].cls) { status_msg("transfer already gone"); return; }
    pid_t tid = g_snap[s].procid;
    if (tid <= 0 || g_tgid <= 0) { status_msg("no live TID for slot %d", s); return; }
    if (syscall(SYS_tgkill, g_tgid, tid, sig) == 0)
        status_msg("%s sent to %s (slot %d, tid %d)",
                   sig == SIGRTMIN ? "abort" : "kick", g_snap[s].username, s, (int)tid);
    else
        status_msg("tgkill failed: %s%s", strerror(errno),
                   errno == EPERM ? " (run as daemon user or root)" : "");
}

/* ── main ────────────────────────────────────────────────────────────── */
static void usage(void) {
    printf("fl_spy %s — live spy for a running fluffer/glftpd daemon\n\n"
           "usage: fl_spy [-r /etc/fluffer.conf] [-k 0xDEAD]\n"
           "  -r <conf>  config file (rootpath/datapath/ipc_key/log paths);\n"
           "             default: /etc/fluffer.conf, else /etc/glftpd.conf\n"
           "  -k <key>   override the SysV IPC key\n\n"
           "press '?' inside for keys\n", VERSION);
}

int main(int argc, char **argv) {
    const char *conf = NULL;
    long keyover = -1;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) conf = argv[++i];
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) keyover = strtol(argv[++i], NULL, 0);
        else { usage(); return strcmp(argv[i], "-h") && strcmp(argv[i], "--help"); }
    }
    if (!conf)      /* no -r: fluffer conf first, glftpd conf second */
        conf = access(DEF_CONF, R_OK) == 0 ? DEF_CONF
             : access("/etc/glftpd.conf", R_OK) == 0 ? "/etc/glftpd.conf"
             : DEF_CONF;

    setlocale(LC_ALL, "");
    g_utf8 = !strcmp(nl_langinfo(CODESET), "UTF-8");

    cfg_parse_file(conf, 0);
    snprintf(g_root, sizeof(g_root), "%s", cfg_get("rootpath", ""));
    snprintf(g_datapath, sizeof(g_datapath), "%s", cfg_get("datapath", "/ftp-data"));
    const char *ks = cfg_get("ipc_key", NULL);
    if (ks) g_key = (key_t)strtoul(ks, NULL, 0);
    if (keyover >= 0) g_key = (key_t)keyover;
    g_xl_ms = atoi(cfg_get("xferlog_millisecs", "0"));

    host_log_path(g_xftail.path, sizeof(g_xftail.path), "xferlog",   "/ftp-data/logs/xferlog");
    host_log_path(g_gltail.path, sizeof(g_gltail.path), "glftpdlog", "/ftp-data/logs/glftpd.log");
    host_log_path(g_lgtail.path, sizeof(g_lgtail.path), "login_log", "/ftp-data/logs/login.log");
    host_log_path(g_sytail.path, sizeof(g_sytail.path), "sysop_log", "/ftp-data/logs/sysop.log");

    groups_load();
    shm_attach();
    tails_poll(1);

    initscr();
    cbreak();
    noecho();
    nonl();
    keypad(stdscr, TRUE);
    curs_set(0);
    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(P_DEF,   -1,          -1);
        init_pair(P_TITLE, COLOR_BLACK, COLOR_CYAN);
        init_pair(P_UL,    COLOR_RED,   -1);
        init_pair(P_DL,    COLOR_CYAN,  -1);
        init_pair(P_OK,    COLOR_GREEN, -1);
        init_pair(P_WARN,  COLOR_YELLOW,-1);
        init_pair(P_ERR,   COLOR_RED,   -1);
        /* Column headers are a rule, not a block: bold on the default
           background + underline.  A filled background is reserved for the
           A_REVERSE cursor row so the selection is the only solid bar. */
        init_pair(P_HDR,   -1,          -1);
    }

    long last_sample = 0;
    for (;;) {
        long nms = now_ms();
        if (nms - last_sample >= g_tick_ms || last_sample == 0) {
            shm_check();
            sample();
            aggregate();
            tails_poll(0);
            last_sample = nms;
        }
        build_rows();
        render();

        long wait = g_tick_ms - (now_ms() - last_sample);
        timeout(wait < 10 ? 10 : (int)wait);
        int ch = getch();
        if (ch == ERR) continue;

        if (g_confirm) {
            if (ch == 'y' || ch == 'Y') fire_signal();
            else { g_confirm = 0; g_confirm_slot = -1; status_msg("cancelled"); }
            continue;
        }
        if (g_filter_edit) {
            if (ch == 27) { g_filter[0] = '\0'; g_filter_edit = 0; }
            else if (ch == '\r' || ch == '\n' || ch == KEY_ENTER) g_filter_edit = 0;
            else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
                size_t n = strlen(g_filter);
                if (n) g_filter[n - 1] = '\0';
            } else if (isprint(ch) && strlen(g_filter) < sizeof(g_filter) - 1) {
                size_t n = strlen(g_filter);
                g_filter[n] = (char)ch;
                g_filter[n + 1] = '\0';
            }
            continue;
        }
        if (g_help_open) { g_help_open = 0; continue; }

        if (g_ov_open) {
            switch (ch) {
            case 27: case 'q': case '\r': case '\n': case KEY_ENTER:
                g_ov_open = 0; break;
            case '\t':
                g_ov_focus = !g_ov_focus; break;
            case KEY_UP:
                if (g_ov_focus) g_ov_tsel--;              /* clamped in draw */
                else if (g_ov_sel > 0) g_ov_sel--;
                break;
            case KEY_DOWN:
                if (g_ov_focus) g_ov_tsel++;
                else g_ov_sel++;                          /* clamped in draw */
                break;
            case KEY_PPAGE:
                if (g_ov_focus) g_ov_tsel -= 5;
                else { g_ov_sel -= 5; if (g_ov_sel < 0) g_ov_sel = 0; }
                break;
            case KEY_NPAGE:
                if (g_ov_focus) g_ov_tsel += 5;
                else g_ov_sel += 5;
                break;
            case 'x': request_signal(SIGRTMIN); break;
            case 'k': request_signal(SIGRTMIN + 1); break;
            case 'b': g_bits = !g_bits; break;
            case '?': g_help_open = 1; break;
            }
            continue;
        }

        switch (ch) {
        case 'q': case 27:
            endwin();
            return 0;
        case '\t':
            g_view = (g_view + 1) % 3; g_cursor = g_scroll = 0; break;
        case '1': case 'u': g_view = V_USERS; g_cursor = g_scroll = 0; break;
        case '2': case 't': g_view = V_XFERS; g_cursor = g_scroll = 0; break;
        case '3': case 'a': g_view = V_LOG;   g_scroll = 0; g_log_follow = 1; break;
        case KEY_UP:
            if (g_view == V_LOG) { g_log_follow = 0; g_scroll--; }
            else if (g_cursor > 0) { g_cursor--; remember_sel(); }
            break;
        case KEY_DOWN:
            if (g_view == V_LOG) { g_scroll++; }
            else if (g_cursor < g_nrows - 1) { g_cursor++; remember_sel(); }
            break;
        case KEY_PPAGE:
            if (g_view == V_LOG) { g_log_follow = 0; g_scroll -= 20; }
            else { g_cursor -= 20; if (g_cursor < 0) g_cursor = 0; remember_sel(); }
            break;
        case KEY_NPAGE:
            if (g_view == V_LOG) g_scroll += 20;
            else {
                g_cursor += 20;
                if (g_cursor >= g_nrows) g_cursor = g_nrows - 1;
                if (g_cursor < 0) g_cursor = 0;
                remember_sel();
            }
            break;
        case KEY_HOME:
            g_cursor = 0; g_scroll = 0;
            if (g_view == V_LOG) g_log_follow = 0;
            remember_sel();
            break;
        case KEY_END:
            if (g_view == V_LOG) g_log_follow = 1;
            else if (g_nrows) { g_cursor = g_nrows - 1; remember_sel(); }
            break;
        case '\r': case '\n': case KEY_ENTER:
            if (g_view == V_USERS && g_nrows) {
                snprintf(g_ov_user, sizeof(g_ov_user), "%s", g_users[g_rows[g_cursor]].name);
                g_ov_open = 1; g_ov_sel = 0; g_ov_scroll = 0; g_ov_focus = 0; g_ov_tscroll = 0; g_ov_tsel = 0;
            } else if (g_view == V_XFERS && g_nrows) {
                snprintf(g_ov_user, sizeof(g_ov_user), "%s",
                         g_snap[g_rows[g_cursor]].username);
                g_ov_open = 1; g_ov_sel = 0; g_ov_scroll = 0; g_ov_focus = 0; g_ov_tscroll = 0; g_ov_tsel = 0;
            }
            break;
        case '/':
            g_filter_edit = 1; break;
        case 's':
            if (g_view != V_LOG) g_sort[g_view] = (g_sort[g_view] + 1) % 3;
            break;
        case 'g':
            g_graph_on = !g_graph_on; break;
        case 'b':
            g_bits = !g_bits;
            status_msg("speeds in %s", g_bits ? "bit/s (decimal)" : "GiB/s");
            break;
        case 'x': request_signal(SIGRTMIN); break;
        case 'k': request_signal(SIGRTMIN + 1); break;
        case '+': case '=':
            g_tick_ms -= 50; if (g_tick_ms < TICK_MIN_MS) g_tick_ms = TICK_MIN_MS;
            status_msg("refresh %d ms", g_tick_ms); break;
        case '-': case '_':
            g_tick_ms += 50; if (g_tick_ms > TICK_MAX_MS) g_tick_ms = TICK_MAX_MS;
            status_msg("refresh %d ms", g_tick_ms); break;
        case 'r': case KEY_RESIZE:
            clearok(stdscr, TRUE); break;
        case '?': case 'h':
            g_help_open = 1; break;
        }
    }
}
