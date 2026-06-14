/*
 * ssh-guard - fanotify-based access control for sensitive directories
 *
 * Blocks any process whose executable inode is not in the whitelist from
 * opening files inside watched directories. Identity is verified via
 * dev+ino comparison (resistant to process-name spoofing and binary copies).
 *
 * Build: gcc -O2 -Wall -Wextra -o ssh-guard ssh-guard.c
 * Run:   must be root (needs CAP_SYS_ADMIN for fanotify PERM events)
 *
 * Config: /etc/ssh-guard/config
 *
 * Signals:
 * SIGHUP  - reload config and refresh the inode whitelist (use after pacman updates)
 * SIGTERM - graceful shutdown
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

/* === constants === */

#define MAX_ENTRIES  128
#define CONFIG_PATH  "/etc/ssh-guard/config"
#define PID_FILE     "/run/ssh-guard.pid"

/* === types === */

typedef struct {
    dev_t dev;
    ino_t ino;
    char  path[PATH_MAX];
} Entry;

/* === globals === */

static Entry watch_dirs[MAX_ENTRIES];
static int   watch_count   = 0;
static Entry allowed_bins[MAX_ENTRIES];
static int   allowed_count = 0;
static int   fan_fd        = -1;

static volatile sig_atomic_t g_reload  = 0;
static volatile sig_atomic_t g_running = 1;

/* === logging === */

static void logmsg(int prio, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsyslog(prio, fmt, ap);
    va_end(ap);

    /* Mirror to stderr when running interactively */
    if (isatty(STDERR_FILENO)) {
        vfprintf(stderr, fmt, ap);
        fputc('\n', stderr);
    }
    va_end(ap);
}

/* === string helpers === */

static void trim(char *s) {
    /* trailing whitespace */
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == '\n' || s[len-1] == '\r' ||
                       s[len-1] == ' '  || s[len-1] == '\t'))
        s[--len] = '\0';
    /* leading whitespace */
    size_t lead = strspn(s, " \t");
    if (lead) memmove(s, s + lead, len - lead + 1);
}

/* === config parser === */

/*
 * Config format (lines starting with # are comments):
 *
 * [watch]
 * /home/alice/.ssh
 * /root/.ssh
 *
 * [allow]
 * /usr/bin/ssh
 * /usr/bin/ssh-agent
 * /usr/bin/git
 * ...
 */
static int load_config(void) {
    FILE *f = fopen(CONFIG_PATH, "r");
    if (!f) {
        logmsg(LOG_ERR, "Cannot open %s: %s", CONFIG_PATH, strerror(errno));
        return -1;
    }

    watch_count   = 0;
    allowed_count = 0;

    char line[PATH_MAX + 16];
    int  section = 0; /* 0=none  1=[watch]  2=[allow] */

    while (fgets(line, sizeof(line), f)) {
        trim(line);
        if (line[0] == '#' || line[0] == '\0') continue;

        if (strcmp(line, "[watch]") == 0) { section = 1; continue; }
        if (strcmp(line, "[allow]") == 0) { section = 2; continue; }
        if (section == 0) continue;

        struct stat st;
        if (stat(line, &st) != 0) {
            logmsg(LOG_WARNING, "Skipping (not found): %s", line);
            continue;
        }

        if (section == 1 && watch_count < MAX_ENTRIES) {
            watch_dirs[watch_count].dev = st.st_dev;
            watch_dirs[watch_count].ino = st.st_ino;
            strncpy(watch_dirs[watch_count].path, line, PATH_MAX - 1);
            watch_count++;
            logmsg(LOG_INFO, "Watch:  %s  (ino=%lu)", line, (unsigned long)st.st_ino);

        } else if (section == 2 && allowed_count < MAX_ENTRIES) {
            allowed_bins[allowed_count].dev = st.st_dev;
            allowed_bins[allowed_count].ino = st.st_ino;
            strncpy(allowed_bins[allowed_count].path, line, PATH_MAX - 1);
            allowed_count++;
            logmsg(LOG_INFO, "Allow:  %s  (ino=%lu)", line, (unsigned long)st.st_ino);
        }
    }

    fclose(f);
    logmsg(LOG_INFO, "Config loaded: %d watch dirs, %d allowed binaries",
           watch_count, allowed_count);
    return 0;
}

/* === inode-based identity check === */

/*
 * Checks whether the binary backing process `pid` is in the allow list.
 *
 * We open /proc/<pid>/exe with O_PATH (no execution, no read) and then fstat
 * the resulting fd. This is TOCTOU-resistant: between open() and fstat() the
 * kernel holds a reference to the dentry, so even if the binary on disk is
 * replaced mid-check, we still get the inode of the *running* binary.
 */
static int is_allowed(pid_t pid) {
    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%d/exe", (int)pid);

    int exe_fd = open(proc_exe, O_RDONLY | O_PATH);
    if (exe_fd < 0) {
        /* Process vanished between the event and our check - default deny */
        return 0;
    }

    struct stat st;
    int r = fstat(exe_fd, &st);
    close(exe_fd);
    if (r != 0) return 0;

    for (int i = 0; i < allowed_count; i++) {
        if (allowed_bins[i].dev == st.st_dev &&
            allowed_bins[i].ino == st.st_ino)
            return 1;
    }

    /* Resolve path for the log entry (best-effort; can't race-fail us here) */
    char exe_path[PATH_MAX] = "<unknown>";
    ssize_t n = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
    if (n > 0) exe_path[n] = '\0';

    logmsg(LOG_WARNING,
           "DENIED  pid=%-6d  exe=%s  dev=%lu  ino=%lu",
           (int)pid, exe_path,
           (unsigned long)st.st_dev, (unsigned long)st.st_ino);
    return 0;
}

/* === fanotify mark helpers === */

static void add_all_marks(void) {
    for (int i = 0; i < watch_count; i++) {
        if (fanotify_mark(fan_fd,
                          FAN_MARK_ADD,
                          FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_EVENT_ON_CHILD,
                          AT_FDCWD, watch_dirs[i].path) < 0) {
            logmsg(LOG_ERR, "fanotify_mark(%s): %s",
                   watch_dirs[i].path, strerror(errno));
        }
    }
}

/* === signal handler === */

static void on_signal(int sig) {
    if      (sig == SIGHUP)                g_reload  = 1;
    else if (sig == SIGTERM || sig == SIGINT)      g_running = 0;
}

/* === main === */

int main(void) {
    openlog("ssh-guard", LOG_PID | LOG_NDELAY, LOG_DAEMON);
    logmsg(LOG_INFO, "ssh-guard starting (pid %d)", getpid());

    /* Write PID file so systemd / pacman hooks can find us */
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) { fprintf(pf, "%d\n", getpid()); fclose(pf); }

    /* Signals */
    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Load config (watch dirs + allowed binary paths -> inodes) */
    if (load_config() < 0) return 1;

    /* Initialise fanotify in content/permission mode, non-blocking */
    fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK,
                           O_RDONLY | O_LARGEFILE);
    if (fan_fd < 0) {
        logmsg(LOG_ERR, "fanotify_init: %s  (running as root?)", strerror(errno));
        return 1;
    }

    add_all_marks();
    logmsg(LOG_INFO, "Daemon ready - default-deny on all watched paths");

    /* Aligned event buffer */
    char buf[16384]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    while (g_running) {
        /* === SIGHUP: reload config and refresh marks === */
        if (g_reload) {
            g_reload = 0;
            logmsg(LOG_INFO, "SIGHUP received - reloading config");

            /* Flush ALL inode marks, then re-add after re-reading config */
            fanotify_mark(fan_fd, FAN_MARK_FLUSH, 0, AT_FDCWD, "/");
            load_config();
            add_all_marks();
            logmsg(LOG_INFO, "Reload complete");
        }

        /* === Read events === */
        ssize_t len = read(fan_fd, buf, sizeof(buf));
        if (len < 0) {
            if (errno == EINTR)  continue;       /* signal interrupted us  */
            if (errno == EAGAIN) {               /* nothing ready yet      */
                usleep(5000);
                continue;
            }
            logmsg(LOG_ERR, "read: %s", strerror(errno));
            break;
        }

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)buf;

        while (FAN_EVENT_OK(ev, len)) {
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                logmsg(LOG_ERR, "Unexpected fanotify metadata version %d", ev->vers);
                g_running = 0;
                break;
            }

            if (ev->mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) {
                int allow = is_allowed(ev->pid);

                struct fanotify_response resp = {
                    .fd       = ev->fd,
                    .response = allow ? FAN_ALLOW : FAN_DENY,
                };
                if (write(fan_fd, &resp, sizeof(resp)) < 0)
                    logmsg(LOG_ERR, "write response: %s", strerror(errno));
            }

            if (ev->fd >= 0) close(ev->fd);
            ev = FAN_EVENT_NEXT(ev, len);
        }
    }

    /* === Cleanup === */
    close(fan_fd);
    unlink(PID_FILE);
    logmsg(LOG_INFO, "ssh-guard stopped");
    closelog();
    return 0;
}