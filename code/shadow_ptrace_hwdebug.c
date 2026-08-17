/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "wujishadow_compat.h"

static bool shadow_log_enabled = true;
module_param_named(shadow_log, shadow_log_enabled, bool, 0600);
MODULE_PARM_DESC(shadow_log, "Enable rate-limited ShadowPtrace event logging");

#define COMBINED_SILENT_LOG(...)                 \
    do {                                         \
        if (shadow_log_enabled)                  \
            pr_info_ratelimited(__VA_ARGS__);    \
    } while (0)

#define COMPAT_NR_PTRACE 26
#define COMPAT_NR_PERF_EVENT_OPEN 364
#define COMPAT_NR_IOCTL 54
#define COMPAT_NR_CLOSE 6
#define COMPAT_NR_READ 3
#define COMPAT_NR_WAIT4 114
#define COMPAT_NR_OPENAT 322

#define TARGET_NAME_LEN 128
#define CMDLINE_LEN 128
#define SHADOW_SLOTS 64
#define SESSION_SLOTS 64
#define PERF_FD_SLOTS 64
#define STATUS_FD_SLOTS 64
#define STATUS_OPEN_SLOTS 32
#define STATUS_PATH_LEN 192
#define STATUS_SAMPLE_LEN 1536
#define PERF_MAGIC 0x53485045ULL
#define PTRACE_MAGIC 0x53485054ULL
#define STATUS_OPEN_MAGIC 0x53484f50ULL
#define STATUS_READ_MAGIC 0x53485244ULL
#define UNMATCHED_LOG_LIMIT 128
#define UNMATCHED_INTERESTING_LOG_LIMIT 512

#define NT_ARM_HW_BREAK 0x402
#define NT_ARM_HW_WATCH 0x403

#define HW_BREAK_DBG_INFO 0x906
#define HW_WATCH_DBG_INFO 0x904
#define HW_BREAK_READBACK_CTRL 0x1e5
#define HW_WATCH_READBACK_CTRL 0x1fd
#define WAIT_WNOHANG 1
#define WAIT_STOPPED_SIGSTOP 0x137f

/* arm64 does not expose these legacy requests in its kernel UAPI headers. */
#ifndef PTRACE_PEEKUSER
#define PTRACE_PEEKUSER 3
#endif
#ifndef PTRACE_POKEUSER
#define PTRACE_POKEUSER 6
#endif
#ifndef PTRACE_GETREGS
#define PTRACE_GETREGS 12
#endif
#ifndef PTRACE_SETREGS
#define PTRACE_SETREGS 13
#endif
#ifndef PTRACE_GETFPREGS
#define PTRACE_GETFPREGS 14
#endif
#ifndef PTRACE_SETFPREGS
#define PTRACE_SETFPREGS 15
#endif


struct user_iovec64
{
    unsigned long long iov_base;
    unsigned long long iov_len;
};

struct user_iovec32
{
    unsigned int iov_base;
    unsigned int iov_len;
};

struct shadow_state
{
    int valid;
    int regset;
    pid_t target_pid;
    struct user_hwdebug_state state;
};

struct ptrace_session
{
    int valid;
    pid_t target_pid;
    pid_t tracer_pid;
    int attached;
    int completed;
    int wait_reported;
};

struct perf_fd_state
{
    int valid;
    int fd;
    pid_t owner_pid;
    pid_t owner_tgid;
    pid_t target_pid;
    long cpu;
    long group_fd;
    unsigned long long flags;
    unsigned int bp_type;
    unsigned long long bp_addr;
    unsigned long long bp_len;
};

struct status_fd_state
{
    int valid;
    int fd;
    pid_t owner_tgid;
    pid_t target_pid;
    char path[STATUS_PATH_LEN];
};

struct status_open_pending
{
    int valid;
    pid_t owner_pid;
    pid_t owner_tgid;
    pid_t target_pid;
    unsigned long long dfd;
    unsigned long long flags;
    unsigned long long mode;
    char path[STATUS_PATH_LEN];
};

struct perf_attr_min
{
    unsigned int type;
    unsigned int size;
    unsigned long long config;
    unsigned long long sample_period_or_freq;
    unsigned long long sample_type;
    unsigned long long read_format;
    unsigned long long flags;
    unsigned int wakeup_events_or_watermark;
    unsigned int bp_type;
    unsigned long long bp_addr;
    unsigned long long bp_len;
};

static int native_ptrace_hooked;
static int compat_ptrace_hooked;
static int native_perf_hooked;
static int compat_perf_hooked;
static int native_ioctl_hooked;
static int compat_ioctl_hooked;
static int native_openat_hooked;
static int compat_openat_hooked;
static int native_close_hooked;
static int compat_close_hooked;
static int native_read_hooked;
static int compat_read_hooked;
static int native_wait4_hooked;
static int compat_wait4_hooked;
static char target_name[TARGET_NAME_LEN];
static struct shadow_state shadows[SHADOW_SLOTS];
static struct ptrace_session sessions[SESSION_SLOTS];
static struct perf_fd_state perf_fds[PERF_FD_SLOTS];
static struct status_fd_state status_fds[STATUS_FD_SLOTS];
static struct status_open_pending status_open_pending[STATUS_OPEN_SLOTS];
static unsigned int status_open_next;
static int status_fd_active_count;
static pid_t target_tgid_hint;

static unsigned long long log_seq;
static unsigned long long ptrace_seen;
static unsigned long long ptrace_matched;
static unsigned long long ptrace_unmatched;
static unsigned long long ptrace_faked;
static unsigned long long stateful_faked;
static unsigned long long perf_seen;
static unsigned long long perf_matched;
static unsigned long long perf_unmatched;
static unsigned long long perf_unmatched_breakpoints;
static unsigned long long perf_breakpoints;
static unsigned long long perf_blocked;
static unsigned long long perf_fd_events;
static unsigned long long regset_reads;
static unsigned long long regset_writes;
static unsigned long long wait4_seen;
static unsigned long long wait4_faked;
static unsigned long long status_open_seen;
static unsigned long long status_open_tracked;
static unsigned long long status_read_seen;
static unsigned long long status_read_faked;
static unsigned long long status_close_tracked;
static unsigned long long phys_failures;

static pid_t (*task_pid_nr_ns_fn)(struct task_struct *task, enum pid_type type, struct pid_namespace *ns);
static int (*get_cmdline_fn)(struct task_struct *task, char *buffer, int buflen);
extern int wuji_copy_current_user_phys(uint64_t addr, void *buf, size_t size,
                                       int write);
static struct status_fd_state *find_status_fd(pid_t owner_tgid, int fd);

static int local_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int local_streq(const char *a, const char *b)
{
    int i = 0;

    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == b[i];
}

static int local_starts_with(const char *s, const char *prefix)
{
    int i = 0;

    if (!s || !prefix) return 0;
    if (!prefix[0]) return 1;
    while (prefix[i]) {
        if (s[i] != prefix[i]) return 0;
        i++;
    }
    return 1;
}

static int local_contains(const char *s, const char *needle)
{
    int i;
    int j;

    if (!s || !needle || !needle[0]) return 0;
    for (i = 0; s[i]; i++) {
        for (j = 0; needle[j] && s[i + j] == needle[j]; j++) {
        }
        if (!needle[j]) return 1;
    }
    return 0;
}

static void local_copy(char *dst, int dstlen, const char *src)
{
    int i;

    if (!dst || dstlen <= 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    for (i = 0; i < dstlen - 1 && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static void sanitize_log_string(char *s)
{
    int i;

    if (!s) return;
    for (i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '\n' || c == '\r' || c == '\t') {
            s[i] = '|';
        } else if (c < 0x20 || c > 0x7e) {
            s[i] = '?';
        }
    }
}

static const char *shadow_skip_spaces(const char *s)
{
    if (!s) return "";
    while (local_is_space(*s)) s++;
    return s;
}

static void reset_fixed_target(void)
{
    volatile char *target = target_name;

    target[0] = 'c';
    target[1] = 'o';
    target[2] = 'm';
    target[3] = '.';
    target[4] = 't';
    target[5] = 'e';
    target[6] = 'n';
    target[7] = 'c';
    target[8] = 'e';
    target[9] = 'n';
    target[10] = 't';
    target[11] = '.';
    target[12] = 't';
    target[13] = 'm';
    target[14] = 'g';
    target[15] = 'p';
    target[16] = '.';
    target[17] = 's';
    target[18] = 'g';
    target[19] = 'a';
    target[20] = 'm';
    target[21] = 'e';
    target[22] = '\0';
}

static __maybe_unused const char *request_name(unsigned long long request)
{
    switch (request) {
    case 0:
        return "PTRACE_TRACEME";
    case PTRACE_PEEKTEXT:
        return "PTRACE_PEEKTEXT";
    case PTRACE_PEEKDATA:
        return "PTRACE_PEEKDATA";
    case PTRACE_PEEKUSER:
        return "PTRACE_PEEKUSER";
    case PTRACE_POKETEXT:
        return "PTRACE_POKETEXT";
    case PTRACE_POKEDATA:
        return "PTRACE_POKEDATA";
    case PTRACE_POKEUSER:
        return "PTRACE_POKEUSER";
    case PTRACE_CONT:
        return "PTRACE_CONT";
    case PTRACE_KILL:
        return "PTRACE_KILL";
    case PTRACE_SINGLESTEP:
        return "PTRACE_SINGLESTEP";
    case PTRACE_GETREGS:
        return "PTRACE_GETREGS";
    case PTRACE_SETREGS:
        return "PTRACE_SETREGS";
    case PTRACE_GETFPREGS:
        return "PTRACE_GETFPREGS";
    case PTRACE_SETFPREGS:
        return "PTRACE_SETFPREGS";
    case PTRACE_ATTACH:
        return "PTRACE_ATTACH";
    case PTRACE_DETACH:
        return "PTRACE_DETACH";
    case PTRACE_SYSCALL:
        return "PTRACE_SYSCALL";
    case PTRACE_SETOPTIONS:
        return "PTRACE_SETOPTIONS";
    case PTRACE_GETEVENTMSG:
        return "PTRACE_GETEVENTMSG";
    case PTRACE_GETSIGINFO:
        return "PTRACE_GETSIGINFO";
    case PTRACE_SETSIGINFO:
        return "PTRACE_SETSIGINFO";
    case PTRACE_GETREGSET:
        return "PTRACE_GETREGSET";
    case PTRACE_SETREGSET:
        return "PTRACE_SETREGSET";
    case PTRACE_SEIZE:
        return "PTRACE_SEIZE";
    case PTRACE_INTERRUPT:
        return "PTRACE_INTERRUPT";
    case PTRACE_LISTEN:
        return "PTRACE_LISTEN";
    case PTRACE_PEEKSIGINFO:
        return "PTRACE_PEEKSIGINFO";
    case PTRACE_GETSIGMASK:
        return "PTRACE_GETSIGMASK";
    case PTRACE_SETSIGMASK:
        return "PTRACE_SETSIGMASK";
    case PTRACE_SECCOMP_GET_FILTER:
        return "PTRACE_SECCOMP_GET_FILTER";
    case PTRACE_SECCOMP_GET_METADATA:
        return "PTRACE_SECCOMP_GET_METADATA";
    case PTRACE_GET_SYSCALL_INFO:
        return "PTRACE_GET_SYSCALL_INFO";
    default:
        return "PTRACE_OTHER";
    }
}

static __maybe_unused const char *regset_name(unsigned long long regset)
{
    switch (regset) {
    case NT_ARM_HW_BREAK:
        return "NT_ARM_HW_BREAK";
    case NT_ARM_HW_WATCH:
        return "NT_ARM_HW_WATCH";
    default:
        return "NT_OTHER";
    }
}

static int is_unmatched_log_sample(unsigned long long count, int interesting)
{
    if (count <= UNMATCHED_LOG_LIMIT) return 1;
    if (interesting && count <= UNMATCHED_INTERESTING_LOG_LIMIT) return 1;
    return (count & 1023ULL) == 0;
}

static int is_interesting_ptrace_unmatched(unsigned long long request, unsigned long long regset)
{
    if (request == PTRACE_ATTACH || request == PTRACE_DETACH || request == PTRACE_SETOPTIONS) return 1;
    if ((request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) &&
        (regset == NT_ARM_HW_BREAK || regset == NT_ARM_HW_WATCH)) {
        return 1;
    }
    return 0;
}

static __maybe_unused const char *perf_ioctl_name(unsigned long long cmd)
{
    switch (cmd) {
    case PERF_EVENT_IOC_ENABLE:
        return "PERF_EVENT_IOC_ENABLE";
    case PERF_EVENT_IOC_DISABLE:
        return "PERF_EVENT_IOC_DISABLE";
    case PERF_EVENT_IOC_REFRESH:
        return "PERF_EVENT_IOC_REFRESH";
    case PERF_EVENT_IOC_RESET:
        return "PERF_EVENT_IOC_RESET";
    case PERF_EVENT_IOC_PERIOD:
        return "PERF_EVENT_IOC_PERIOD";
    case PERF_EVENT_IOC_SET_OUTPUT:
        return "PERF_EVENT_IOC_SET_OUTPUT";
    case PERF_EVENT_IOC_SET_FILTER:
        return "PERF_EVENT_IOC_SET_FILTER";
    case PERF_EVENT_IOC_ID:
        return "PERF_EVENT_IOC_ID";
    case PERF_EVENT_IOC_SET_BPF:
        return "PERF_EVENT_IOC_SET_BPF";
    case PERF_EVENT_IOC_PAUSE_OUTPUT:
        return "PERF_EVENT_IOC_PAUSE_OUTPUT";
    case PERF_EVENT_IOC_QUERY_BPF:
        return "PERF_EVENT_IOC_QUERY_BPF";
    case PERF_EVENT_IOC_MODIFY_ATTRIBUTES:
        return "PERF_EVENT_IOC_MODIFY_ATTRIBUTES";
    default:
        return "PERF_EVENT_IOC_OTHER";
    }
}

static int read_user(void *dst, unsigned long long user_ptr, int len)
{
    if (!dst || !user_ptr || len <= 0) return 0;
    return wuji_copy_current_user_phys(user_ptr, dst, (size_t)len, 0) == 0;
}

static int read_user_cstr(char *dst, int dstlen, unsigned long long user_ptr)
{
    int i;

    if (!dst || dstlen <= 0) return 0;
    dst[0] = '\0';
    if (!user_ptr) return 0;

    for (i = 0; i < dstlen - 1; i++) {
        char ch;

        if (!read_user(&ch, user_ptr + i, 1)) {
            dst[i] = '\0';
            return i > 0;
        }
        dst[i] = ch;
        if (!ch) return 1;
    }

    dst[dstlen - 1] = '\0';
    return 1;
}

static int write_user(unsigned long long user_ptr, const void *src, int len)
{
    if (!src || !user_ptr || len <= 0) return 0;
    return wuji_copy_current_user_phys(user_ptr, (void *)src, (size_t)len, 1) == 0;
}

static int read_iovec(unsigned long long data, int compat, unsigned long long *base, unsigned long long *len)
{
    struct user_iovec64 iov64;
    struct user_iovec32 iov32;

    *base = 0;
    *len = 0;
    if (!data) return 0;

    if (compat) {
        if (!read_user(&iov32, data, sizeof(iov32))) return 0;
        *base = iov32.iov_base;
        *len = iov32.iov_len;
    } else {
        if (!read_user(&iov64, data, sizeof(iov64))) return 0;
        *base = iov64.iov_base;
        *len = iov64.iov_len;
    }
    return *base != 0 && *len >= sizeof(struct user_hwdebug_state);
}

static void init_empty_hwdebug(struct user_hwdebug_state *state, int regset)
{
    int i;

    state->dbg_info = regset == NT_ARM_HW_BREAK ? HW_BREAK_DBG_INFO : HW_WATCH_DBG_INFO;
    state->pad = 0;
    for (i = 0; i < 16; i++) {
        state->dbg_regs[i].addr = 0;
        state->dbg_regs[i].ctrl = 0;
        state->dbg_regs[i].pad = 0;
    }
}

static void normalize_hwdebug(struct user_hwdebug_state *state, int regset)
{
    int i;
    unsigned int ctrl = regset == NT_ARM_HW_BREAK ? HW_BREAK_READBACK_CTRL : HW_WATCH_READBACK_CTRL;

    state->dbg_info = regset == NT_ARM_HW_BREAK ? HW_BREAK_DBG_INFO : HW_WATCH_DBG_INFO;
    state->pad = 0;
    for (i = 0; i < 16; i++) {
        if (state->dbg_regs[i].addr || state->dbg_regs[i].ctrl) {
            state->dbg_regs[i].ctrl = ctrl;
            state->dbg_regs[i].pad = 0;
        }
    }
}

static void copy_hwdebug_state(struct user_hwdebug_state *dst, const struct user_hwdebug_state *src)
{
    int i;

    dst->dbg_info = src->dbg_info;
    dst->pad = src->pad;
    for (i = 0; i < 16; i++) {
        dst->dbg_regs[i].addr = src->dbg_regs[i].addr;
        dst->dbg_regs[i].ctrl = src->dbg_regs[i].ctrl;
        dst->dbg_regs[i].pad = src->dbg_regs[i].pad;
    }
}

static struct shadow_state *find_shadow(pid_t target_pid, int regset, int create)
{
    int i;
    int free_idx = -1;

    for (i = 0; i < SHADOW_SLOTS; i++) {
        if (shadows[i].valid && shadows[i].target_pid == target_pid && shadows[i].regset == regset) return &shadows[i];
        if (!shadows[i].valid && free_idx < 0) free_idx = i;
    }

    if (!create || free_idx < 0) return 0;

    shadows[free_idx].valid = 1;
    shadows[free_idx].target_pid = target_pid;
    shadows[free_idx].regset = regset;
    init_empty_hwdebug(&shadows[free_idx].state, regset);
    return &shadows[free_idx];
}

static void clear_shadow_target(pid_t target_pid)
{
    int i;

    for (i = 0; i < SHADOW_SLOTS; i++) {
        if (shadows[i].valid && shadows[i].target_pid == target_pid) shadows[i].valid = 0;
    }
}

static void clear_all_shadows(void)
{
    int i;

    for (i = 0; i < SHADOW_SLOTS; i++) shadows[i].valid = 0;
}

static struct ptrace_session *find_session(pid_t target_pid, int create)
{
    int i;
    int free_idx = -1;

    for (i = 0; i < SESSION_SLOTS; i++) {
        if (smp_load_acquire(&sessions[i].valid) &&
            READ_ONCE(sessions[i].target_pid) == target_pid)
            return &sessions[i];
        if (!READ_ONCE(sessions[i].valid) && free_idx < 0)
            free_idx = i;
    }

    if (!create || free_idx < 0) return 0;

    smp_store_release(&sessions[free_idx].valid, 0);
    sessions[free_idx].target_pid = target_pid;
    sessions[free_idx].tracer_pid = 0;
    sessions[free_idx].attached = 0;
    sessions[free_idx].completed = 0;
    sessions[free_idx].wait_reported = 0;
    smp_store_release(&sessions[free_idx].valid, 1);
    return &sessions[free_idx];
}

static struct ptrace_session *find_wait_session(pid_t tracer_pid, pid_t wait_pid)
{
    int i;

    for (i = 0; i < SESSION_SLOTS; i++) {
        if (!smp_load_acquire(&sessions[i].valid) ||
            !READ_ONCE(sessions[i].attached) ||
            READ_ONCE(sessions[i].tracer_pid) != tracer_pid)
            continue;
        if (wait_pid > 0 && sessions[i].target_pid != wait_pid) continue;
        return &sessions[i];
    }
    return 0;
}

static void clear_all_sessions(void)
{
    int i;

    for (i = 0; i < SESSION_SLOTS; i++)
        smp_store_release(&sessions[i].valid, 0);
}

static void clear_session_target(pid_t target_pid)
{
    int i;

    for (i = 0; i < SESSION_SLOTS; i++) {
        if (smp_load_acquire(&sessions[i].valid) &&
            READ_ONCE(sessions[i].target_pid) == target_pid)
            smp_store_release(&sessions[i].valid, 0);
    }
}

static void clear_all_perf_fds(void)
{
    int i;

    for (i = 0; i < PERF_FD_SLOTS; i++)
        smp_store_release(&perf_fds[i].valid, 0);
}

static struct perf_fd_state *find_perf_fd(pid_t owner_tgid, int fd)
{
    int i;

    for (i = 0; i < PERF_FD_SLOTS; i++) {
        if (smp_load_acquire(&perf_fds[i].valid) &&
            READ_ONCE(perf_fds[i].owner_tgid) == owner_tgid &&
            READ_ONCE(perf_fds[i].fd) == fd)
            return &perf_fds[i];
    }
    return 0;
}

static void remove_perf_fd(pid_t owner_tgid, int fd)
{
    struct perf_fd_state *state = find_perf_fd(owner_tgid, fd);

    if (state)
        smp_store_release(&state->valid, 0);
}

static void track_perf_fd(int fd, pid_t owner_pid, pid_t owner_tgid, pid_t target_pid, long cpu, long group_fd,
                          unsigned long long flags, unsigned int bp_type, unsigned long long bp_addr,
                          unsigned long long bp_len)
{
    struct perf_fd_state *state = find_perf_fd(owner_tgid, fd);
    int i;

    if (!state) {
        for (i = 0; i < PERF_FD_SLOTS; i++) {
            if (!perf_fds[i].valid) {
                state = &perf_fds[i];
                break;
            }
        }
    }
    if (!state) return;

    smp_store_release(&state->valid, 0);
    state->fd = fd;
    state->owner_pid = owner_pid;
    state->owner_tgid = owner_tgid;
    state->target_pid = target_pid;
    state->cpu = cpu;
    state->group_fd = group_fd;
    state->flags = flags;
    state->bp_type = bp_type;
    state->bp_addr = bp_addr;
    state->bp_len = bp_len;
    smp_store_release(&state->valid, 1);
}

static void log_hwdebug_slots(pid_t tracer_pid, pid_t target_pid, int regset, const char *phase,
                              struct user_hwdebug_state *state)
{
    int i;
    int active = 0;

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=%s type=hwdebug tracer_pid=%d target_pid=%d regset=%s dbg_info=0x%x\n",
            ++log_seq, phase, tracer_pid, target_pid, regset_name(regset), state->dbg_info);

    for (i = 0; i < 16; i++) {
        if (!state->dbg_regs[i].addr && !state->dbg_regs[i].ctrl) continue;
        active++;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=%s type=hwdebug_slot tracer_pid=%d target_pid=%d regset=%s slot=%d bp_addr=0x%llx ctrl=0x%x enabled=%u\n",
                ++log_seq, phase, tracer_pid, target_pid, regset_name(regset), i, state->dbg_regs[i].addr,
                state->dbg_regs[i].ctrl, state->dbg_regs[i].ctrl & 1);
    }

    if (!active) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=%s type=hwdebug_slot tracer_pid=%d target_pid=%d regset=%s active=0\n",
                ++log_seq, phase, tracer_pid, target_pid, regset_name(regset));
    }
}

static void read_current_identity(char *comm, int comm_len, char *cmdline, int cmdline_len)
{
    struct task_struct *task = current;
    char task_comm[TASK_COMM_LEN];
    int copied;

    local_copy(comm, comm_len, "");
    local_copy(cmdline, cmdline_len, "");
    if (!task) return;

    get_task_comm(task_comm, task);
    local_copy(comm, comm_len, task_comm);

    if (!get_cmdline_fn || cmdline_len <= 0) return;
    copied = get_cmdline_fn(task, cmdline, cmdline_len - 1);
    if (copied <= 0) {
        cmdline[0] = '\0';
        return;
    }
    if (copied >= cmdline_len) copied = cmdline_len - 1;
    cmdline[copied] = '\0';
}

static int current_matches_target(char *comm, int comm_len, char *cmdline, int cmdline_len)
{
    pid_t tgid;

    read_current_identity(comm, comm_len, cmdline, cmdline_len);

    if (!(cmdline[0] && (local_streq(cmdline, target_name) ||
                         local_starts_with(cmdline, target_name))) &&
        !(comm[0] && (local_streq(comm, target_name) ||
                      local_starts_with(comm, target_name))))
        return 0;

    tgid = task_pid_nr_ns_fn ?
        task_pid_nr_ns_fn(current, PIDTYPE_TGID, 0) : -1;
    if (tgid > 0)
        WRITE_ONCE(target_tgid_hint, tgid);
    return 1;
}

static pid_t current_pid(void)
{
    if (task_pid_nr_ns_fn) return task_pid_nr_ns_fn(current, PIDTYPE_PID, 0);
    return -1;
}

static pid_t current_tgid(void)
{
    if (task_pid_nr_ns_fn) return task_pid_nr_ns_fn(current, PIDTYPE_TGID, 0);
    return -1;
}

static int fast_current_matches_target(void)
{
    struct task_struct *leader;
    pid_t tgid;
    int i;

    tgid = current_tgid();
    if (tgid > 0 && tgid == READ_ONCE(target_tgid_hint))
        return 1;

    leader = READ_ONCE(current->group_leader);
    if (!leader)
        return 0;

    for (i = 0; i < TASK_COMM_LEN - 1 && target_name[i]; i++) {
        if (READ_ONCE(leader->comm[i]) != target_name[i])
            return 0;
    }
    return i > 0;
}

bool shadow_syscall_should_intercept(int nr, int compat,
                                     const struct pt_regs *regs)
{
    pid_t pid;
    pid_t tgid;
    int fd;

    if (!regs)
        return false;

    fd = (int)regs->regs[0];
    tgid = current_tgid();

    /* Ptrace is low volume and seeds the exact TGID cache after full matching. */
    if ((!compat && nr == __NR_ptrace) ||
        (compat && nr == COMPAT_NR_PTRACE))
        return true;

    if ((!compat && (nr == __NR_read || nr == __NR_close ||
                     nr == __NR_ioctl)) ||
        (compat && (nr == COMPAT_NR_READ || nr == COMPAT_NR_CLOSE ||
                    nr == COMPAT_NR_IOCTL))) {
        if (tgid < 0)
            return false;
        return find_status_fd(tgid, fd) || find_perf_fd(tgid, fd);
    }

    if ((!compat && nr == __NR_wait4) ||
        (compat && nr == COMPAT_NR_WAIT4)) {
        pid = current_pid();
        if (pid < 0)
            return false;
        return find_wait_session(pid, (pid_t)regs->regs[0]) != NULL;
    }

    if ((!compat && (nr == __NR_perf_event_open || nr == __NR_openat)) ||
        (compat && (nr == COMPAT_NR_PERF_EVENT_OPEN ||
                    nr == COMPAT_NR_OPENAT)))
        return fast_current_matches_target();

    return false;
}
NOKPROBE_SYMBOL(shadow_syscall_should_intercept);

static int local_is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static pid_t parse_pid_value(const char **cursor)
{
    const char *p;
    unsigned long value = 0;
    int digits = 0;

    if (!cursor || !*cursor) return 0;
    p = *cursor;
    while (local_is_digit(*p)) {
        value = value * 10 + (unsigned long)(*p - '0');
        p++;
        digits++;
        if (value > 4194304UL) return 0;
    }

    if (!digits) return 0;
    *cursor = p;
    return (pid_t)value;
}

static pid_t parse_status_path_target(const char *path)
{
    const char *p;
    const char *task;
    pid_t pid;

    if (!path || !path[0]) return 0;
    if (local_streq(path, "/proc/self/status") || local_streq(path, "/proc/thread-self/status")) return current_pid();
    if (local_streq(path, "status")) return 0;
    if (!local_starts_with(path, "/proc/")) return 0;

    p = path + 6;
    pid = parse_pid_value(&p);
    if (pid <= 0) return 0;

    task = p;
    while (task && task[0]) {
        if (local_starts_with(task, "/task/")) {
            const char *tp = task + 6;
            pid_t tid = parse_pid_value(&tp);

            if (tid > 0 && local_streq(tp, "/status")) return tid;
            return pid;
        }
        task++;
    }

    if (local_streq(p, "/status")) return pid;
    return 0;
}

static int is_status_path(const char *path)
{
    if (!path || !path[0]) return 0;
    if (local_streq(path, "status")) return 1;
    if (local_streq(path, "/proc/self/status") || local_streq(path, "/proc/thread-self/status")) return 1;
    if (local_starts_with(path, "/proc/") && local_contains(path, "/status")) return 1;
    return 0;
}

static void clear_all_status_fds(void)
{
    int i;

    for (i = 0; i < STATUS_FD_SLOTS; i++)
        smp_store_release(&status_fds[i].valid, 0);
    for (i = 0; i < STATUS_OPEN_SLOTS; i++) status_open_pending[i].valid = 0;
    status_fd_active_count = 0;
    status_open_next = 0;
}

static struct status_fd_state *find_status_fd(pid_t owner_tgid, int fd)
{
    int i;

    for (i = 0; i < STATUS_FD_SLOTS; i++) {
        if (smp_load_acquire(&status_fds[i].valid) &&
            READ_ONCE(status_fds[i].owner_tgid) == owner_tgid &&
            READ_ONCE(status_fds[i].fd) == fd)
            return &status_fds[i];
    }
    return 0;
}

static void remove_status_fd(pid_t owner_tgid, int fd)
{
    struct status_fd_state *state = find_status_fd(owner_tgid, fd);

    if (!state) return;
    smp_store_release(&state->valid, 0);
    if (status_fd_active_count > 0) status_fd_active_count--;
}

static void track_status_fd(int fd, pid_t owner_tgid, pid_t target_pid, const char *path)
{
    struct status_fd_state *state = find_status_fd(owner_tgid, fd);
    int i;

    if (!state) {
        for (i = 0; i < STATUS_FD_SLOTS; i++) {
            if (!status_fds[i].valid) {
                state = &status_fds[i];
                break;
            }
        }
    }

    if (!state) {
        state = &status_fds[fd >= 0 ? fd % STATUS_FD_SLOTS : 0];
        if (!state->valid) status_fd_active_count++;
    } else if (!state->valid) {
        status_fd_active_count++;
    }

    smp_store_release(&state->valid, 0);
    state->fd = fd;
    state->owner_tgid = owner_tgid;
    state->target_pid = target_pid;
    local_copy(state->path, sizeof(state->path), path);
    smp_store_release(&state->valid, 1);
}

static int alloc_status_open_pending(pid_t owner_pid, pid_t owner_tgid, pid_t target_pid, unsigned long long dfd,
                                     unsigned long long flags, unsigned long long mode, const char *path)
{
    int i;
    int idx = -1;

    for (i = 0; i < STATUS_OPEN_SLOTS; i++) {
        if (!status_open_pending[i].valid) {
            idx = i;
            break;
        }
    }
    if (idx < 0) idx = (int)(status_open_next++ % STATUS_OPEN_SLOTS);

    status_open_pending[idx].valid = 1;
    status_open_pending[idx].owner_pid = owner_pid;
    status_open_pending[idx].owner_tgid = owner_tgid;
    status_open_pending[idx].target_pid = target_pid;
    status_open_pending[idx].dfd = dfd;
    status_open_pending[idx].flags = flags;
    status_open_pending[idx].mode = mode;
    local_copy(status_open_pending[idx].path, sizeof(status_open_pending[idx].path), path);
    return idx;
}

static const char *find_line_prefix(char *buf, int len, const char *prefix)
{
    int i;
    int j;
    int prefix_len = 0;

    if (!buf || len <= 0 || !prefix) return 0;
    while (prefix[prefix_len]) prefix_len++;

    for (i = 0; i + prefix_len <= len; i++) {
        if (i > 0 && buf[i - 1] != '\n') continue;
        for (j = 0; j < prefix_len && buf[i + j] == prefix[j]; j++) {
        }
        if (j == prefix_len) return buf + i;
    }
    return 0;
}

static pid_t parse_status_pid_from_text(char *buf, int len)
{
    const char *line;
    const char *p;

    line = find_line_prefix(buf, len, "Pid:");
    if (!line) return 0;
    p = line + 4;
    while (*p == ' ' || *p == '\t') p++;
    return parse_pid_value(&p);
}

static void fill_decimal(char *out, int outlen, pid_t value)
{
    char tmp[16];
    int n = 0;
    int i;
    unsigned int v;

    if (!out || outlen <= 0) return;
    if (value < 0) value = 0;
    v = (unsigned int)value;

    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v && n < (int)sizeof(tmp));

    for (i = 0; i < n && i < outlen - 1; i++) out[i] = tmp[n - 1 - i];
    out[i] = '\0';
}

static int replace_line_payload(char *buf, int *len, int cap, int max_len, const char *prefix, const char *value)
{
    char *line;
    char *p;
    char *payload;
    char *newline;
    int old_payload_len;
    int value_len;
    int grow;
    int i;

    if (!buf || !len || !prefix || !value || *len <= 0) return 0;
    line = (char *)find_line_prefix(buf, *len, prefix);
    if (!line) return 0;

    p = line;
    while (p < buf + *len && *p && *p != ':') p++;
    if (p >= buf + *len || *p != ':') return 0;
    p++;
    while (p < buf + *len && (*p == ' ' || *p == '\t')) p++;
    payload = p;
    newline = payload;
    while (newline < buf + *len && *newline != '\n') newline++;

    old_payload_len = (int)(newline - payload);
    for (value_len = 0; value[value_len]; value_len++) {
    }

    if (value_len > old_payload_len) {
        grow = value_len - old_payload_len;
        if (*len + grow <= cap && *len + grow <= max_len) {
            for (i = *len; i >= (int)(newline - buf); i--) buf[i + grow] = buf[i];
            *len += grow;
            newline += grow;
            old_payload_len = value_len;
        } else if (*len == max_len && *len + grow <= cap && (int)(payload - buf) + value_len < max_len) {
            for (i = max_len - grow - 1; i >= (int)(newline - buf); i--) buf[i + grow] = buf[i];
            buf[max_len] = '\0';
            old_payload_len = value_len;
        }
    }

    if (value_len <= old_payload_len) {
        for (i = 0; i < value_len; i++) payload[i] = value[i];
        for (; i < old_payload_len; i++) payload[i] = ' ';
        return 1;
    }

    if (old_payload_len > 0) {
        payload[0] = value[0];
        for (i = 1; i < old_payload_len; i++) payload[i] = ' ';
        return 1;
    }

    return 0;
}

static int virtualize_status_text(char *buf, int *len, int cap, int max_len, struct status_fd_state *state,
                                  pid_t reader_pid)
{
    struct ptrace_session *session = 0;
    pid_t target_pid;
    char tracer_text[16];
    int changed = 0;
    int show_fake_attached = 0;

    if (!buf || !len || !state) return 0;

    target_pid = state->target_pid;
    if (target_pid <= 0) target_pid = parse_status_pid_from_text(buf, *len);
    if (target_pid > 0) session = find_session(target_pid, 0);

    if (session && session->attached && session->tracer_pid == reader_pid) show_fake_attached = 1;

    if (show_fake_attached) {
        fill_decimal(tracer_text, sizeof(tracer_text), session->tracer_pid);
        changed += replace_line_payload(buf, len, cap, max_len, "TracerPid:", tracer_text);
        changed += replace_line_payload(buf, len, cap, max_len, "State:", "t (tracing)");
    } else {
        changed += replace_line_payload(buf, len, cap, max_len, "TracerPid:", "0");
        changed += replace_line_payload(buf, len, cap, max_len, "State:", "S (sleeping)");
    }

    return changed;
}

static int is_hwdebug_regset(unsigned long long regset)
{
    return regset == NT_ARM_HW_BREAK || regset == NT_ARM_HW_WATCH;
}

static void before_ptrace(hook_fargs4_t *args, void *udata)
{
    char comm[TASK_COMM_LEN];
    char cmdline[CMDLINE_LEN];
    unsigned long long request;
    pid_t tracer_pid;
    pid_t target_pid;
    int compat = udata != 0;

    (void)compat;

    ptrace_seen++;
    if (!current_matches_target(comm, sizeof(comm), cmdline, sizeof(cmdline))) {
        unsigned long long regset = syscall_argn(args, 2);
        int interesting;

        ptrace_unmatched++;
        request = syscall_argn(args, 0);
        target_pid = (pid_t)syscall_argn(args, 1);
        interesting = is_interesting_ptrace_unmatched(request, regset);
        if (is_unmatched_log_sample(ptrace_unmatched, interesting)) {
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=ptrace_unmatched type=ptrace pid=%d tgid=%d target_pid=%d req=0x%llx req_name=%s addr=0x%llx regset=%s data=0x%llx compat=%d unmatched=%llu interesting=%d comm=%s cmdline=%s\n",
                    ++log_seq, current_pid(), current_tgid(), target_pid, request, request_name(request), regset,
                    regset_name(regset), syscall_argn(args, 3), compat, ptrace_unmatched, interesting, comm, cmdline);
        }
        return;
    }

    ptrace_matched++;
    tracer_pid = current_pid();
    request = syscall_argn(args, 0);
    target_pid = (pid_t)syscall_argn(args, 1);
    args->local.data0 = PTRACE_MAGIC;
    args->local.data1 = request;
    args->local.data2 = (uint64_t)tracer_pid;
    args->local.data3 = (uint64_t)target_pid;
    args->local.data4 = syscall_argn(args, 2);
    args->local.data5 = syscall_argn(args, 3);
    args->local.data6 = (uint64_t)compat;
    args->local.data7 = 0;

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=ptrace_enter type=ptrace tracer_pid=%d target_pid=%d req=0x%llx req_name=%s addr=0x%llx regset=%s data=0x%llx compat=%d comm=%s cmdline=%s\n",
            ++log_seq, tracer_pid, target_pid, request, request_name(request), syscall_argn(args, 2),
            regset_name(syscall_argn(args, 2)), syscall_argn(args, 3), compat, comm, cmdline);

    if (request == PTRACE_ATTACH) {
        struct ptrace_session *session = find_session(target_pid, 1);

        if (session) {
            session->tracer_pid = tracer_pid;
            session->attached = 1;
            session->completed = 0;
            session->wait_reported = 0;
        }
        clear_shadow_target(target_pid);
        args->ret = 0;
        args->skip_origin = 1;
        args->local.data7 = 1;
        stateful_faked++;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_attach_done type=ptrace tracer_pid=%d target_pid=%d ret=0 stateful_faked=%llu\n",
                ++log_seq, tracer_pid, target_pid, stateful_faked);
        return;
    }

    if (request == PTRACE_DETACH) {
        struct ptrace_session *session = find_session(target_pid, 0);

        if (session) {
            session->tracer_pid = tracer_pid;
            session->attached = 0;
            session->completed = 1;
        }
        clear_shadow_target(target_pid);
        clear_session_target(target_pid);
        args->ret = 0;
        args->skip_origin = 1;
        args->local.data7 = 1;
        stateful_faked++;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_detach_done type=ptrace tracer_pid=%d target_pid=%d ret=0 stateful_faked=%llu\n",
                ++log_seq, tracer_pid, target_pid, stateful_faked);
        return;
    }

    if (request == PTRACE_SETOPTIONS) {
        args->ret = 0;
        args->skip_origin = 1;
        args->local.data7 = 1;
        stateful_faked++;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_setoptions_done type=ptrace tracer_pid=%d target_pid=%d ret=0 stateful_faked=%llu\n",
                ++log_seq, tracer_pid, target_pid, stateful_faked);
        return;
    }

    if ((request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) && is_hwdebug_regset(syscall_argn(args, 2))) {
        struct ptrace_session *session;
        struct shadow_state *shadow;
        struct user_hwdebug_state incoming;
        unsigned long long iov_base;
        unsigned long long iov_len;
        int regset = (int)syscall_argn(args, 2);

        session = find_session(target_pid, 1);
        if (session) {
            session->tracer_pid = tracer_pid;
            session->attached = 1;
            session->completed = 0;
            session->wait_reported = 1;
        }

        ptrace_faked++;
        if (!read_iovec(syscall_argn(args, 3), compat, &iov_base, &iov_len)) {
            args->ret = -EFAULT;
            args->skip_origin = 1;
            args->local.data7 = 1;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_regset_iov_fail tracer_pid=%d target_pid=%d regset=%s ret=%d phys_failures=%llu\n",
                    ++log_seq, tracer_pid, target_pid, regset_name(regset), -EFAULT, phys_failures);
            return;
        }

        shadow = find_shadow(target_pid, regset, 1);
        if (!shadow) {
            args->ret = -ENOMEM;
            args->skip_origin = 1;
            args->local.data7 = 1;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_regset_shadow_full tracer_pid=%d target_pid=%d regset=%s ret=%d\n",
                    ++log_seq, tracer_pid, target_pid, regset_name(regset), -ENOMEM);
            return;
        }

        if (request == PTRACE_SETREGSET) {
            if (!read_user(&incoming, iov_base, sizeof(incoming))) {
                args->ret = -EFAULT;
                args->skip_origin = 1;
                args->local.data7 = 1;
                COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_setregset_read_fail tracer_pid=%d target_pid=%d regset=%s iov_base=0x%llx iov_len=%llu ret=%d phys_failures=%llu\n",
                        ++log_seq, tracer_pid, target_pid, regset_name(regset), iov_base, iov_len, -EFAULT,
                        phys_failures);
                return;
            }
            copy_hwdebug_state(&shadow->state, &incoming);
            log_hwdebug_slots(tracer_pid, target_pid, regset, "set_before", &incoming);
            normalize_hwdebug(&shadow->state, regset);
            log_hwdebug_slots(tracer_pid, target_pid, regset, "shadow_after_set", &shadow->state);
            regset_writes++;
            args->ret = -ENOSPC;
            args->skip_origin = 1;
            args->local.data7 = 1;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_setregset_done tracer_pid=%d target_pid=%d regset=%s ret=%d writes=%llu\n",
                    ++log_seq, tracer_pid, target_pid, regset_name(regset), -ENOSPC, regset_writes);
            return;
        }

        if (!write_user(iov_base, &shadow->state, sizeof(shadow->state))) {
            args->ret = -EFAULT;
            args->skip_origin = 1;
            args->local.data7 = 1;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_getregset_write_fail tracer_pid=%d target_pid=%d regset=%s iov_base=0x%llx iov_len=%llu ret=%d phys_failures=%llu\n",
                    ++log_seq, tracer_pid, target_pid, regset_name(regset), iov_base, iov_len, -EFAULT,
                    phys_failures);
            return;
        }
        log_hwdebug_slots(tracer_pid, target_pid, regset, "get_return", &shadow->state);
        regset_reads++;
        args->ret = 0;
        args->skip_origin = 1;
        args->local.data7 = 1;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_getregset_done tracer_pid=%d target_pid=%d regset=%s ret=0 reads=%llu\n",
                ++log_seq, tracer_pid, target_pid, regset_name(regset), regset_reads);
        return;
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=pass type=ptrace tracer_pid=%d target_pid=%d req_name=%s\n", ++log_seq,
            tracer_pid, target_pid, request_name(request));
}

static void after_ptrace(hook_fargs4_t *args, void *udata)
{
    struct ptrace_session *session;
    unsigned long long request;
    pid_t tracer_pid;
    pid_t target_pid;
    unsigned long long shadowed;

    (void)udata;
    if (args->local.data0 != PTRACE_MAGIC) return;

    request = args->local.data1;
    tracer_pid = (pid_t)args->local.data2;
    target_pid = (pid_t)args->local.data3;
    shadowed = args->local.data7;

    if (request == PTRACE_ATTACH || request == PTRACE_SETOPTIONS || request == PTRACE_DETACH) {
        args->ret = 0;
        shadowed = 1;
    } else if ((request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) && is_hwdebug_regset(args->local.data4)) {
        session = find_session(target_pid, 0);
        if (session && session->completed) {
            args->ret = -ESRCH;
        } else if (request == PTRACE_GETREGSET) {
            args->ret = 0;
        } else {
            args->ret = -ENOSPC;
        }
        shadowed = 1;
    }

    if (!shadowed && request == PTRACE_ATTACH && (long)args->ret == 0) {
        session = find_session(target_pid, 1);
        if (session) {
            session->tracer_pid = tracer_pid;
            session->attached = 1;
            session->completed = 0;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=session_attached tracer_pid=%d target_pid=%d\n",
                    ++log_seq, tracer_pid, target_pid);
        }
    } else if (!shadowed && request == PTRACE_DETACH && (long)args->ret == 0) {
        session = find_session(target_pid, 1);
        if (session) {
            session->tracer_pid = tracer_pid;
            session->attached = 0;
            session->completed = 1;
            clear_shadow_target(target_pid);
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=session_completed tracer_pid=%d target_pid=%d\n",
                    ++log_seq, tracer_pid, target_pid);
        }
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=ptrace_exit type=ptrace tracer_pid=%d target_pid=%d req=0x%llx req_name=%s addr=0x%llx regset=%s data=0x%llx ret=%ld compat=%llu shadowed=%llu\n",
            ++log_seq, tracer_pid, target_pid, request,
            request_name(request), args->local.data4, regset_name(args->local.data4), args->local.data5,
            (long)args->ret, args->local.data6, shadowed);
}

static void before_wait4(hook_fargs4_t *args, void *udata)
{
    char comm[TASK_COMM_LEN];
    char cmdline[CMDLINE_LEN];
    struct ptrace_session *session;
    pid_t tracer_pid;
    pid_t wait_pid;
    unsigned long long status_ptr;
    unsigned long long options;
    int status = WAIT_STOPPED_SIGSTOP;

    (void)udata;
    wait4_seen++;
    if (!current_matches_target(comm, sizeof(comm), cmdline, sizeof(cmdline))) return;

    tracer_pid = current_pid();
    wait_pid = (pid_t)syscall_argn(args, 0);
    status_ptr = syscall_argn(args, 1);
    options = syscall_argn(args, 2);
    session = find_wait_session(tracer_pid, wait_pid);
    if (!session) return;

    args->skip_origin = 1;
    if (!session->wait_reported) {
        if (status_ptr) write_user(status_ptr, &status, sizeof(status));
        session->wait_reported = 1;
        args->ret = (uint64_t)(unsigned int)session->target_pid;
        wait4_faked++;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_wait4_stopped type=wait4 tracer_pid=%d target_pid=%d wait_pid=%d status=0x%x options=0x%llx ret=%d faked=%llu comm=%s cmdline=%s\n",
                ++log_seq, tracer_pid, session->target_pid, wait_pid, status, options, session->target_pid,
                wait4_faked, comm, cmdline);
        return;
    }

    if (options & WAIT_WNOHANG) {
        args->ret = 0;
    } else {
        args->ret = (uint64_t)(long)-ECHILD;
    }
    wait4_faked++;
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=fake_wait4_done type=wait4 tracer_pid=%d target_pid=%d wait_pid=%d options=0x%llx ret=%ld faked=%llu comm=%s cmdline=%s\n",
            ++log_seq, tracer_pid, session->target_pid, wait_pid, options, (long)args->ret, wait4_faked, comm,
            cmdline);
}

static int read_perf_attr(unsigned long long attr_ptr, struct perf_attr_min *attr)
{
    if (!attr_ptr || !attr) return 0;
    return read_user(attr, attr_ptr, sizeof(*attr));
}

static void before_perf_event_open(hook_fargs5_t *args, void *udata)
{
    char comm[TASK_COMM_LEN];
    char cmdline[CMDLINE_LEN];
    struct perf_attr_min attr;
    pid_t pid;
    pid_t tgid;
    long target_pid;
    long cpu;
    long group_fd;
    unsigned long long flags;
    int attr_valid;
    int is_breakpoint = 0;
    int compat = udata != 0;

    (void)compat;
    perf_seen++;
    if (!current_matches_target(comm, sizeof(comm), cmdline, sizeof(cmdline))) {
        pid = current_pid();
        tgid = current_tgid();
        target_pid = (long)syscall_argn(args, 1);
        cpu = (long)syscall_argn(args, 2);
        group_fd = (long)syscall_argn(args, 3);
        flags = syscall_argn(args, 4);
        attr_valid = read_perf_attr(syscall_argn(args, 0), &attr);
        if (attr_valid && attr.type == PERF_TYPE_BREAKPOINT) {
            is_breakpoint = 1;
            perf_unmatched_breakpoints++;
        }
        perf_unmatched++;
        if (is_unmatched_log_sample(perf_unmatched, is_breakpoint)) {
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_unmatched type=perf_event_open pid=%d tgid=%d target_pid=%ld cpu=%ld group_fd=%ld flags=0x%llx attr=0x%llx attr_valid=%d attr_type=%u attr_size=%u bp_type=0x%x bp_addr=0x%llx bp_len=%llu compat=%d unmatched=%llu unmatched_breakpoints=%llu comm=%s cmdline=%s\n",
                    ++log_seq, pid, tgid, target_pid, cpu, group_fd, flags, syscall_argn(args, 0), attr_valid,
                    attr_valid ? attr.type : 0, attr_valid ? attr.size : 0, is_breakpoint ? attr.bp_type : 0,
                    is_breakpoint ? attr.bp_addr : 0, is_breakpoint ? attr.bp_len : 0, compat, perf_unmatched,
                    perf_unmatched_breakpoints, comm, cmdline);
        }
        return;
    }

    perf_matched++;
    pid = current_pid();
    tgid = current_tgid();
    target_pid = (long)syscall_argn(args, 1);
    cpu = (long)syscall_argn(args, 2);
    group_fd = (long)syscall_argn(args, 3);
    flags = syscall_argn(args, 4);
    attr_valid = read_perf_attr(syscall_argn(args, 0), &attr);
    if (attr_valid && attr.type == PERF_TYPE_BREAKPOINT) {
        is_breakpoint = 1;
        perf_breakpoints++;
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_enter type=perf_event_open pid=%d tgid=%d target_pid=%ld cpu=%ld group_fd=%ld flags=0x%llx attr=0x%llx attr_valid=%d attr_type=%u attr_size=%u bp_type=0x%x bp_addr=0x%llx bp_len=%llu compat=%d comm=%s cmdline=%s\n",
            ++log_seq, pid, tgid, target_pid, cpu, group_fd, flags, syscall_argn(args, 0), attr_valid,
            attr_valid ? attr.type : 0, attr_valid ? attr.size : 0, is_breakpoint ? attr.bp_type : 0,
            is_breakpoint ? attr.bp_addr : 0, is_breakpoint ? attr.bp_len : 0, compat, comm, cmdline);

    args->local.data0 = PERF_MAGIC;
    args->local.data1 = is_breakpoint;
    args->local.data2 = (uint64_t)pid;
    args->local.data3 = (uint64_t)tgid;
    args->local.data4 = (uint64_t)target_pid;
    args->local.data5 = is_breakpoint ? attr.bp_addr : 0;
    args->local.data6 = is_breakpoint ? attr.bp_len : 0;
    args->local.data7 = is_breakpoint ? attr.bp_type : 0;

    if (is_breakpoint) {
        perf_blocked++;
        args->ret = -ENOSPC;
        args->skip_origin = 1;
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_blocked type=perf_event_open pid=%d tgid=%d target_pid=%ld ret=%d bp_type=0x%x bp_addr=0x%llx bp_len=%llu blocked=%llu\n",
                ++log_seq, pid, tgid, target_pid, -ENOSPC, attr.bp_type, attr.bp_addr, attr.bp_len, perf_blocked);
    }
}

static void after_perf_event_open(hook_fargs5_t *args, void *udata)
{
    int fd;

    (void)udata;
    if (args->local.data0 != PERF_MAGIC) return;

    if (args->local.data1) {
        args->ret = -ENOSPC;
    }

    fd = (int)(long)args->ret;
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_exit type=perf_event_open ret=%ld is_breakpoint=%llu pid=%d tgid=%d target_pid=%d bp_type=0x%llx bp_addr=0x%llx bp_len=%llu\n",
            ++log_seq, (long)args->ret, args->local.data1, (pid_t)args->local.data2, (pid_t)args->local.data3,
            (pid_t)args->local.data4, args->local.data7, args->local.data5, args->local.data6);

    if ((long)args->ret >= 0 && args->local.data1) {
        track_perf_fd(fd, (pid_t)args->local.data2, (pid_t)args->local.data3, (pid_t)args->local.data4,
                      (long)syscall_argn(args, 2), (long)syscall_argn(args, 3), syscall_argn(args, 4),
                      (unsigned int)args->local.data7, args->local.data5, args->local.data6);
    }
}

static void before_ioctl(hook_fargs3_t *args, void *udata)
{
    struct perf_fd_state *state;
    pid_t tgid = current_tgid();
    int fd = (int)syscall_argn(args, 0);
    unsigned long long cmd = syscall_argn(args, 1);

    (void)udata;
    (void)cmd;
    state = find_perf_fd(tgid, fd);
    if (!state) return;

    perf_fd_events++;
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_ioctl type=perf_fd pid=%d tgid=%d fd=%d cmd=0x%llx cmd_name=%s arg=0x%llx target_pid=%d cpu=%ld group_fd=%ld bp_type=0x%x bp_addr=0x%llx bp_len=%llu events=%llu\n",
            ++log_seq, current_pid(), tgid, fd, cmd, perf_ioctl_name(cmd), syscall_argn(args, 2), state->target_pid,
            state->cpu, state->group_fd, state->bp_type, state->bp_addr, state->bp_len, perf_fd_events);
}

static void before_openat(hook_fargs4_t *args, void *udata)
{
    char comm[TASK_COMM_LEN];
    char cmdline[CMDLINE_LEN];
    char path[STATUS_PATH_LEN];
    pid_t pid;
    pid_t tgid;
    pid_t target_pid;
    int pending_idx;

    args->local.data0 = 0;
    if (!current_matches_target(comm, sizeof(comm), cmdline, sizeof(cmdline))) return;

    if (!read_user_cstr(path, sizeof(path), syscall_argn(args, 1))) return;
    sanitize_log_string(path);
    if (!is_status_path(path)) return;
    status_open_seen++;

    pid = current_pid();
    tgid = current_tgid();
    if (pid < 0 || tgid < 0) return;
    target_pid = parse_status_path_target(path);
    pending_idx = alloc_status_open_pending(pid, tgid, target_pid, syscall_argn(args, 0), syscall_argn(args, 2),
                                            syscall_argn(args, 3), path);

    args->local.data0 = STATUS_OPEN_MAGIC;
    args->local.data1 = (uint64_t)pending_idx;

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=status_open_enter type=proc_status pid=%d tgid=%d target_pid=%d dfd=%lld flags=0x%llx mode=0x%llx path=\"%s\" pending=%d compat=%d comm=%s cmdline=%s\n",
            ++log_seq, pid, tgid, target_pid, (long long)syscall_argn(args, 0), syscall_argn(args, 2),
            syscall_argn(args, 3), path, pending_idx, udata != 0, comm, cmdline);
}

static void after_openat(hook_fargs4_t *args, void *udata)
{
    struct status_open_pending *pending;
    long ret;
    int pending_idx;

    (void)udata;
    if (args->local.data0 != STATUS_OPEN_MAGIC) return;

    pending_idx = (int)args->local.data1;
    if (pending_idx < 0 || pending_idx >= STATUS_OPEN_SLOTS) return;
    pending = &status_open_pending[pending_idx];
    if (!pending->valid) return;

    ret = (long)args->ret;
    if (ret >= 0) {
        track_status_fd((int)ret, pending->owner_tgid, pending->target_pid, pending->path);
        status_open_tracked++;
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=status_open_exit type=proc_status pid=%d tgid=%d target_pid=%d fd=%ld tracked=%d path=\"%s\" tracked_count=%llu active=%d\n",
            ++log_seq, pending->owner_pid, pending->owner_tgid, pending->target_pid, ret, ret >= 0, pending->path,
            status_open_tracked, status_fd_active_count);

    pending->valid = 0;
}

static void before_read(hook_fargs3_t *args, void *udata)
{
    struct perf_fd_state *state;
    struct status_fd_state *status_state;
    pid_t tgid = current_tgid();
    int fd = (int)syscall_argn(args, 0);

    (void)udata;
    args->local.data0 = 0;

    if (status_fd_active_count > 0) {
        status_state = find_status_fd(tgid, fd);
        if (status_state) {
            status_read_seen++;
            args->local.data0 = STATUS_READ_MAGIC;
            args->local.data1 = (uint64_t)fd;
            args->local.data2 = syscall_argn(args, 1);
            args->local.data3 = syscall_argn(args, 2);
            args->local.data4 = (uint64_t)current_pid();
            args->local.data5 = (uint64_t)tgid;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=status_read_enter type=proc_status pid=%d tgid=%d fd=%d target_pid=%d buf=0x%llx count=%llu path=\"%s\"\n",
                    ++log_seq, (pid_t)args->local.data4, tgid, fd, status_state->target_pid, syscall_argn(args, 1),
                    syscall_argn(args, 2), status_state->path);
        }
    }

    state = find_perf_fd(tgid, fd);
    if (!state) return;

    perf_fd_events++;
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_read type=perf_fd pid=%d tgid=%d fd=%d buf=0x%llx count=%llu target_pid=%d bp_type=0x%x bp_addr=0x%llx bp_len=%llu events=%llu\n",
            ++log_seq, current_pid(), tgid, fd, syscall_argn(args, 1), syscall_argn(args, 2), state->target_pid,
            state->bp_type, state->bp_addr, state->bp_len, perf_fd_events);
}

static void after_read(hook_fargs3_t *args, void *udata)
{
    char sample[STATUS_SAMPLE_LEN + 1];
    struct status_fd_state *status_state;
    pid_t reader_pid;
    pid_t tgid;
    int fd;
    int len;
    int max_len;
    long ret;
    int changed;

    (void)udata;
    if (args->local.data0 != STATUS_READ_MAGIC) return;

    ret = (long)args->ret;
    if (ret <= 0 || !args->local.data2) return;

    fd = (int)args->local.data1;
    reader_pid = (pid_t)args->local.data4;
    tgid = (pid_t)args->local.data5;
    status_state = find_status_fd(tgid, fd);
    if (!status_state) return;

    len = ret < STATUS_SAMPLE_LEN ? (int)ret : STATUS_SAMPLE_LEN;
    max_len = args->local.data3 < STATUS_SAMPLE_LEN ? (int)args->local.data3 : STATUS_SAMPLE_LEN;
    if (len <= 0 || max_len <= 0) return;
    if (len > max_len) len = max_len;

    if (!read_user(sample, args->local.data2, len)) return;
    sample[len] = '\0';

    changed = virtualize_status_text(sample, &len, STATUS_SAMPLE_LEN, max_len, status_state, reader_pid);
    if (!changed) return;

    if (!write_user(args->local.data2, sample, len)) return;
    if (len != ret && len <= max_len) args->ret = (uint64_t)len;
    status_read_faked++;

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=status_read_fake type=proc_status pid=%d tgid=%d fd=%d target_pid=%d old_ret=%ld new_ret=%d changed=%d faked=%llu path=\"%s\"\n",
            ++log_seq, reader_pid, tgid, fd, status_state->target_pid, ret, len, changed, status_read_faked,
            status_state->path);
}

static void before_close(hook_fargs1_t *args, void *udata)
{
    struct perf_fd_state *state;
    struct status_fd_state *status_state;
    pid_t tgid = current_tgid();
    int fd = (int)syscall_argn(args, 0);

    (void)udata;
    if (status_fd_active_count > 0) {
        status_state = find_status_fd(tgid, fd);
        if (status_state) {
            status_close_tracked++;
            COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=status_close type=proc_status pid=%d tgid=%d fd=%d target_pid=%d path=\"%s\" closed=%llu\n",
                    ++log_seq, current_pid(), tgid, fd, status_state->target_pid, status_state->path,
                    status_close_tracked);
            remove_status_fd(tgid, fd);
        }
    }

    state = find_perf_fd(tgid, fd);
    if (!state) return;

    perf_fd_events++;
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: logseq=%llu phase=perf_close type=perf_fd pid=%d tgid=%d fd=%d target_pid=%d bp_type=0x%x bp_addr=0x%llx bp_len=%llu events=%llu\n",
            ++log_seq, current_pid(), tgid, fd, state->target_pid, state->bp_type, state->bp_addr, state->bp_len,
            perf_fd_events);
    remove_perf_fd(tgid, fd);
}

static void appendf(char *buf, int outlen, int *len, const char *fmt, ...)
{
    va_list ap;
    int left;
    int written;

    if (!buf || outlen <= 0 || !len || *len >= outlen - 1) return;

    left = outlen - *len;
    va_start(ap, fmt);
    written = vsnprintf(buf + *len, left, fmt, ap);
    va_end(ap);

    if (written < 0) return;
    if (written >= left) {
        *len = outlen - 1;
        buf[*len] = '\0';
    } else {
        *len += written;
    }
}

static void append_status(char *buf, int outlen, int *len)
{
    appendf(buf, outlen, len,
            "shadow-ptrace-hwdebug target=\"%s\" target_tgid=%d get_cmdline=%d task_pid=%d hook_gate=target+tracked-fd read_mode=physical write_mode=physical phys_deps=shared\n"
            "seen=%llu matched=%llu unmatched=%llu faked=%llu stateful_faked=%llu reads=%llu writes=%llu wait4_seen=%llu wait4_faked=%llu phys_failures=%llu shadows=%d sessions=%d\n"
            "perf seen=%llu matched=%llu unmatched=%llu breakpoints=%llu unmatched_breakpoints=%llu blocked=%llu fd_events=%llu fd_slots=%d\n"
            "proc_status open_seen=%llu open_tracked=%llu read_seen=%llu read_faked=%llu close_tracked=%llu fd_active=%d fd_slots=%d\n"
            "hooks native_ptrace=%d compat_ptrace=%d native_perf=%d compat_perf=%d native_ioctl=%d compat_ioctl=%d native_openat=%d compat_openat=%d native_read=%d compat_read=%d native_close=%d compat_close=%d native_wait4=%d compat_wait4=%d\n",
            target_name, READ_ONCE(target_tgid_hint), get_cmdline_fn != 0,
            task_pid_nr_ns_fn != 0,
            ptrace_seen, ptrace_matched,
            ptrace_unmatched, ptrace_faked, stateful_faked, regset_reads, regset_writes, wait4_seen, wait4_faked,
            phys_failures, SHADOW_SLOTS, SESSION_SLOTS,
            perf_seen, perf_matched, perf_unmatched, perf_breakpoints, perf_unmatched_breakpoints, perf_blocked,
            perf_fd_events, PERF_FD_SLOTS,
            status_open_seen, status_open_tracked, status_read_seen, status_read_faked, status_close_tracked,
            status_fd_active_count, STATUS_FD_SLOTS, native_ptrace_hooked, compat_ptrace_hooked,
            native_perf_hooked, compat_perf_hooked, native_ioctl_hooked, compat_ioctl_hooked,
            native_openat_hooked, compat_openat_hooked, native_read_hooked, compat_read_hooked,
            native_close_hooked, compat_close_hooked, native_wait4_hooked, compat_wait4_hooked);
}

long shadow_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    (void)args;
    (void)event;
    (void)reserved;

    reset_fixed_target();
    clear_all_shadows();
    clear_all_sessions();
    clear_all_perf_fds();
    clear_all_status_fds();
    target_tgid_hint = 0;
    log_seq = 0;
    ptrace_seen = 0;
    ptrace_matched = 0;
    ptrace_unmatched = 0;
    ptrace_faked = 0;
    stateful_faked = 0;
    perf_seen = 0;
    perf_matched = 0;
    perf_unmatched = 0;
    perf_unmatched_breakpoints = 0;
    perf_breakpoints = 0;
    perf_blocked = 0;
    perf_fd_events = 0;
    regset_reads = 0;
    regset_writes = 0;
    wait4_seen = 0;
    wait4_faked = 0;
    status_open_seen = 0;
    status_open_tracked = 0;
    status_read_seen = 0;
    status_read_faked = 0;
    status_close_tracked = 0;
    phys_failures = 0;

    task_pid_nr_ns_fn = (typeof(task_pid_nr_ns_fn))kallsyms_lookup_name("__task_pid_nr_ns");
    get_cmdline_fn = (typeof(get_cmdline_fn))kallsyms_lookup_name("get_cmdline");
    err = hook_syscalln(__NR_ptrace, 4, before_ptrace, after_ptrace, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook ptrace: %d\n", err);
        return -EINVAL;
    }
    native_ptrace_hooked = 1;

    err = hook_syscalln(__NR_perf_event_open, 5, before_perf_event_open, after_perf_event_open, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook perf_event_open: %d\n", err);
    } else {
        native_perf_hooked = 1;
    }

    err = hook_syscalln(__NR_ioctl, 3, before_ioctl, 0, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook ioctl: %d\n", err);
    } else {
        native_ioctl_hooked = 1;
    }

    err = hook_syscalln(__NR_openat, 4, before_openat, after_openat, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook openat: %d\n", err);
    } else {
        native_openat_hooked = 1;
    }

    err = hook_syscalln(__NR_read, 3, before_read, after_read, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook read: %d\n", err);
    } else {
        native_read_hooked = 1;
    }

    err = hook_syscalln(__NR_close, 1, before_close, 0, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook close: %d\n", err);
    } else {
        native_close_hooked = 1;
    }

    err = hook_syscalln(__NR_wait4, 4, before_wait4, 0, 0);
    if (err) {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: failed to hook wait4: %d\n", err);
    } else {
        native_wait4_hooked = 1;
    }

    err = hook_compat_syscalln(COMPAT_NR_PTRACE, 4, before_ptrace, after_ptrace, (void *)1);
    if (!err) {
        compat_ptrace_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat ptrace hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_PERF_EVENT_OPEN, 5, before_perf_event_open, after_perf_event_open, (void *)1);
    if (!err) {
        compat_perf_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat perf_event_open hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_IOCTL, 3, before_ioctl, 0, (void *)1);
    if (!err) {
        compat_ioctl_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat ioctl hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_OPENAT, 4, before_openat, after_openat, (void *)1);
    if (!err) {
        compat_openat_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat openat hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_READ, 3, before_read, after_read, (void *)1);
    if (!err) {
        compat_read_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat read hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_CLOSE, 1, before_close, 0, (void *)1);
    if (!err) {
        compat_close_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat close hook skipped: %d\n", err);
    }

    err = hook_compat_syscalln(COMPAT_NR_WAIT4, 4, before_wait4, 0, (void *)1);
    if (!err) {
        compat_wait4_hooked = 1;
    } else {
        COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: compat wait4 hook skipped: %d\n", err);
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: loaded target=%s get_cmdline=%d task_pid=%d read_mode=physical write_mode=physical phys_deps=shared perf_hooks=%d%d ioctl_hooks=%d%d status_open_hooks=%d%d read_hooks=%d%d close_hooks=%d%d wait4_hooks=%d%d\n",
            target_name, get_cmdline_fn != 0, task_pid_nr_ns_fn != 0,
            native_perf_hooked,
            compat_perf_hooked, native_ioctl_hooked, compat_ioctl_hooked, native_openat_hooked,
            compat_openat_hooked, native_read_hooked, compat_read_hooked, native_close_hooked,
            compat_close_hooked, native_wait4_hooked, compat_wait4_hooked);
    return 0;
}

long shadow_control(const char *args, char *__user out_msg, int outlen)
{
    char msg[1024];
    int len = 0;
    const char *cmd = shadow_skip_spaces(args);

    msg[0] = '\0';
    if (!cmd[0] || local_streq(cmd, "status")) {
        append_status(msg, sizeof(msg), &len);
    } else if (local_streq(cmd, "clear")) {
        clear_all_shadows();
        clear_all_sessions();
        clear_all_perf_fds();
        clear_all_status_fds();
        target_tgid_hint = 0;
        ptrace_seen = 0;
        ptrace_matched = 0;
        ptrace_unmatched = 0;
        ptrace_faked = 0;
        stateful_faked = 0;
        perf_seen = 0;
        perf_matched = 0;
        perf_unmatched = 0;
        perf_unmatched_breakpoints = 0;
        perf_breakpoints = 0;
        perf_blocked = 0;
        perf_fd_events = 0;
        regset_reads = 0;
        regset_writes = 0;
        wait4_seen = 0;
        wait4_faked = 0;
        status_open_seen = 0;
        status_open_tracked = 0;
        status_read_seen = 0;
        status_read_faked = 0;
        status_close_tracked = 0;
        phys_failures = 0;
        appendf(msg, sizeof(msg), &len, "shadow-ptrace-hwdebug cleared\n");
        append_status(msg, sizeof(msg), &len);
    } else {
        appendf(msg, sizeof(msg), &len, "unknown command: %s\n", cmd);
        append_status(msg, sizeof(msg), &len);
    }

    if (out_msg && outlen > 0) {
        int copy_len = len + 1;
        if (copy_len > outlen) {
            copy_len = outlen;
            msg[copy_len - 1] = '\0';
        }
        compat_copy_to_user(out_msg, msg, copy_len);
    }

    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: %s", msg);
    return 0;
}

long shadow_exit(void *__user reserved)
{
    (void)reserved;

    if (compat_wait4_hooked) {
        unhook_compat_syscalln(COMPAT_NR_WAIT4, before_wait4, 0);
        compat_wait4_hooked = 0;
    }
    if (native_wait4_hooked) {
        unhook_syscalln(__NR_wait4, before_wait4, 0);
        native_wait4_hooked = 0;
    }
    if (compat_close_hooked) {
        unhook_compat_syscalln(COMPAT_NR_CLOSE, before_close, 0);
        compat_close_hooked = 0;
    }
    if (native_close_hooked) {
        unhook_syscalln(__NR_close, before_close, 0);
        native_close_hooked = 0;
    }
    if (compat_read_hooked) {
        unhook_compat_syscalln(COMPAT_NR_READ, before_read, after_read);
        compat_read_hooked = 0;
    }
    if (native_read_hooked) {
        unhook_syscalln(__NR_read, before_read, after_read);
        native_read_hooked = 0;
    }
    if (compat_openat_hooked) {
        unhook_compat_syscalln(COMPAT_NR_OPENAT, before_openat, after_openat);
        compat_openat_hooked = 0;
    }
    if (native_openat_hooked) {
        unhook_syscalln(__NR_openat, before_openat, after_openat);
        native_openat_hooked = 0;
    }
    if (compat_ioctl_hooked) {
        unhook_compat_syscalln(COMPAT_NR_IOCTL, before_ioctl, 0);
        compat_ioctl_hooked = 0;
    }
    if (native_ioctl_hooked) {
        unhook_syscalln(__NR_ioctl, before_ioctl, 0);
        native_ioctl_hooked = 0;
    }
    if (compat_perf_hooked) {
        unhook_compat_syscalln(COMPAT_NR_PERF_EVENT_OPEN, before_perf_event_open, after_perf_event_open);
        compat_perf_hooked = 0;
    }
    if (native_perf_hooked) {
        unhook_syscalln(__NR_perf_event_open, before_perf_event_open, after_perf_event_open);
        native_perf_hooked = 0;
    }
    if (compat_ptrace_hooked) {
        unhook_compat_syscalln(COMPAT_NR_PTRACE, before_ptrace, after_ptrace);
        compat_ptrace_hooked = 0;
    }
    if (native_ptrace_hooked) {
        unhook_syscalln(__NR_ptrace, before_ptrace, after_ptrace);
        native_ptrace_hooked = 0;
    }
    clear_all_shadows();
    clear_all_sessions();
    clear_all_perf_fds();
    clear_all_status_fds();
    COMBINED_SILENT_LOG("shadow-ptrace-hwdebug: unloaded\n");
    return 0;
}
