/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "wujishadow_compat.h"

static const struct {
    int pgd_offset;
} mm_struct_offset = {
    .pgd_offset = offsetof(struct mm_struct, pgd),
};

#define COMBINED_SILENT_LOG(...) do { } while (0)

#define WUJI_HWBP_MAX 8
#define WUJI_HIT_RING_MAX 64
#define WUJI_COMPAT_IO_MAX 65536

#define WUJI_PROC_KEY "9c7e1a3b5d0f2c8e4a6b1d9f3e7c0a2b"

#define PERF_TYPE_BREAKPOINT 5

#define HW_BREAKPOINT_LEN_1 1
#define HW_BREAKPOINT_LEN_2 2
#define HW_BREAKPOINT_LEN_4 4
#define HW_BREAKPOINT_LEN_8 8

#define HW_BREAKPOINT_R 1
#define HW_BREAKPOINT_W 2
#define HW_BREAKPOINT_RW (HW_BREAKPOINT_R | HW_BREAKPOINT_W)
#define HW_BREAKPOINT_X 4

#define WUJI_REQ_NONE 0
#define WUJI_REQ_INSTALL 1
#define WUJI_REQ_UNINSTALL 2
#define WUJI_REQ_CLEAR 3

#define WUJI_CMD_INIT_DEVICE_INFO 1
#define WUJI_CMD_GET_PROCESS_MAPS_COUNT 6
#define WUJI_CMD_GET_PROCESS_MAPS_LIST 7
#define WUJI_CMD_HWBP_OPEN_PROCESS 0x40
#define WUJI_CMD_HWBP_CLOSE_PROCESS 0x41
#define WUJI_CMD_HWBP_READ_PROCESS_MEM 0x42
#define WUJI_CMD_HWBP_WRITE_PROCESS_MEM 0x43
#define WUJI_CMD_HWBP_READ_USER_INSN 0x44
#define WUJI_CMD_HWBP_GET_NUM_BRPS 0x45
#define WUJI_CMD_HWBP_GET_NUM_WRPS 0x46
#define WUJI_CMD_HWBP_INST_PROCESS_HWBP 0x47
#define WUJI_CMD_HWBP_UNINST_PROCESS_HWBP 0x48
#define WUJI_CMD_HWBP_SUSPEND_PROCESS_HWBP 0x49
#define WUJI_CMD_HWBP_RESUME_PROCESS_HWBP 0x4a
#define WUJI_CMD_HWBP_GET_HWBP_HIT_COUNT 0x4b
#define WUJI_CMD_HWBP_GET_HWBP_HIT_DETAIL 0x4c
#define WUJI_CMD_HWBP_CLEAR_HWBP_HIT 0x4d
#define WUJI_CMD_HWBP_SET_TRACE_STEP_COUNT 0x53
#define WUJI_CMD_HWBP_SET_STEP_SIMULATE 0x54
#define WUJI_CMD_HWBP_SET_STEP_FILTER 0x55
#define WUJI_CMD_HWBP_SET_EXEC_BP_RESTORE_MODE 0x56
#define WUJI_CMD_HWBP_GET_DRIVER_LOG 0x5e
#define WUJI_CMD_HWBP_CLEAR_DRIVER_LOG 0x5f
#define WUJI_CMD_HWBP_START_STEP_SESSION 0x60
#define WUJI_CMD_HWBP_GET_STEP_STATUS 0x61
#define WUJI_CMD_HWBP_START_HIT_SESSION 0x63
#define WUJI_CMD_HWBP_STOP_HIT_SESSION 0x64
#define WUJI_CMD_HWBP_GET_HIT_STATUS 0x65
#define WUJI_CMD_HWBP_GET_HWBP_HIT_DETAIL_EX 0x6b
#define WUJI_CMD_HWBP_GET_STATE_SNAPSHOT 0x6c
#define WUJI_CMD_HWBP_CLEAR_STATE_SNAPSHOT 0x6d

#define WUJI_READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#define WUJI_WRITE_ONCE(x, val) \
    do { (*(volatile typeof(x) *)&(x)) = (val); } while (0)
#ifndef UINT64_MAX
#define UINT64_MAX (~0ULL)
#endif

#define WUJI_MEMREMAP_WB 0x00000001UL
#define WUJI_PHYS_ADDR_BITS 48

#define WUJI_PHYS_MAP_LINEAR 0
#define WUJI_PHYS_MAP_MEMREMAP 1
#define WUJI_PHYS_MAP_IOREMAP 2

#define WUJI_HIT_AUX_X1_U16 (1U << 0)

#define WUJI_HIT_FLAG_CAPTURE_X1_U16 (1ULL << 16)
#define WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16 (1ULL << 17)
#define WUJI_HIT_FLAG_SNAPSHOT_HP_OBJECT (1ULL << 18)
#define WUJI_HIT_FLAG_SNAPSHOT_SKILL_CD (1ULL << 19)
#define WUJI_HIT_FLAG_SNAPSHOT_BUFF_TIMER (1ULL << 20)

#define WUJI_SNAPSHOT_TYPE_COORD 1
#define WUJI_SNAPSHOT_TYPE_HP 2
#define WUJI_SNAPSHOT_TYPE_SKILL 3
#define WUJI_SNAPSHOT_TYPE_BUFF 4

#define WUJI_GAMECORE_HP_OBJECT_ACTOR_OFFSET 0x10ULL
#define WUJI_SKILL_COOLDOWN_RAW_OFFSET 0x3cULL
#define WUJI_SKILL_COOLDOWN_PERIOD_RAW_OFFSET 0x44ULL
#define WUJI_BUFF_TIMER_X_OFFSET 0x2b8ULL
#define WUJI_BUFF_TIMER_Y_OFFSET 0x2c0ULL

struct perf_event;
struct perf_sample_data;
struct pid;
struct task_struct;
struct proc_dir_entry;
struct inode;
struct file;
struct kiocb;
struct iov_iter;
struct poll_table_struct;
struct vm_area_struct;

typedef void (*perf_overflow_handler_t)(struct perf_event *event,
                                        struct perf_sample_data *data,
                                        struct pt_regs *regs);
typedef unsigned long (*find_symbol_t)(const char *name);
typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *attr, perf_overflow_handler_t triggered,
    void *context, struct task_struct *task);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef struct task_struct *(*find_get_task_by_vpid_t)(int nr);
typedef struct task_struct *(*find_task_by_pid_t)(int nr);
typedef struct pid *(*find_get_pid_t)(int nr);
typedef struct pid *(*find_vpid_t)(int nr);
typedef struct task_struct *(*pid_task_t)(struct pid *pid, int type);
typedef struct task_struct *(*get_pid_task_t)(struct pid *pid, int type);
typedef void (*put_pid_t)(struct pid *pid);
typedef void (*put_task_struct_t)(struct task_struct *task);
typedef void (*rcu_read_lock_t)(void);
typedef void (*rcu_read_unlock_t)(void);
typedef struct task_struct *(*kthread_create_on_node_t)(
    int (*threadfn)(void *data), void *data, int node, const char *namefmt, ...);
typedef int (*wake_up_process_t)(struct task_struct *tsk);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef void (*user_disable_single_step_t)(struct task_struct *task);
typedef void (*perf_event_disable_inatomic_t)(struct perf_event *event);
typedef void (*perf_event_enable_t)(struct perf_event *event);
typedef unsigned long (*copy_from_user_t)(void *to,
                                          const void __user *from,
                                          unsigned long n);
typedef unsigned long (*copy_to_user_t)(void __user *to,
                                        const void *from,
                                        unsigned long n);
typedef void *(*memremap_t)(uint64_t offset, size_t size,
                            unsigned long flags);
typedef void (*memunmap_t)(void *addr);
typedef int (*pfn_is_map_memory_t)(unsigned long pfn);
typedef int (*pfn_valid_t)(unsigned long pfn);
typedef void *(*ioremap_cache_t)(uint64_t phys, size_t size);
typedef void (*iounmap_t)(void *addr);
typedef struct mm_struct *(*get_task_mm_t)(struct task_struct *task);
typedef void (*mmput_t)(struct mm_struct *mm);
typedef struct proc_dir_entry *(*proc_mkdir_t)(const char *name,
                                               struct proc_dir_entry *parent);
typedef struct proc_dir_entry *(*proc_create_t)(
    const char *name, umode_t mode, struct proc_dir_entry *parent,
    const struct proc_ops *proc_ops);
typedef void (*proc_remove_t)(struct proc_dir_entry *de);

#pragma pack(push, 1)
struct wuji_ioctl_request {
    char cmd;
    uint64_t param1;
    uint64_t param2;
    uint64_t param3;
    uint64_t buf_size;
};

struct wuji_hwbp_hit_count {
    uint64_t hit_total_count;
    uint64_t hit_item_arr_count;
};

struct wuji_user_pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint64_t orig_x0;
    uint64_t syscallno;
};

struct wuji_user_fpsimd_state {
    uint32_t sregs[32];
    uint32_t fpsr;
    uint32_t fpcr;
    uint32_t valid;
};

struct wuji_hwbp_hit_item {
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    struct wuji_user_pt_regs regs_info;
    struct wuji_user_fpsimd_state fpsimd_info;
};

struct wuji_hwbp_hit_item_ex {
    struct wuji_hwbp_hit_item base;
    uint32_t aux_flags;
    uint32_t aux_size;
    uint64_t aux_addr;
    uint8_t aux_data[16];
};

struct wuji_hwbp_hit_aux_capture {
    uint32_t aux_flags;
    uint32_t aux_size;
    uint64_t aux_addr;
    uint8_t aux_data[16];
};

struct wuji_hwbp_hit_status {
    uint32_t running;
    uint32_t done;
    uint32_t stop_reason;
    uint32_t reserved;
    uint64_t requested_hits;
    uint64_t remaining_hits;
};

struct wuji_hwbp_coord_snapshot_item {
    uint64_t handle;
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    uint64_t seq;
    uint64_t x0;
    uint64_t x1;
    uint64_t x8;
    uint64_t x20;
    uint64_t x29;
    uint64_t x30;
    int32_t x;
    int32_t mid;
    int32_t y;
    uint32_t valid;
};

struct wuji_hwbp_hp_snapshot_item {
    uint64_t handle;
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    uint64_t seq;
    uint64_t hp_obj;
    uint64_t actor;
    int32_t hp;
    int32_t maxhp;
    uint32_t valid;
};

struct wuji_hwbp_skill_snapshot_item {
    uint64_t handle;
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    uint64_t seq;
    uint64_t cd_obj;
    uint64_t actor;
    int32_t raw;
    int32_t period_raw;
    int32_t skill_id;
    uint32_t slot;
    uint32_t valid;
};

struct wuji_hwbp_buff_snapshot_item {
    uint64_t handle;
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    uint64_t seq;
    uint64_t timer_object;
    int32_t raw_ms;
    int32_t x;
    int32_t y;
    uint32_t valid;
};

struct wuji_hwbp_hit_state_capture {
    struct wuji_hwbp_hit_aux_capture aux;
    struct wuji_hwbp_coord_snapshot_item coord;
    struct wuji_hwbp_hp_snapshot_item hp;
    struct wuji_hwbp_skill_snapshot_item skill;
    struct wuji_hwbp_buff_snapshot_item buff;
};
#pragma pack(pop)

struct hwbp_slot {
    bool used;
    bool stepping;
    pid_t pid;
    uint64_t addr;
    uint64_t len;
    uint64_t type;
    uint64_t flags;
    uint64_t hits;
    uint64_t last_pc;
    uint64_t step_starts;
    uint64_t step_completes;
    uint64_t last_step_pc;
    uint64_t hit_seq_base;
    uint32_t hit_head;
    uint32_t hit_count;
    struct wuji_hwbp_hit_item hit_ring[WUJI_HIT_RING_MAX];
    struct wuji_hwbp_hit_state_capture capture_ring[WUJI_HIT_RING_MAX];
    struct perf_event *event;
    struct task_struct *step_task;
};

struct wuji_task_ref {
    struct task_struct *task;
    struct pid *pid;
    int task_owned;
    int pid_owned;
};


static register_user_hw_breakpoint_t g_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t g_unregister_hw_breakpoint;
static find_symbol_t g_find_symbol;
static find_get_task_by_vpid_t g_find_get_task_by_vpid;
static find_task_by_pid_t g_find_task_by_pid;
static find_get_pid_t g_find_get_pid;
static find_vpid_t g_find_vpid;
static pid_task_t g_pid_task;
static get_pid_task_t g_get_pid_task;
static put_pid_t g_put_pid;
static put_task_struct_t g_put_task_struct;
static rcu_read_lock_t g_rcu_read_lock;
static rcu_read_unlock_t g_rcu_read_unlock;
static kthread_create_on_node_t g_kthread_create_on_node;
static wake_up_process_t g_wake_up_process;
static user_enable_single_step_t g_user_enable_single_step;
static user_disable_single_step_t g_user_disable_single_step;
static perf_event_disable_inatomic_t g_perf_event_disable_inatomic;
static perf_event_enable_t g_perf_event_enable;
static copy_from_user_t g_copy_from_user;
static copy_to_user_t g_copy_to_user;
static memremap_t g_memremap;
static memunmap_t g_memunmap;
static pfn_is_map_memory_t g_pfn_is_map_memory;
static pfn_valid_t g_pfn_valid;
static ioremap_cache_t g_ioremap_cache;
static iounmap_t g_iounmap;
static int g_ioremap_ready;
static uint64_t *g_memstart_addr;
static int g_phys_page_shift;
static int g_phys_user_va_bits;
static int g_phys_kernel_va_bits;
static get_task_mm_t g_get_task_mm_fn;
static mmput_t g_mmput_fn;
static proc_mkdir_t g_proc_mkdir;
static proc_create_t g_proc_create;
static proc_remove_t g_proc_remove;
static unsigned long g_single_step_handler_addr;
static int g_step_hook_installed;
static struct proc_dir_entry *g_proc_dir;
static struct proc_dir_entry *g_proc_file;
static struct task_struct *g_worker_task;
static struct hwbp_slot g_slots[WUJI_HWBP_MAX];
static char g_compat_io_buf[WUJI_COMPAT_IO_MAX];
static uint64_t g_total_hits;
static uint64_t g_unknown_hits;
static uint64_t g_last_hit_pc;
static uint64_t g_last_hit_event;
static uint64_t g_hit_seq;
static uint64_t g_hit_session_requested;
static uint64_t g_hit_session_remaining;
static uint32_t g_hit_session_running;
static uint32_t g_hit_session_done;
static uint32_t g_hit_session_stop_reason;
static uint64_t g_step_starts;
static uint64_t g_step_completes;
static uint64_t g_step_failures;
static int g_last_step_error;
static uint64_t g_install_attempts;
static uint64_t g_install_failures;
static uint64_t g_uninstall_attempts;
static uint64_t g_uninstall_failures;
static uint64_t g_prepare_attempts;
static uint64_t g_prepare_failures;
static uint64_t g_submit_seq;
static uint64_t g_done_seq;
static volatile int g_req_type;
static volatile int g_worker_alive;
static volatile int g_worker_busy;
static pid_t g_req_pid;
static uint64_t g_req_addr;
static uint64_t g_req_len;
static uint64_t g_req_handle;
static int g_last_resolve_error;
static int g_last_prepare_error;
static int g_last_worker_error;
static const char *g_resolver_name = "none";
static char g_last_worker_msg[256];

static int wuji_hwbp_worker(void *data);
static void wuji_single_step_before(hook_fargs3_t *fargs, void *udata);
static void record_slot_hit(struct hwbp_slot *slot, struct pt_regs *regs,
                            struct task_struct *task);
static void capture_slot_hit_state(struct hwbp_slot *slot,
                                   const struct wuji_hwbp_hit_item *hit,
                                   struct wuji_hwbp_hit_state_capture *capture,
                                   struct task_struct *task);
static void copy_hit_item(struct wuji_hwbp_hit_item *dst,
                          const struct wuji_hwbp_hit_item *src);
static int compat_access_process(pid_t nr, uint64_t addr, void *buf,
                                 size_t size, int write, int user_buf);
static int wuji_copy_task_user_phys_fast(struct task_struct *task,
                                         uint64_t addr, void *buf,
                                         size_t size, int write);
static size_t wuji_min_size(size_t a, size_t b);
static int wuji_user_va_to_phys(uint64_t pgd, uint64_t va, uint64_t *out_phys,
                                size_t *out_page_left);
static int wuji_copy_phys(uint64_t phys, void *buf, size_t size, int write);
static int resolve_compat_uaccess_symbols(void);
static int wuji_get_task_ref(pid_t nr, struct wuji_task_ref *ref);
static void wuji_put_task_ref(struct wuji_task_ref *ref);
static int is_wuji_valid_hp_pair(int32_t hp, int32_t maxhp);
static int is_wuji_plausible_skill_raw(int32_t raw);
static int build_status_reply(char *reply, size_t reply_size);
static ssize_t wuji_compat_proc_read(struct file *file, char __user *buf,
                                     size_t count, loff_t *ppos);

static const struct proc_ops g_wuji_proc_ops = {
    .proc_read = wuji_compat_proc_read,
};

static inline struct task_struct *wuji_current_task(void)
{
    return get_current();
}

static long copy_reply(char *__user out_msg, int outlen, const char *msg)
{
    int len;

    if (!msg) {
        msg = "";
    }

    if (msg && *msg) {
        COMBINED_SILENT_LOG("wuji-hwbp: %s", msg);
    }

    if (!out_msg || outlen <= 0) {
        return 0;
    }

    len = (int)strlen(msg) + 1;
    if (len > outlen) {
        len = outlen;
    }

    if (compat_copy_to_user(out_msg, msg, len)) {
        return -EFAULT;
    }

    return 0;
}

static unsigned long lookup_symbol(const char *name)
{
    unsigned long addr;

    if (!name || !*name) {
        return 0;
    }

    /*
     * SukiSU-Ultra exposes sukisu_compact_find_symbol(), whose address table
     * also provides the KPM-facing "compact_find_symbol" alias.  Do not import
     * ordinary kernel functions as KPM undefined symbols: the KPM loader only
     * resolves its own exported KP symbols at relocation time.  Resolve normal
     * kernel APIs lazily here instead.
     */
    if (!g_find_symbol) {
        if (!kallsyms_lookup_name) {
            g_resolver_name = "missing-kallsyms";
            return 0;
        }

        g_find_symbol =
            (find_symbol_t)kallsyms_lookup_name("sukisu_compact_find_symbol");
        if (g_find_symbol) {
            g_resolver_name = "sukisu_compact_find_symbol";
        } else {
            g_find_symbol = kallsyms_lookup_name;
            g_resolver_name = "kallsyms_lookup_name";
        }
    }

    addr = g_find_symbol(name);
    if (!addr && g_find_symbol != kallsyms_lookup_name && kallsyms_lookup_name) {
        addr = kallsyms_lookup_name(name);
    }

    return addr;
}

static int resolve_symbols(void)
{
    if (g_register_user_hw_breakpoint && g_unregister_hw_breakpoint &&
        ((g_find_get_task_by_vpid && g_put_task_struct) ||
         (g_find_task_by_pid && g_put_task_struct) ||
         (g_find_get_pid && g_put_pid && g_get_pid_task &&
          g_put_task_struct) ||
         (g_find_vpid && g_pid_task && g_rcu_read_lock &&
          g_rcu_read_unlock))) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        g_last_resolve_error = -ENOSYS;
        return -ENOSYS;
    }

    g_register_user_hw_breakpoint =
        (register_user_hw_breakpoint_t)lookup_symbol("register_user_hw_breakpoint");
    g_unregister_hw_breakpoint =
        (unregister_hw_breakpoint_t)lookup_symbol("unregister_hw_breakpoint");
    g_find_get_task_by_vpid =
        (find_get_task_by_vpid_t)lookup_symbol("find_get_task_by_vpid");
    g_find_task_by_pid =
        (find_task_by_pid_t)lookup_symbol("my_get_task_struct_by_pid");
    g_find_get_pid = (find_get_pid_t)lookup_symbol("find_get_pid");
    g_find_vpid = (find_vpid_t)lookup_symbol("find_vpid");
    g_get_pid_task = (get_pid_task_t)lookup_symbol("get_pid_task");
    g_put_task_struct = (put_task_struct_t)lookup_symbol("put_task_struct");
    g_pid_task = (pid_task_t)lookup_symbol("pid_task");
    g_put_pid = (put_pid_t)lookup_symbol("put_pid");
    g_rcu_read_lock =
        (rcu_read_lock_t)lookup_symbol("__rcu_read_lock");
    g_rcu_read_unlock =
        (rcu_read_unlock_t)lookup_symbol("__rcu_read_unlock");

    if (!g_register_user_hw_breakpoint || !g_unregister_hw_breakpoint ||
        !((g_find_get_task_by_vpid && g_put_task_struct) ||
          (g_find_task_by_pid && g_put_task_struct) ||
          (g_find_get_pid && g_put_pid && g_get_pid_task &&
           g_put_task_struct) ||
          (g_find_vpid && g_pid_task && g_rcu_read_lock &&
           g_rcu_read_unlock))) {
        g_last_resolve_error = -ENOSYS;
        COMBINED_SILENT_LOG("wuji-hwbp: required symbols missing resolver=%s hwbp=%px/%px task=%px/%px pid=%px/%px get_pid_task=%px put_task=%px pid_task=%px put_pid=%px rcu=%px/%px\n",
               g_resolver_name, g_register_user_hw_breakpoint,
               g_unregister_hw_breakpoint, g_find_get_task_by_vpid,
               g_find_task_by_pid, g_find_get_pid, g_find_vpid,
               g_get_pid_task, g_put_task_struct, g_pid_task, g_put_pid,
               g_rcu_read_lock, g_rcu_read_unlock);
        return g_last_resolve_error;
    }

    g_last_resolve_error = 0;
    return 0;
}

static int wuji_get_task_ref(pid_t nr, struct wuji_task_ref *ref)
{
    if (!ref || nr <= 0) {
        return -EINVAL;
    }
    memset(ref, 0, sizeof(*ref));

    if (resolve_symbols()) {
        return -ENOSYS;
    }

    if (g_find_get_task_by_vpid && g_put_task_struct) {
        ref->task = g_find_get_task_by_vpid(nr);
        ref->task_owned = ref->task ? 1 : 0;
        return ref->task ? 0 : -ESRCH;
    }

    if (g_find_task_by_pid && g_put_task_struct) {
        ref->task = g_find_task_by_pid(nr);
        ref->task_owned = ref->task ? 1 : 0;
        return ref->task ? 0 : -ESRCH;
    }

    if (g_find_get_pid && g_put_pid && g_get_pid_task &&
        g_put_task_struct) {
        ref->pid = g_find_get_pid(nr);
        ref->pid_owned = ref->pid ? 1 : 0;
        if (!ref->pid) {
            return -ESRCH;
        }
        ref->task = g_get_pid_task(ref->pid, 0);
        ref->task_owned = ref->task ? 1 : 0;
        if (!ref->task) {
            wuji_put_task_ref(ref);
            return -ESRCH;
        }
        return 0;
    }

    /*
     * Some 4.x vendor kernels and 6.12 builds only expose find_vpid() plus
     * pid_task(). Their established physical-memory drivers use the same task
     * pointer after leaving RCU; preserve that fallback for those kernels.
     * It is selected only when no reference-returning lookup API is exported.
     */
    if (g_find_vpid && g_pid_task && g_rcu_read_lock && g_rcu_read_unlock) {
        g_rcu_read_lock();
        ref->pid = g_find_vpid(nr);
        ref->task = ref->pid ? g_pid_task(ref->pid, 0) : NULL;
        g_rcu_read_unlock();
        if (!ref->task) {
            memset(ref, 0, sizeof(*ref));
            return -ESRCH;
        }
        ref->pid = NULL;
        return 0;
    }

    return -ENOSYS;
}

static void wuji_put_task_ref(struct wuji_task_ref *ref)
{
    if (!ref) {
        return;
    }
    if (ref->task_owned && ref->task && g_put_task_struct) {
        g_put_task_struct(ref->task);
    }
    if (ref->pid_owned && ref->pid && g_put_pid) {
        g_put_pid(ref->pid);
    }
    memset(ref, 0, sizeof(*ref));
}

static int resolve_worker_symbols(void)
{
    if (g_kthread_create_on_node && g_wake_up_process) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_kthread_create_on_node =
        (kthread_create_on_node_t)lookup_symbol("kthread_create_on_node");
    g_wake_up_process = (wake_up_process_t)lookup_symbol("wake_up_process");

    if (!g_kthread_create_on_node || !g_wake_up_process) {
        g_last_worker_error = -ENOSYS;
        COMBINED_SILENT_LOG("wuji-hwbp: worker symbols missing create=%px wake=%px\n",
               g_kthread_create_on_node, g_wake_up_process);
        return -ENOSYS;
    }

    return 0;
}

static int start_worker(void)
{
    struct task_struct *task;
    int ret;

    if (WUJI_READ_ONCE(g_worker_alive) || g_worker_task) {
        return -EBUSY;
    }

    ret = resolve_worker_symbols();
    if (ret) {
        return ret;
    }

    task = g_kthread_create_on_node(wuji_hwbp_worker, NULL, -1, "wuji-hwbp");
    if (IS_ERR(task)) {
        ret = (int)PTR_ERR(task);
        COMBINED_SILENT_LOG("wuji-hwbp: failed to create worker ret=%d\n", ret);
        return ret;
    }
    if (!task) {
        COMBINED_SILENT_LOG("wuji-hwbp: kthread_create_on_node returned NULL\n");
        return -ENOMEM;
    }

    g_worker_task = task;
    WUJI_WRITE_ONCE(g_worker_alive, 1);
    g_wake_up_process(task);
    return 0;
}

static int resolve_step_symbols(void)
{
    if (g_user_enable_single_step && g_user_disable_single_step &&
        g_perf_event_disable_inatomic && g_perf_event_enable &&
        g_single_step_handler_addr) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        g_last_step_error = -ENOSYS;
        return -ENOSYS;
    }

    g_user_enable_single_step =
        (user_enable_single_step_t)lookup_symbol("user_enable_single_step");
    g_user_disable_single_step =
        (user_disable_single_step_t)lookup_symbol("user_disable_single_step");
    g_perf_event_disable_inatomic =
        (perf_event_disable_inatomic_t)lookup_symbol("perf_event_disable_inatomic");
    g_perf_event_enable =
        (perf_event_enable_t)lookup_symbol("perf_event_enable");
    g_single_step_handler_addr = lookup_symbol("single_step_handler");

    if (!g_user_enable_single_step || !g_user_disable_single_step ||
        !g_perf_event_disable_inatomic || !g_perf_event_enable ||
        !g_single_step_handler_addr) {
        g_last_step_error = -ENOSYS;
        COMBINED_SILENT_LOG("wuji-hwbp: step symbols missing enable=%px disable=%px perf_disable_inatomic=%px perf_enable=%px single_step_handler=0x%llx\n",
               g_user_enable_single_step, g_user_disable_single_step,
               g_perf_event_disable_inatomic, g_perf_event_enable,
               (unsigned long long)g_single_step_handler_addr);
        return -ENOSYS;
    }

    g_last_step_error = 0;
    return 0;
}

static int ensure_step_hook(void)
{
    hook_err_t err;
    int ret;

    if (g_step_hook_installed) {
        return 0;
    }

    ret = resolve_step_symbols();
    if (ret) {
        return ret;
    }

    err = hook_wrap3((void *)g_single_step_handler_addr,
                     wuji_single_step_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        g_last_step_error = -(int)err;
        COMBINED_SILENT_LOG("wuji-hwbp: hook single_step_handler failed err=%d addr=0x%llx\n",
               err, (unsigned long long)g_single_step_handler_addr);
        return g_last_step_error;
    }

    g_step_hook_installed = 1;
    g_last_step_error = 0;
    COMBINED_SILENT_LOG("wuji-hwbp: hooked single_step_handler addr=0x%llx\n",
            (unsigned long long)g_single_step_handler_addr);
    return 0;
}

static void remove_step_hook(void)
{
    if (!g_step_hook_installed || !g_single_step_handler_addr) {
        return;
    }

    hook_unwrap((void *)g_single_step_handler_addr,
                wuji_single_step_before, NULL);
    g_step_hook_installed = 0;
    COMBINED_SILENT_LOG("wuji-hwbp: unhooked single_step_handler\n");
}

static void wuji_hwbp_handler(struct perf_event *event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    struct task_struct *task;
    uint64_t pc = 0;
    int i;

    (void)data;

    if (regs) {
        pc = regs->pc;
    }

    g_total_hits++;
    g_last_hit_pc = pc;
    g_last_hit_event = (uint64_t)(uintptr_t)event;
    task = wuji_current_task();

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        if (g_slots[i].event != event &&
            (pc < g_slots[i].addr || pc >= g_slots[i].addr + g_slots[i].len)) {
            continue;
        }

        g_slots[i].hits++;
        g_slots[i].last_pc = pc;
        record_slot_hit(&g_slots[i], regs, task);

        if (!task || !g_user_enable_single_step ||
            !g_perf_event_disable_inatomic || !g_step_hook_installed) {
            g_step_failures++;
            if (event && g_perf_event_disable_inatomic) {
                g_perf_event_disable_inatomic(event);
            }
            COMBINED_SILENT_LOG("wuji-hwbp: hit without step support task=%px enable=%px disable_event=%px hook=%d\n",
                   task, g_user_enable_single_step, g_perf_event_disable_inatomic,
                   g_step_hook_installed);
            return;
        }

        if (g_slots[i].stepping) {
            g_step_failures++;
            COMBINED_SILENT_LOG("wuji-hwbp: nested hit slot=%d pid=%d pc=0x%llx step_task=%px current=%px\n",
                   i, g_slots[i].pid, (unsigned long long)pc,
                   g_slots[i].step_task, task);
            return;
        }

        g_slots[i].stepping = true;
        g_slots[i].step_task = task;
        g_slots[i].step_starts++;
        g_step_starts++;
        g_perf_event_disable_inatomic(event);
        g_user_enable_single_step(task);
        return;
    }

    g_unknown_hits++;
}

static void wuji_single_step_before(hook_fargs3_t *fargs, void *udata)
{
    struct task_struct *task;
    struct pt_regs *regs;
    uint64_t pc = 0;
    int i;

    (void)udata;

    task = wuji_current_task();
    regs = fargs ? (struct pt_regs *)(uintptr_t)fargs->arg2 : NULL;
    if (regs) {
        pc = regs->pc;
    }

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used || !g_slots[i].stepping ||
            g_slots[i].step_task != task) {
            continue;
        }

        if (g_user_disable_single_step) {
            g_user_disable_single_step(task);
        }

        if (g_slots[i].event && g_perf_event_enable) {
            g_perf_event_enable(g_slots[i].event);
        }

        g_slots[i].stepping = false;
        g_slots[i].step_task = NULL;
        g_slots[i].step_completes++;
        g_slots[i].last_step_pc = pc;
        g_step_completes++;

        if (fargs) {
            fargs->ret = 0;
            fargs->skip_origin = 1;
        }
        return;
    }
}

static int validate_len(uint64_t len)
{
    return len == HW_BREAKPOINT_LEN_1 || len == HW_BREAKPOINT_LEN_2 ||
           len == HW_BREAKPOINT_LEN_4 || len == HW_BREAKPOINT_LEN_8;
}

static int validate_type(uint64_t type)
{
    return type == HW_BREAKPOINT_X || type == HW_BREAKPOINT_W ||
           type == HW_BREAKPOINT_RW || type == HW_BREAKPOINT_R;
}

static int find_free_slot(void)
{
    int i;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            return i;
        }
    }

    return -1;
}

static int count_active_slots(void)
{
    int i;
    int active = 0;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used) {
            active++;
        }
    }

    return active;
}

static void reset_slot_state(int i)
{
    g_slots[i].used = false;
    g_slots[i].stepping = false;
    g_slots[i].pid = 0;
    g_slots[i].addr = 0;
    g_slots[i].len = 0;
    g_slots[i].type = 0;
    g_slots[i].flags = 0;
    g_slots[i].hits = 0;
    g_slots[i].last_pc = 0;
    g_slots[i].step_starts = 0;
    g_slots[i].step_completes = 0;
    g_slots[i].last_step_pc = 0;
    g_slots[i].hit_seq_base = 0;
    g_slots[i].hit_head = 0;
    g_slots[i].hit_count = 0;
    memset(g_slots[i].capture_ring, 0, sizeof(g_slots[i].capture_ring));
    g_slots[i].event = NULL;
    g_slots[i].step_task = NULL;
}

static void record_slot_hit(struct hwbp_slot *slot, struct pt_regs *regs,
                            struct task_struct *task)
{
    struct wuji_hwbp_hit_item *item;
    uint32_t pos;
    int i;

    if (!slot) {
        return;
    }

    if (slot->hit_count < WUJI_HIT_RING_MAX) {
        pos = (slot->hit_head + slot->hit_count) % WUJI_HIT_RING_MAX;
        slot->hit_count++;
    } else {
        pos = slot->hit_head;
        slot->hit_head = (slot->hit_head + 1) % WUJI_HIT_RING_MAX;
    }

    item = &slot->hit_ring[pos];
    memset(item, 0, sizeof(*item));
    item->task_id = (uint64_t)slot->pid;
    item->hit_addr = slot->addr;
    item->hit_time = ++g_hit_seq;
    slot->hit_seq_base = item->hit_time;

    if (regs) {
        for (i = 0; i < 31; ++i) {
            item->regs_info.regs[i] = regs->regs[i];
        }
        item->regs_info.sp = regs->sp;
        item->regs_info.pc = regs->pc;
        item->regs_info.pstate = regs->pstate;
    }

    capture_slot_hit_state(slot, item, &slot->capture_ring[pos], task);

    if (g_hit_session_running && !g_hit_session_done &&
        g_hit_session_remaining > 0) {
        g_hit_session_remaining--;
        if (g_hit_session_remaining == 0) {
            g_hit_session_done = 1;
            g_hit_session_stop_reason = 1;
        }
    }
}

static int is_wuji_valid_hp_pair(int32_t hp, int32_t maxhp)
{
    return maxhp > 0 && maxhp <= 100000 &&
           hp >= -100000 && hp <= maxhp + 100000;
}

static int is_wuji_plausible_skill_raw(int32_t raw)
{
    return raw >= 0 && (int64_t)raw <= 300LL * 8192000LL;
}

static void capture_slot_hit_state(struct hwbp_slot *slot,
                                   const struct wuji_hwbp_hit_item *hit,
                                   struct wuji_hwbp_hit_state_capture *capture,
                                   struct task_struct *task)
{
    uint64_t handle;

    if (!capture) {
        return;
    }
    memset(capture, 0, sizeof(*capture));

    if (!slot || !hit || !task) {
        return;
    }

    handle = (uint64_t)(uintptr_t)slot->event;

    if ((slot->flags & (WUJI_HIT_FLAG_CAPTURE_X1_U16 |
                        WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16)) &&
        hit->regs_info.regs[1]) {
        int32_t coord[3] = {};

        if (!wuji_copy_task_user_phys_fast(task, hit->regs_info.regs[1],
                                           coord, sizeof(coord), 0)) {
            capture->aux.aux_flags = WUJI_HIT_AUX_X1_U16;
            capture->aux.aux_size = sizeof(coord);
            capture->aux.aux_addr = hit->regs_info.regs[1];
            memcpy(capture->aux.aux_data, coord, sizeof(coord));

            if (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16) {
                capture->coord.handle = handle;
                capture->coord.task_id = hit->task_id;
                capture->coord.hit_addr = hit->hit_addr;
                capture->coord.hit_time = hit->hit_time;
                capture->coord.seq = hit->hit_time;
                capture->coord.x0 = hit->regs_info.regs[0];
                capture->coord.x1 = hit->regs_info.regs[1];
                capture->coord.x8 = hit->regs_info.regs[8];
                capture->coord.x20 = hit->regs_info.regs[20];
                capture->coord.x29 = hit->regs_info.regs[29];
                capture->coord.x30 = hit->regs_info.regs[30];
                capture->coord.x = coord[0];
                capture->coord.mid = coord[1];
                capture->coord.y = coord[2];
                capture->coord.valid = 1;
            }
        }
    }

    if (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_HP_OBJECT) {
        uint64_t hp_obj = hit->regs_info.regs[1] ? hit->regs_info.regs[1]
                                                 : hit->regs_info.regs[19];
        uint64_t actor = 0;
        int32_t hp = (int32_t)(uint32_t)hit->regs_info.regs[22];
        int32_t maxhp = (int32_t)(uint32_t)hit->regs_info.regs[9];

        if (hp_obj && is_wuji_valid_hp_pair(hp, maxhp) &&
            !wuji_copy_task_user_phys_fast(
                task, hp_obj + WUJI_GAMECORE_HP_OBJECT_ACTOR_OFFSET,
                &actor, sizeof(actor), 0) && actor) {
            capture->hp.handle = handle;
            capture->hp.task_id = hit->task_id;
            capture->hp.hit_addr = hit->hit_addr;
            capture->hp.hit_time = hit->hit_time;
            capture->hp.seq = hit->hit_time;
            capture->hp.hp_obj = hp_obj;
            capture->hp.actor = actor;
            capture->hp.hp = hp;
            capture->hp.maxhp = maxhp;
            capture->hp.valid = 1;
        }
    }

    if (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_SKILL_CD) {
        uint64_t cd_obj = hit->regs_info.regs[20];
        int32_t raw = (int32_t)(uint32_t)hit->regs_info.regs[8];
        int32_t period_raw = 0;

        if (cd_obj &&
            hit->regs_info.regs[22] ==
                cd_obj + WUJI_SKILL_COOLDOWN_RAW_OFFSET &&
            is_wuji_plausible_skill_raw(raw)) {
            if (wuji_copy_task_user_phys_fast(
                    task, cd_obj + WUJI_SKILL_COOLDOWN_PERIOD_RAW_OFFSET,
                    &period_raw, sizeof(period_raw), 0) ||
                !is_wuji_plausible_skill_raw(period_raw)) {
                period_raw = 0;
            }

            capture->skill.handle = handle;
            capture->skill.task_id = hit->task_id;
            capture->skill.hit_addr = hit->hit_addr;
            capture->skill.hit_time = hit->hit_time;
            capture->skill.seq = hit->hit_time;
            capture->skill.cd_obj = cd_obj;
            capture->skill.actor = 0;
            capture->skill.raw = raw;
            capture->skill.period_raw = period_raw;
            capture->skill.skill_id = 0;
            capture->skill.slot = 0;
            capture->skill.valid = 1;
        }
    }

    if (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_BUFF_TIMER) {
        uint64_t timer_object = hit->regs_info.regs[0];
        int32_t raw_ms = (int32_t)(uint32_t)hit->regs_info.regs[8];
        int32_t x = 0;
        int32_t y = 0;

        if (timer_object && raw_ms >= 0 && raw_ms <= 900000 &&
            !wuji_copy_task_user_phys_fast(
                task, timer_object + WUJI_BUFF_TIMER_X_OFFSET,
                &x, sizeof(x), 0) &&
            !wuji_copy_task_user_phys_fast(
                task, timer_object + WUJI_BUFF_TIMER_Y_OFFSET,
                &y, sizeof(y), 0)) {
            capture->buff.handle = handle;
            capture->buff.task_id = hit->task_id;
            capture->buff.hit_addr = hit->hit_addr;
            capture->buff.hit_time = hit->hit_time;
            capture->buff.seq = hit->hit_time;
            capture->buff.timer_object = timer_object;
            capture->buff.raw_ms = raw_ms;
            capture->buff.x = x;
            capture->buff.y = y;
            capture->buff.valid = 1;
        }
    }
}

static void fill_hit_extras(struct hwbp_slot *slot,
                            const struct wuji_hwbp_hit_item *src,
                            const struct wuji_hwbp_hit_state_capture *capture,
                            struct wuji_hwbp_hit_item_ex *out)
{
    memset(out, 0, sizeof(*out));
    if (!slot || !src) {
        return;
    }

    copy_hit_item(&out->base, src);

    if ((slot->flags & (WUJI_HIT_FLAG_CAPTURE_X1_U16 |
                        WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16)) == 0) {
        return;
    }

    if (!capture || (capture->aux.aux_flags & WUJI_HIT_AUX_X1_U16) == 0 ||
        capture->aux.aux_size == 0) {
        return;
    }

    out->aux_flags = capture->aux.aux_flags;
    out->aux_size = capture->aux.aux_size;
    out->aux_addr = capture->aux.aux_addr;
    memcpy(out->aux_data, capture->aux.aux_data,
           sizeof(out->aux_data));
}

static void copy_hit_item(struct wuji_hwbp_hit_item *dst,
                          const struct wuji_hwbp_hit_item *src)
{
    int i;

    dst->task_id = src->task_id;
    dst->hit_addr = src->hit_addr;
    dst->hit_time = src->hit_time;
    for (i = 0; i < 31; ++i) {
        dst->regs_info.regs[i] = src->regs_info.regs[i];
    }
    dst->regs_info.sp = src->regs_info.sp;
    dst->regs_info.pc = src->regs_info.pc;
    dst->regs_info.pstate = src->regs_info.pstate;
    dst->regs_info.orig_x0 = src->regs_info.orig_x0;
    dst->regs_info.syscallno = src->regs_info.syscallno;
    for (i = 0; i < 32; ++i) {
        dst->fpsimd_info.sregs[i] = src->fpsimd_info.sregs[i];
    }
    dst->fpsimd_info.fpsr = src->fpsimd_info.fpsr;
    dst->fpsimd_info.fpcr = src->fpsimd_info.fpcr;
    dst->fpsimd_info.valid = src->fpsimd_info.valid;
}

static long worker_uninstall_slot(int i)
{
    struct perf_event *event;
    int ret;

    if (i < 0 || i >= WUJI_HWBP_MAX || !g_slots[i].used) {
        return -ENOENT;
    }

    event = g_slots[i].event;

    if (g_slots[i].stepping && g_slots[i].step_task &&
        g_user_disable_single_step) {
        g_user_disable_single_step(g_slots[i].step_task);
    }
    g_slots[i].stepping = false;
    g_slots[i].step_task = NULL;

    if (event && !g_unregister_hw_breakpoint) {
        ret = resolve_symbols();
        if (ret) {
            return ret;
        }
    }

    if (event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(event);
    }

    reset_slot_state(i);
    return 0;
}

static long worker_uninstall_handle(uint64_t handle)
{
    int i;
    long ret;

    g_uninstall_attempts++;
    g_last_worker_error = 0;
    if (!handle) {
        g_uninstall_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid handle\n");
        return g_last_worker_error;
    }

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used && (uint64_t)(uintptr_t)g_slots[i].event == handle) {
            ret = worker_uninstall_slot(i);
            if (ret) {
                g_uninstall_failures++;
                g_last_worker_error = (int)ret;
                snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                         "error: uninstall handle=0x%llx ret=%ld\n",
                         (unsigned long long)handle, ret);
                return ret;
            }

            snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                     "ok: uninstalled handle=0x%llx slot=%d\n",
                     (unsigned long long)handle, i);
            COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
            if (count_active_slots() == 0) {
                remove_step_hook();
            }
            return 0;
        }
    }

    g_uninstall_failures++;
    g_last_worker_error = -ENOENT;
    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "error: handle not found 0x%llx\n",
             (unsigned long long)handle);
    return -ENOENT;
}

static long worker_uninstall_all(void)
{
    int i;
    int cleared = 0;
    long first_ret = 0;
    long ret;

    g_uninstall_attempts++;
    g_last_worker_error = 0;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        ret = worker_uninstall_slot(i);
        if (ret && !first_ret) {
            first_ret = ret;
        } else if (!ret) {
            cleared++;
        }
    }

    if (first_ret) {
        g_uninstall_failures++;
        g_last_worker_error = (int)first_ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: clear ret=%ld cleared=%d\n", first_ret, cleared);
        COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
        return first_ret;
    }

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "ok: cleared slots=%d\n", cleared);
    COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
    if (count_active_slots() == 0) {
        remove_step_hook();
    }
    return 0;
}

static int append_active_slot_summary(char *buf, size_t buf_size, int off)
{
    int i;

    if (!buf || buf_size == 0) {
        return 0;
    }
    if (off < 0) {
        off = 0;
    }
    if (off >= (int)buf_size) {
        buf[buf_size - 1] = '\0';
        return (int)buf_size - 1;
    }

    for (i = 0; i < WUJI_HWBP_MAX && off < (int)buf_size; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        off += snprintf(buf + off, buf_size - off,
                        " slot%d{pid=%d addr=0x%llx len=%llu type=%llu handle=0x%llx hits=%llu}",
                        i, g_slots[i].pid,
                        (unsigned long long)g_slots[i].addr,
                        (unsigned long long)g_slots[i].len,
                        (unsigned long long)g_slots[i].type,
                        (unsigned long long)(uintptr_t)g_slots[i].event,
                        (unsigned long long)g_slots[i].hits);
        if (off < 0) {
            off = 0;
        } else if (off >= (int)buf_size) {
            off = (int)buf_size - 1;
            buf[off] = '\0';
            break;
        }
    }

    return off;
}

static int slot_pid_is_alive(int i)
{
    struct wuji_task_ref ref;
    int alive;

    if (i < 0 || i >= WUJI_HWBP_MAX || !g_slots[i].used ||
        g_slots[i].pid <= 0) {
        return 0;
    }

    alive = wuji_get_task_ref(g_slots[i].pid, &ref) == 0;
    if (alive) {
        wuji_put_task_ref(&ref);
    }

    return alive;
}

static int reclaim_dead_pid_slots(const char *reason)
{
    int i;
    int reclaimed = 0;
    int failed = 0;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        pid_t pid;
        uint64_t addr;
        uint64_t handle;
        long ret;

        if (!g_slots[i].used || slot_pid_is_alive(i)) {
            continue;
        }

        pid = g_slots[i].pid;
        addr = g_slots[i].addr;
        handle = (uint64_t)(uintptr_t)g_slots[i].event;
        if (g_slots[i].stepping) {
            COMBINED_SILENT_LOG("wuji-hwbp: drop stale stepping state reason=%s slot=%d pid=%d step_task=%px\n",
                    reason ? reason : "unknown", i, pid,
                    g_slots[i].step_task);
            g_slots[i].stepping = false;
            g_slots[i].step_task = NULL;
        }
        ret = worker_uninstall_slot(i);
        if (ret) {
            failed++;
            COMBINED_SILENT_LOG("wuji-hwbp: stale slot reclaim failed reason=%s slot=%d pid=%d addr=0x%llx handle=0x%llx ret=%ld\n",
                    reason ? reason : "unknown", i, pid,
                    (unsigned long long)addr,
                    (unsigned long long)handle, ret);
            continue;
        }

        reclaimed++;
        COMBINED_SILENT_LOG("wuji-hwbp: reclaimed stale slot reason=%s slot=%d pid=%d addr=0x%llx handle=0x%llx\n",
                reason ? reason : "unknown", i, pid,
                (unsigned long long)addr,
                (unsigned long long)handle);
    }

    if (reclaimed && count_active_slots() == 0) {
        remove_step_hook();
    }
    if (reclaimed || failed) {
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "reclaim: reason=%s reclaimed=%d failed=%d active=%d\n",
                 reason ? reason : "unknown", reclaimed, failed,
                 count_active_slots());
        COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
    }

    return reclaimed;
}

static int uninstall_duplicate_breakpoints(pid_t pid, uint64_t addr,
                                           uint64_t len, uint64_t type,
                                           uint64_t flags)
{
    int i;
    int cleared = 0;

    (void)flags;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        uint64_t handle;
        long ret;

        if (!g_slots[i].used || g_slots[i].pid != pid ||
            g_slots[i].addr != addr || g_slots[i].len != len ||
            g_slots[i].type != type) {
            continue;
        }

        handle = (uint64_t)(uintptr_t)g_slots[i].event;
        ret = worker_uninstall_slot(i);
        if (ret) {
            COMBINED_SILENT_LOG("wuji-hwbp: duplicate uninstall failed slot=%d pid=%d addr=0x%llx handle=0x%llx ret=%ld\n",
                    i, pid, (unsigned long long)addr,
                    (unsigned long long)handle, ret);
            continue;
        }

        cleared++;
        COMBINED_SILENT_LOG("wuji-hwbp: replaced duplicate slot=%d pid=%d addr=0x%llx handle=0x%llx\n",
                i, pid, (unsigned long long)addr,
                (unsigned long long)handle);
    }

    if (cleared && count_active_slots() == 0) {
        remove_step_hook();
    }
    return cleared;
}

static long worker_install_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                      uint64_t type, uint64_t flags,
                                      uint64_t *out_handle)
{
    struct perf_event_attr attr;
    struct perf_event *event;
    struct wuji_task_ref task_ref;
    int slot;
    int ret;
    int off;

    g_install_attempts++;
    g_last_worker_error = 0;
    if (pid <= 0 || !addr) {
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid pid/address\n");
        return g_last_worker_error;
    }
    if (!validate_len(len) || !validate_type(type)) {
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid breakpoint length/type\n");
        return g_last_worker_error;
    }

    ret = resolve_symbols();
    if (ret) {
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: required symbols missing ret=%d\n", ret);
        return ret;
    }

    reclaim_dead_pid_slots("pre-install");
    uninstall_duplicate_breakpoints(pid, addr, len, type, flags);

    slot = find_free_slot();
    if (slot < 0) {
        reclaim_dead_pid_slots("slot-full");
        slot = find_free_slot();
    }
    if (slot < 0) {
        g_install_failures++;
        g_last_worker_error = -ENOSPC;
        off = snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                       "error: no free hwbp slot active=%d max=%d",
                       count_active_slots(), WUJI_HWBP_MAX);
        append_active_slot_summary(g_last_worker_msg,
                                   sizeof(g_last_worker_msg), off);
        COMBINED_SILENT_LOG("wuji-hwbp: %s\n", g_last_worker_msg);
        return g_last_worker_error;
    }

    ret = wuji_get_task_ref(pid, &task_ref);
    if (ret) {
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: task not found\n");
        return g_last_worker_error;
    }

    if (flags & (WUJI_HIT_FLAG_CAPTURE_X1_U16 |
                 WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16 |
                 WUJI_HIT_FLAG_SNAPSHOT_HP_OBJECT |
                 WUJI_HIT_FLAG_SNAPSHOT_SKILL_CD |
                 WUJI_HIT_FLAG_SNAPSHOT_BUFF_TIMER)) {
        ret = resolve_compat_uaccess_symbols();
        if (ret) {
            wuji_put_task_ref(&task_ref);
            g_install_failures++;
            g_last_worker_error = ret;
            snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                     "error: uaccess symbols missing ret=%d\n", ret);
            return ret;
        }
    }

    ret = ensure_step_hook();
    if (ret) {
        wuji_put_task_ref(&task_ref);
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: single-step hook unavailable ret=%d\n", ret);
        return ret;
    }

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.bp_type = (uint32_t)type;
    attr.bp_addr = addr;
    attr.bp_len = len;
    attr.disabled = 0;
    attr.pinned = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "worker: registering pid=%d addr=0x%llx len=%llu type=%llu\n",
             pid, (unsigned long long)addr, (unsigned long long)len,
             (unsigned long long)type);
    COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);

    event = g_register_user_hw_breakpoint(&attr, wuji_hwbp_handler, NULL,
                                          task_ref.task);
    wuji_put_task_ref(&task_ref);

    if (IS_ERR(event)) {
        ret = (int)PTR_ERR(event);
        if (count_active_slots() == 0) {
            remove_step_hook();
        }
        g_install_failures++;
        g_last_worker_error = ret;
        if (ret == -ENOSPC) {
            int off;

            reclaim_dead_pid_slots("perf-enospc");
            off = snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                           "error: register_user_hw_breakpoint ret=%d active=%d max=%d requested{pid=%d addr=0x%llx len=%llu type=%llu flags=0x%llx}",
                           ret, count_active_slots(), WUJI_HWBP_MAX, pid,
                           (unsigned long long)addr,
                           (unsigned long long)len,
                           (unsigned long long)type,
                           (unsigned long long)flags);
            append_active_slot_summary(g_last_worker_msg,
                                       sizeof(g_last_worker_msg), off);
        } else {
            snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                     "error: register_user_hw_breakpoint ret=%d requested{pid=%d addr=0x%llx len=%llu type=%llu flags=0x%llx}\n",
                     ret, pid, (unsigned long long)addr,
                     (unsigned long long)len,
                     (unsigned long long)type,
                     (unsigned long long)flags);
        }
        COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
        return ret;
    }
    if (!event) {
        if (count_active_slots() == 0) {
            remove_step_hook();
        }
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: register_user_hw_breakpoint returned NULL\n");
        return g_last_worker_error;
    }

    reset_slot_state(slot);
    g_slots[slot].used = true;
    g_slots[slot].pid = pid;
    g_slots[slot].addr = addr;
    g_slots[slot].len = len;
    g_slots[slot].type = type;
    g_slots[slot].flags = flags;
    g_slots[slot].hits = 0;
    g_slots[slot].last_pc = 0;
    g_slots[slot].event = event;
    if (out_handle) {
        *out_handle = (uint64_t)(uintptr_t)event;
    }

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "ok: slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu type=%llu\n",
             slot, (unsigned long long)(uintptr_t)event, pid,
             (unsigned long long)addr, (unsigned long long)len,
             (unsigned long long)type);
    COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
    return 0;
}

static long worker_install_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len)
{
    return worker_install_breakpoint(pid, addr, len, HW_BREAKPOINT_X, 0, NULL);
}

static int wuji_hwbp_worker(void *data)
{
    int req_type;
    pid_t pid;
    uint64_t addr;
    uint64_t len;
    uint64_t handle;
    long ret;

    (void)data;

    WUJI_WRITE_ONCE(g_worker_alive, 1);
    req_type = WUJI_READ_ONCE(g_req_type);
    pid = g_req_pid;
    addr = g_req_addr;
    len = g_req_len;
    handle = g_req_handle;

    switch (req_type) {
    case WUJI_REQ_INSTALL:
        ret = worker_install_exec_breakpoint(pid, addr, len);
        break;
    case WUJI_REQ_UNINSTALL:
        ret = worker_uninstall_handle(handle);
        break;
    case WUJI_REQ_CLEAR:
        ret = worker_uninstall_all();
        break;
    default:
        ret = -EINVAL;
        g_last_worker_error = (int)ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: unknown worker request=%d\n", req_type);
        COMBINED_SILENT_LOG("wuji-hwbp: %s", g_last_worker_msg);
        break;
    }

    g_last_worker_error = (int)ret;
    g_done_seq = g_submit_seq;
    barrier();
    WUJI_WRITE_ONCE(g_req_type, WUJI_REQ_NONE);
    WUJI_WRITE_ONCE(g_worker_busy, WUJI_REQ_NONE);
    WUJI_WRITE_ONCE(g_worker_alive, 0);
    g_worker_task = NULL;
    return 0;
}

static long submit_worker_request(int req_type, pid_t pid, uint64_t addr,
                                  uint64_t len, uint64_t handle,
                                  char *__user out_msg, int outlen)
{
    char reply[256];
    uint64_t seq;
    int ret;

    if (WUJI_READ_ONCE(g_req_type) != WUJI_REQ_NONE ||
        WUJI_READ_ONCE(g_worker_busy) != WUJI_REQ_NONE ||
        WUJI_READ_ONCE(g_worker_alive) || g_worker_task) {
        snprintf(reply, sizeof(reply),
                 "error: worker busy pending=%d busy=%d alive=%d submit_seq=%llu done_seq=%llu last=%s",
                 WUJI_READ_ONCE(g_req_type), WUJI_READ_ONCE(g_worker_busy),
                 WUJI_READ_ONCE(g_worker_alive),
                 (unsigned long long)g_submit_seq,
                 (unsigned long long)g_done_seq, g_last_worker_msg);
        return copy_reply(out_msg, outlen, reply);
    }

    g_req_pid = pid;
    g_req_addr = addr;
    g_req_len = len;
    g_req_handle = handle;
    seq = ++g_submit_seq;
    barrier();
    WUJI_WRITE_ONCE(g_worker_busy, req_type);
    WUJI_WRITE_ONCE(g_req_type, req_type);

    ret = start_worker();
    if (ret) {
        WUJI_WRITE_ONCE(g_req_type, WUJI_REQ_NONE);
        WUJI_WRITE_ONCE(g_worker_busy, WUJI_REQ_NONE);
        WUJI_WRITE_ONCE(g_worker_alive, 0);
        g_worker_task = NULL;
        g_last_worker_error = ret;
        snprintf(reply, sizeof(reply), "error: worker unavailable ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    snprintf(reply, sizeof(reply),
             "queued: seq=%llu req=%d pid=%d addr=0x%llx len=%llu handle=0x%llx\n",
             (unsigned long long)seq, req_type, pid,
             (unsigned long long)addr, (unsigned long long)len,
             (unsigned long long)handle);
    return copy_reply(out_msg, outlen, reply);
}

static long install_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                    char *__user out_msg, int outlen)
{
    if (pid <= 0 || !addr) {
        return copy_reply(out_msg, outlen, "error: invalid pid/address\n");
    }
    if (!validate_len(len)) {
        return copy_reply(out_msg, outlen, "error: invalid breakpoint length\n");
    }

    return submit_worker_request(WUJI_REQ_INSTALL, pid, addr, len, 0,
                                 out_msg, outlen);
}

static int resolve_compat_proc_symbols(void)
{
    if (g_proc_mkdir && g_proc_create && g_proc_remove) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_proc_mkdir = (proc_mkdir_t)lookup_symbol("proc_mkdir");
    g_proc_create = (proc_create_t)lookup_symbol("proc_create");
    g_proc_remove = (proc_remove_t)lookup_symbol("proc_remove");

    if (!g_proc_mkdir || !g_proc_create || !g_proc_remove) {
        COMBINED_SILENT_LOG("wuji-hwbp: proc symbols missing mkdir=%px create=%px remove=%px\n",
               g_proc_mkdir, g_proc_create, g_proc_remove);
        return -ENOSYS;
    }

    return 0;
}

static int resolve_compat_uaccess_symbols(void)
{
    if (g_copy_from_user && g_copy_to_user) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_copy_from_user = (copy_from_user_t)lookup_symbol("_copy_from_user");
    if (!g_copy_from_user) {
        g_copy_from_user = (copy_from_user_t)lookup_symbol("copy_from_user");
    }
    if (!g_copy_from_user) {
        g_copy_from_user =
            (copy_from_user_t)lookup_symbol("__arch_copy_from_user");
    }
    g_copy_to_user = (copy_to_user_t)lookup_symbol("_copy_to_user");
    if (!g_copy_to_user) {
        g_copy_to_user = (copy_to_user_t)lookup_symbol("copy_to_user");
    }
    if (!g_copy_to_user) {
        g_copy_to_user =
            (copy_to_user_t)lookup_symbol("__arch_copy_to_user");
    }

    if (!g_copy_from_user || !g_copy_to_user) {
        COMBINED_SILENT_LOG("wuji-hwbp: compat uaccess symbols missing copy_from_user=%px copy_to_user=%px\n",
               g_copy_from_user, g_copy_to_user);
        return -ENOSYS;
    }

    return 0;
}

static int resolve_compat_phys_symbols(void)
{
    int ret;

    if (g_get_task_mm_fn && g_mmput_fn &&
        ((g_memremap && g_memunmap) ||
         (g_ioremap_ready && g_ioremap_cache && g_iounmap) ||
         ((g_pfn_is_map_memory || g_pfn_valid) && g_memstart_addr))) {
        return 0;
    }

    ret = resolve_compat_uaccess_symbols();
    if (ret) {
        return ret;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_memremap = (memremap_t)lookup_symbol("memremap");
    g_memunmap = (memunmap_t)lookup_symbol("memunmap");
    g_pfn_is_map_memory =
        (pfn_is_map_memory_t)lookup_symbol("pfn_is_map_memory");
    g_pfn_valid = (pfn_valid_t)lookup_symbol("pfn_valid");
    g_ioremap_cache = (ioremap_cache_t)lookup_symbol("ioremap_cache");
    g_iounmap = (iounmap_t)lookup_symbol("iounmap");
    if (!g_iounmap) {
        g_iounmap = (iounmap_t)lookup_symbol("__iounmap");
    }
    g_ioremap_ready = g_ioremap_cache && g_iounmap ? 1 : 0;
    g_memstart_addr = (uint64_t *)lookup_symbol("memstart_addr");
    g_get_task_mm_fn = (get_task_mm_t)lookup_symbol("get_task_mm");
    g_mmput_fn = (mmput_t)lookup_symbol("mmput");

    if (!g_get_task_mm_fn || !g_mmput_fn ||
        ((!g_memremap || !g_memunmap) &&
         (!g_ioremap_cache || !g_iounmap) &&
         (!(g_pfn_is_map_memory || g_pfn_valid) || !g_memstart_addr))) {
        COMBINED_SILENT_LOG("wuji-hwbp: compat physical symbols missing memremap=%px/%px ioremap=%px/%px pfn=%px/%px memstart=%px get_task_mm=%px mmput=%px\n",
               g_memremap, g_memunmap, g_ioremap_cache, g_iounmap,
               g_pfn_is_map_memory, g_pfn_valid, g_memstart_addr,
               g_get_task_mm_fn, g_mmput_fn);
        return -ENOSYS;
    }

    return 0;
}

static int compat_copy_payload_to_user(void __user *to, const void *from,
                                       size_t size)
{
    if (!to || !from) {
        return -EINVAL;
    }
    if (!size) {
        return 0;
    }
    if (!g_copy_to_user && resolve_compat_uaccess_symbols()) {
        return -ENOSYS;
    }
    return g_copy_to_user(to, from, size) ? -EFAULT : 0;
}

static int create_compat_proc(void)
{
    int ret;

    if (g_proc_file) {
        return 0;
    }

    ret = resolve_compat_proc_symbols();
    if (ret) {
        return ret;
    }

    g_proc_dir = g_proc_mkdir(WUJI_PROC_KEY, NULL);
    if (!g_proc_dir) {
        COMBINED_SILENT_LOG("wuji-hwbp: proc_mkdir failed name=%s\n", WUJI_PROC_KEY);
        return -ENOMEM;
    }

    g_proc_file = g_proc_create(WUJI_PROC_KEY, 0666, g_proc_dir,
                                &g_wuji_proc_ops);
    if (!g_proc_file) {
        g_proc_remove(g_proc_dir);
        g_proc_dir = NULL;
        COMBINED_SILENT_LOG("wuji-hwbp: proc_create failed name=%s/%s\n",
               WUJI_PROC_KEY, WUJI_PROC_KEY);
        return -ENOMEM;
    }

    COMBINED_SILENT_LOG("wuji-hwbp: compat proc ready /proc/%s/%s\n",
            WUJI_PROC_KEY, WUJI_PROC_KEY);
    return 0;
}

static void remove_compat_proc(void)
{
    if (g_proc_file && g_proc_remove) {
        g_proc_remove(g_proc_file);
        g_proc_file = NULL;
    }
    if (g_proc_dir && g_proc_remove) {
        g_proc_remove(g_proc_dir);
        g_proc_dir = NULL;
    }
}

static uint64_t wuji_read_tcr_el1(void)
{
    uint64_t tcr;

    asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
    return tcr;
}

static int wuji_page_shift_from_tcr(void)
{
    uint64_t tg0 = (wuji_read_tcr_el1() >> 14) & 0x3ULL;

    switch (tg0) {
    case 0:
        return 12;
    case 1:
        return 16;
    case 2:
        return 14;
    default:
        return 0;
    }
}

static int wuji_user_va_bits_from_tcr(void)
{
    uint64_t t0sz = wuji_read_tcr_el1() & 0x3fULL;

    if (t0sz >= 64) {
        return 0;
    }

    return 64 - (int)t0sz;
}

static uint64_t wuji_addr_mask_for_shift(int shift)
{
    return (((1ULL << (WUJI_PHYS_ADDR_BITS - shift)) - 1ULL) << shift);
}

static size_t wuji_min_size(size_t a, size_t b)
{
    return a < b ? a : b;
}

/*
 * The arm64 linear map starts at -2^VA_BITS. KPatch's linear_voffset is not
 * a reliable KPM relocation on every loader/kernel combination, so derive
 * the address from TCR_EL1 and memstart_addr.
 */
static int wuji_kernel_va_bits_from_tcr(void)
{
    uint64_t t1sz = (wuji_read_tcr_el1() >> 16) & 0x3fULL;

    if (t1sz >= 64) {
        return 0;
    }

    return 64 - (int)t1sz;
}

static int wuji_cached_page_shift(void)
{
    int value = WUJI_READ_ONCE(g_phys_page_shift);

    if (!value) {
        value = wuji_page_shift_from_tcr();
        WUJI_WRITE_ONCE(g_phys_page_shift, value);
    }

    return value;
}

static int wuji_cached_user_va_bits(void)
{
    int value = WUJI_READ_ONCE(g_phys_user_va_bits);

    if (!value) {
        value = wuji_user_va_bits_from_tcr();
        WUJI_WRITE_ONCE(g_phys_user_va_bits, value);
    }

    return value;
}

static int wuji_cached_kernel_va_bits(void)
{
    int value = WUJI_READ_ONCE(g_phys_kernel_va_bits);

    if (!value) {
        value = wuji_kernel_va_bits_from_tcr();
        WUJI_WRITE_ONCE(g_phys_kernel_va_bits, value);
    }

    return value;
}

static uint64_t wuji_linear_map_base(void)
{
    int bits = wuji_cached_kernel_va_bits();

    if (bits <= 0 || bits >= 64) {
        return 0;
    }

    return ~((1ULL << bits) - 1ULL);
}

static void *wuji_phys_to_linear(uint64_t phys, size_t size)
{
    uint64_t memstart;
    uint64_t base;
    int va_bits;
    int page_shift;

    if ((!g_pfn_is_map_memory && !g_pfn_valid) || !g_memstart_addr || !size) {
        return NULL;
    }

    page_shift = wuji_cached_page_shift();
    if (page_shift <= 0 ||
        (g_pfn_is_map_memory &&
         !g_pfn_is_map_memory((unsigned long)(phys >> page_shift))) ||
        (!g_pfn_is_map_memory && g_pfn_valid &&
         !g_pfn_valid((unsigned long)(phys >> page_shift)))) {
        return NULL;
    }

    memstart = WUJI_READ_ONCE(*g_memstart_addr);
    if (phys < memstart) {
        return NULL;
    }

    va_bits = wuji_cached_kernel_va_bits();
    if (va_bits <= 0 || va_bits >= 64 ||
        phys - memstart >= (1ULL << va_bits)) {
        return NULL;
    }

    base = wuji_linear_map_base();
    if (!base || phys - memstart > UINT64_MAX - base) {
        return NULL;
    }

    /* size is page-bounded by all callers; avoid wrapping the linear VA. */
    if ((uint64_t)size > UINT64_MAX - (phys - memstart + base)) {
        return NULL;
    }

    return (void *)(uintptr_t)((phys - memstart) | base);
}

void *wuji_map_compat_phys(uint64_t phys, size_t size, int *map_kind)
{
    void *mapped;

    if (map_kind) {
        *map_kind = WUJI_PHYS_MAP_LINEAR;
    }

    mapped = wuji_phys_to_linear(phys, size);
    if (mapped) {
        return mapped;
    }

    if (g_memremap && g_memunmap) {
        mapped = g_memremap(phys, size, WUJI_MEMREMAP_WB);
        if (mapped && map_kind) {
            *map_kind = WUJI_PHYS_MAP_MEMREMAP;
        }
        if (mapped) {
            return mapped;
        }
    }

    if (!g_ioremap_ready || !g_ioremap_cache || !g_iounmap) {
        return NULL;
    }
    mapped = g_ioremap_cache(phys, size);
    if (mapped && map_kind) {
        *map_kind = WUJI_PHYS_MAP_IOREMAP;
    }
    return mapped;
}

void wuji_unmap_compat_phys(void *mapped, int map_kind)
{
    if (!mapped) {
        return;
    }
    if (map_kind == WUJI_PHYS_MAP_MEMREMAP && g_memunmap) {
        g_memunmap(mapped);
    } else if (map_kind == WUJI_PHYS_MAP_IOREMAP && g_iounmap) {
        g_iounmap(mapped);
    }
}

static int wuji_copy_task_user_phys_fast(struct task_struct *task,
                                         uint64_t addr, void *buf,
                                         size_t size, int write)
{
    struct mm_struct *mm;
    uint64_t pgd;
    size_t done = 0;
    int ret;

    if (!addr || !buf || !size) {
        return -EINVAL;
    }

    ret = resolve_compat_phys_symbols();
    if (ret) {
        return ret;
    }
    if (!task || !g_get_task_mm_fn || !g_mmput_fn ||
        mm_struct_offset.pgd_offset < 0) {
        return -ENOSYS;
    }

    mm = g_get_task_mm_fn(task);
    if (!mm || IS_ERR(mm)) {
        return -ESRCH;
    }

    pgd = WUJI_READ_ONCE(*(uint64_t *)((uintptr_t)mm +
                                      (uintptr_t)mm_struct_offset.pgd_offset));
    if (!pgd) {
        ret = -EFAULT;
        goto out_mmput;
    }

    while (done < size) {
        uint64_t phys = 0;
        size_t page_left = 0;
        size_t chunk;

        ret = wuji_user_va_to_phys(pgd, addr + done, &phys, &page_left);
        if (ret) {
            goto out_mmput;
        }
        if (!page_left) {
            ret = -EFAULT;
            goto out_mmput;
        }

        chunk = wuji_min_size(size - done, page_left);
        ret = wuji_copy_phys(phys, (char *)buf + done, chunk, write);
        if (ret) {
            goto out_mmput;
        }
        done += chunk;
    }

    ret = 0;

out_mmput:
    g_mmput_fn(mm);
    return ret;
}

int wuji_copy_current_user_phys(uint64_t addr, void *buf, size_t size,
                                int write)
{
    return wuji_copy_task_user_phys_fast(wuji_current_task(), addr, buf, size,
                                         write);
}

static int wuji_user_va_to_phys(uint64_t pgd, uint64_t va, uint64_t *out_phys,
                                size_t *out_page_left)
{
    void *mapped_table = NULL;
    int mapped_table_needs_unmap = 0;
    uint64_t table_va = pgd;
    uint64_t desc = 0;
    uint64_t offset_mask;
    int page_shift = wuji_cached_page_shift();
    int va_bits = wuji_cached_user_va_bits();
    int pxd_bits;
    int page_level;
    int start_level;
    int lv;

    if (!pgd || !out_phys || page_shift <= 0 || va_bits <= 0) {
        return -EINVAL;
    }

    pxd_bits = page_shift - 3;
    page_level = (va_bits - 4) / pxd_bits;
    if (page_level <= 0 || page_level > 4) {
        return -EINVAL;
    }
    start_level = 4 - page_level;

    for (lv = start_level; lv < 4; ++lv) {
        uint64_t pxd_shift = (uint64_t)pxd_bits * (uint64_t)(4 - lv) + 3ULL;
        uint64_t pxd_ptrs = 1ULL << pxd_bits;
        uint64_t pxd_index = (va >> pxd_shift) & (pxd_ptrs - 1ULL);
        uint64_t *entry;
        uint64_t type;

        if (!table_va) {
            wuji_unmap_compat_phys(mapped_table, mapped_table_needs_unmap);
            return -EFAULT;
        }

        entry = (uint64_t *)(uintptr_t)table_va;
        desc = WUJI_READ_ONCE(entry[pxd_index]);
        type = desc & 0x3ULL;

        if (type == 0x3ULL) {
            uint64_t next_pa;

            if (lv == 3) {
                offset_mask = (1ULL << page_shift) - 1ULL;
                *out_phys = (desc & wuji_addr_mask_for_shift(page_shift)) |
                            (va & offset_mask);
                if (out_page_left) {
                    *out_page_left = (size_t)(offset_mask + 1ULL -
                                             (va & offset_mask));
                }
                wuji_unmap_compat_phys(mapped_table,
                                      mapped_table_needs_unmap);
                return 0;
            }

            next_pa = desc & wuji_addr_mask_for_shift(page_shift);
            wuji_unmap_compat_phys(mapped_table, mapped_table_needs_unmap);
            mapped_table = NULL;
            mapped_table_needs_unmap = 0;
            mapped_table = wuji_map_compat_phys(
                next_pa, (size_t)(1ULL << page_shift),
                &mapped_table_needs_unmap);
            if (!mapped_table) {
                return -EFAULT;
            }
            table_va = (uint64_t)(uintptr_t)mapped_table;
            continue;
        }

        if (type == 0x1ULL && lv < 3) {
            int block_bits = (3 - lv) * pxd_bits + page_shift;
            offset_mask = (1ULL << block_bits) - 1ULL;
            *out_phys = (desc & wuji_addr_mask_for_shift(block_bits)) |
                        (va & offset_mask);
            if (out_page_left) {
                uint64_t page_mask = (1ULL << page_shift) - 1ULL;
                *out_page_left = (size_t)(page_mask + 1ULL -
                                         (va & page_mask));
            }
            wuji_unmap_compat_phys(mapped_table,
                                  mapped_table_needs_unmap);
            return 0;
        }

        wuji_unmap_compat_phys(mapped_table, mapped_table_needs_unmap);
        return -EFAULT;
    }

    wuji_unmap_compat_phys(mapped_table, mapped_table_needs_unmap);
    return -EFAULT;
}

static int wuji_copy_phys(uint64_t phys, void *buf, size_t size, int write)
{
    void *mapped;
    int mapped_needs_unmap = 0;
    uint64_t page_mask;
    uint64_t page_base;
    size_t page_off;
    int page_shift = wuji_cached_page_shift();

    if (!buf || !size || page_shift <= 0) {
        return -EINVAL;
    }

    page_mask = (1ULL << page_shift) - 1ULL;
    page_base = phys & ~page_mask;
    page_off = (size_t)(phys & page_mask);
    if (page_off + size > (size_t)(1ULL << page_shift)) {
        return -EINVAL;
    }

    mapped = wuji_map_compat_phys(page_base, (size_t)(1ULL << page_shift),
                                  &mapped_needs_unmap);
    if (!mapped) {
        return -EFAULT;
    }

    if (write) {
        memcpy((char *)mapped + page_off, buf, size);
        dsb(ishst);
    } else {
        memcpy(buf, (char *)mapped + page_off, size);
    }

    wuji_unmap_compat_phys(mapped, mapped_needs_unmap);
    return 0;
}

/* Copy directly between a mapped physical page and the protocol user buffer. */
static int wuji_copy_phys_user(uint64_t phys, void __user *buf, size_t size,
                               int write)
{
    void *mapped;
    int mapped_needs_unmap = 0;
    uint64_t page_mask;
    uint64_t page_base;
    size_t page_off;
    int page_shift = wuji_cached_page_shift();
    unsigned long not_copied;

    if (!buf || !size || page_shift <= 0 ||
        (!g_copy_from_user && write) || (!g_copy_to_user && !write)) {
        return -EINVAL;
    }

    page_mask = (1ULL << page_shift) - 1ULL;
    page_base = phys & ~page_mask;
    page_off = (size_t)(phys & page_mask);
    if (page_off + size > (size_t)(1ULL << page_shift)) {
        return -EINVAL;
    }

    mapped = wuji_map_compat_phys(page_base, (size_t)(1ULL << page_shift),
                                  &mapped_needs_unmap);
    if (!mapped) {
        return -EFAULT;
    }

    if (write) {
        not_copied = g_copy_from_user((char *)mapped + page_off, buf, size);
        if (!not_copied) {
            dsb(ishst);
        }
    } else {
        not_copied = g_copy_to_user(buf, (char *)mapped + page_off, size);
    }

    wuji_unmap_compat_phys(mapped, mapped_needs_unmap);
    return not_copied ? -EFAULT : 0;
}

static int compat_access_process(pid_t nr, uint64_t addr, void *buf,
                                 size_t size, int write, int user_buf)
{
    struct wuji_task_ref task_ref;
    struct mm_struct *mm;
    uint64_t pgd;
    size_t done = 0;
    int ret;

    if (!addr || !buf || size == 0 || size > WUJI_COMPAT_IO_MAX ||
        size > 0x7fffffffU) {
        return -EINVAL;
    }

    ret = resolve_compat_phys_symbols();
    if (ret) {
        return ret;
    }
    if (mm_struct_offset.pgd_offset < 0) {
        COMBINED_SILENT_LOG("wuji-hwbp: physical memory unavailable mm.pgd offset=%d\n",
               mm_struct_offset.pgd_offset);
        return -ENOSYS;
    }

    ret = wuji_get_task_ref(nr, &task_ref);
    if (ret) {
        return ret;
    }

    mm = g_get_task_mm_fn(task_ref.task);
    if (!mm || IS_ERR(mm)) {
        ret = -ESRCH;
        goto out_put_task;
    }

    pgd = WUJI_READ_ONCE(*(uint64_t *)((uintptr_t)mm +
                                      (uintptr_t)mm_struct_offset.pgd_offset));
    if (!pgd) {
        ret = -EFAULT;
        goto out_mmput;
    }

    while (done < size) {
        uint64_t phys = 0;
        size_t page_left = 0;
        size_t chunk;

        ret = wuji_user_va_to_phys(pgd, addr + done, &phys, &page_left);
        if (ret) {
            ret = done ? (int)done : ret;
            goto out_mmput;
        }
        if (!page_left) {
            ret = done ? (int)done : -EFAULT;
            goto out_mmput;
        }

        chunk = wuji_min_size(size - done, page_left);
        if (user_buf) {
            ret = wuji_copy_phys_user(
                phys, (char __user *)buf + done, chunk, user_buf == 2);
        } else {
            ret = wuji_copy_phys(phys, (char *)buf + done, chunk, write);
        }
        if (ret) {
            ret = done ? (int)done : ret;
            goto out_mmput;
        }
        done += chunk;
    }

    ret = (int)done;

out_mmput:
    g_mmput_fn(mm);
out_put_task:
    wuji_put_task_ref(&task_ref);

    return ret;
}

static struct hwbp_slot *find_slot_by_handle(uint64_t handle)
{
    int i;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used &&
            (uint64_t)(uintptr_t)g_slots[i].event == handle) {
            return &g_slots[i];
        }
    }

    return NULL;
}

static ssize_t compat_copy_hit_detail(uint64_t handle, char __user *out,
                                      size_t out_size, int extended)
{
    struct hwbp_slot *slot;
    uint32_t max_items;
    uint32_t copy_count;
    uint32_t i;
    size_t item_size;

    if (!out || out_size == 0 || handle == 0) {
        return -EINVAL;
    }

    slot = find_slot_by_handle(handle);
    if (!slot) {
        return -ENOENT;
    }

    item_size = extended ? sizeof(struct wuji_hwbp_hit_item_ex)
                         : sizeof(struct wuji_hwbp_hit_item);
    max_items = (uint32_t)(out_size / item_size);
    if (max_items == 0) {
        return 0;
    }

    copy_count = slot->hit_count;
    if (copy_count > max_items) {
        copy_count = max_items;
    }

    for (i = 0; i < copy_count; ++i) {
        uint32_t pos = (slot->hit_head + i) % WUJI_HIT_RING_MAX;
        if (extended) {
            struct wuji_hwbp_hit_item_ex ex_item;
            fill_hit_extras(slot, &slot->hit_ring[pos],
                            &slot->capture_ring[pos], &ex_item);
            if (compat_copy_payload_to_user(out + i * item_size, &ex_item,
                                            sizeof(ex_item))) {
                return -EFAULT;
            }
        } else {
            if (compat_copy_payload_to_user(out + i * item_size,
                                            &slot->hit_ring[pos],
                                            sizeof(slot->hit_ring[pos]))) {
                return -EFAULT;
            }
        }
    }

    if (copy_count >= slot->hit_count) {
        slot->hit_head = 0;
        slot->hit_count = 0;
    } else {
        slot->hit_head = (slot->hit_head + copy_count) % WUJI_HIT_RING_MAX;
        slot->hit_count -= copy_count;
    }

    return (ssize_t)copy_count;
}

static int fill_coord_snapshot(struct hwbp_slot *slot,
                               const struct wuji_hwbp_hit_item *hit,
                               const struct wuji_hwbp_hit_state_capture *capture,
                               struct wuji_hwbp_coord_snapshot_item *out)
{
    memset(out, 0, sizeof(*out));
    if (!slot || !hit ||
        (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_COORD_X1_U16) == 0 ||
        !capture || capture->coord.valid == 0) {
        return 0;
    }

    memcpy(out, &capture->coord, sizeof(*out));
    return 1;
}

static int fill_hp_snapshot(struct hwbp_slot *slot,
                            const struct wuji_hwbp_hit_item *hit,
                            const struct wuji_hwbp_hit_state_capture *capture,
                            struct wuji_hwbp_hp_snapshot_item *out)
{
    memset(out, 0, sizeof(*out));
    if (!slot || !hit ||
        (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_HP_OBJECT) == 0 ||
        !capture || capture->hp.valid == 0) {
        return 0;
    }

    memcpy(out, &capture->hp, sizeof(*out));
    return 1;
}

static int fill_skill_snapshot(struct hwbp_slot *slot,
                               const struct wuji_hwbp_hit_item *hit,
                               const struct wuji_hwbp_hit_state_capture *capture,
                               struct wuji_hwbp_skill_snapshot_item *out)
{
    memset(out, 0, sizeof(*out));
    if (!slot || !hit ||
        (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_SKILL_CD) == 0 ||
        !capture || capture->skill.valid == 0) {
        return 0;
    }

    memcpy(out, &capture->skill, sizeof(*out));
    return 1;
}

static int fill_buff_snapshot(struct hwbp_slot *slot,
                              const struct wuji_hwbp_hit_item *hit,
                              const struct wuji_hwbp_hit_state_capture *capture,
                              struct wuji_hwbp_buff_snapshot_item *out)
{
    memset(out, 0, sizeof(*out));
    if (!slot || !hit ||
        (slot->flags & WUJI_HIT_FLAG_SNAPSHOT_BUFF_TIMER) == 0 ||
        !capture || capture->buff.valid == 0) {
        return 0;
    }

    memcpy(out, &capture->buff, sizeof(*out));
    return 1;
}

static size_t state_snapshot_item_size(uint64_t type)
{
    switch (type) {
    case WUJI_SNAPSHOT_TYPE_COORD:
        return sizeof(struct wuji_hwbp_coord_snapshot_item);
    case WUJI_SNAPSHOT_TYPE_HP:
        return sizeof(struct wuji_hwbp_hp_snapshot_item);
    case WUJI_SNAPSHOT_TYPE_SKILL:
        return sizeof(struct wuji_hwbp_skill_snapshot_item);
    case WUJI_SNAPSHOT_TYPE_BUFF:
        return sizeof(struct wuji_hwbp_buff_snapshot_item);
    default:
        return 0;
    }
}

static int snapshot_capture_key(uint64_t type,
                                const struct wuji_hwbp_hit_state_capture *capture,
                                uint64_t *out_key)
{
    uint64_t key = 0;

    if (!capture || !out_key) {
        return 0;
    }

    switch (type) {
    case WUJI_SNAPSHOT_TYPE_COORD:
        if (!capture->coord.valid) {
            return 0;
        }
        key = capture->coord.x0 ? capture->coord.x0 : capture->coord.x1;
        break;
    case WUJI_SNAPSHOT_TYPE_HP:
        if (!capture->hp.valid) {
            return 0;
        }
        key = capture->hp.actor ? capture->hp.actor : capture->hp.hp_obj;
        break;
    case WUJI_SNAPSHOT_TYPE_SKILL:
        if (!capture->skill.valid) {
            return 0;
        }
        key = capture->skill.cd_obj;
        break;
    case WUJI_SNAPSHOT_TYPE_BUFF:
        if (!capture->buff.valid) {
            return 0;
        }
        key = capture->buff.timer_object;
        break;
    default:
        return 0;
    }

    if (!key) {
        return 0;
    }
    *out_key = key;
    return 1;
}

static int has_later_snapshot_for_key(struct hwbp_slot *slot, uint64_t type,
                                      uint32_t start_index, uint64_t key)
{
    uint32_t j;

    if (!slot || !key) {
        return 0;
    }

    for (j = start_index + 1; j < slot->hit_count; ++j) {
        uint32_t pos = (slot->hit_head + j) % WUJI_HIT_RING_MAX;
        uint64_t later_key = 0;

        if (snapshot_capture_key(type, &slot->capture_ring[pos],
                                 &later_key) && later_key == key) {
            return 1;
        }
    }

    return 0;
}

static ssize_t compat_copy_state_snapshot(uint64_t type, uint64_t handle,
                                          char __user *out, size_t out_size)
{
    union {
        struct wuji_hwbp_coord_snapshot_item coord;
        struct wuji_hwbp_hp_snapshot_item hp;
        struct wuji_hwbp_skill_snapshot_item skill;
        struct wuji_hwbp_buff_snapshot_item buff;
    } item;
    uint32_t max_items;
    uint32_t copied = 0;
    size_t item_size;
    int found = 0;
    int i;

    if (!out || out_size == 0) {
        return -EINVAL;
    }

    item_size = state_snapshot_item_size(type);
    if (!item_size) {
        return -EINVAL;
    }

    max_items = (uint32_t)(out_size / item_size);
    if (!max_items) {
        return 0;
    }

    for (i = 0; i < WUJI_HWBP_MAX && copied < max_items; ++i) {
        struct hwbp_slot *slot = &g_slots[i];
        uint32_t j;

        if (!slot->used) {
            continue;
        }
        if (handle && (uint64_t)(uintptr_t)slot->event != handle) {
            continue;
        }
        found = 1;

        for (j = 0; j < slot->hit_count && copied < max_items; ++j) {
            uint32_t pos = (slot->hit_head + j) % WUJI_HIT_RING_MAX;
            struct wuji_hwbp_hit_item *hit = &slot->hit_ring[pos];
            struct wuji_hwbp_hit_state_capture *capture =
                &slot->capture_ring[pos];
            uint64_t key = 0;
            int valid = 0;

            memset(&item, 0, sizeof(item));
            switch (type) {
            case WUJI_SNAPSHOT_TYPE_COORD:
                valid = fill_coord_snapshot(
                    slot, hit, capture,
                    &item.coord);
                break;
            case WUJI_SNAPSHOT_TYPE_HP:
                valid = fill_hp_snapshot(
                    slot, hit, capture,
                    &item.hp);
                break;
            case WUJI_SNAPSHOT_TYPE_SKILL:
                valid = fill_skill_snapshot(
                    slot, hit, capture,
                    &item.skill);
                break;
            case WUJI_SNAPSHOT_TYPE_BUFF:
                valid = fill_buff_snapshot(
                    slot, hit, capture,
                    &item.buff);
                break;
            default:
                return -EINVAL;
            }

            if (!valid) {
                continue;
            }
            if (snapshot_capture_key(type, capture, &key) &&
                has_later_snapshot_for_key(slot, type, j, key)) {
                continue;
            }
            if (compat_copy_payload_to_user(out + copied * item_size,
                                            &item, item_size)) {
                return -EFAULT;
            }
            copied++;
        }
    }

    if (handle && !found) {
        return -ENOENT;
    }

    return (ssize_t)copied;
}

static int compat_clear_state_snapshot(uint64_t type, uint64_t handle)
{
    int found = 0;
    int i;

    if (type && !state_snapshot_item_size(type)) {
        return -EINVAL;
    }

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        struct hwbp_slot *slot = &g_slots[i];

        if (!slot->used) {
            continue;
        }
        if (handle && (uint64_t)(uintptr_t)slot->event != handle) {
            continue;
        }
        found = 1;
        slot->hit_head = 0;
        slot->hit_count = 0;
    }

    if (handle && !found) {
        return -ENOENT;
    }

    return 0;
}

static ssize_t wuji_compat_proc_read(struct file *file, char __user *buf,
                                     size_t count, loff_t *ppos)
{
    struct wuji_ioctl_request req;
    char __user *payload;
    size_t payload_size;
    int ret;

    (void)file;
    (void)ppos;

    if (!buf || count < sizeof(req)) {
        return -EINVAL;
    }

    ret = resolve_compat_uaccess_symbols();
    if (ret) {
        return ret;
    }

    if (g_copy_from_user(&req, buf, sizeof(req))) {
        return -EFAULT;
    }

    payload = buf + sizeof(req);
    payload_size = req.buf_size;
    if (payload_size > count - sizeof(req)) {
        payload_size = count - sizeof(req);
    }

    switch ((unsigned char)req.cmd) {
    case WUJI_CMD_INIT_DEVICE_INFO:
    case WUJI_CMD_HWBP_CLOSE_PROCESS:
    case WUJI_CMD_HWBP_SUSPEND_PROCESS_HWBP:
    case WUJI_CMD_HWBP_RESUME_PROCESS_HWBP:
    case WUJI_CMD_HWBP_SET_TRACE_STEP_COUNT:
    case WUJI_CMD_HWBP_SET_STEP_SIMULATE:
    case WUJI_CMD_HWBP_SET_STEP_FILTER:
    case WUJI_CMD_HWBP_SET_EXEC_BP_RESTORE_MODE:
    case WUJI_CMD_HWBP_START_STEP_SESSION:
        return 0;

    case WUJI_CMD_GET_PROCESS_MAPS_COUNT:
    case WUJI_CMD_GET_PROCESS_MAPS_LIST:
        return -ENOSYS;

    case WUJI_CMD_HWBP_OPEN_PROCESS: {
        uint64_t handle = req.param1;
        struct wuji_task_ref task_ref;

        ret = wuji_get_task_ref((pid_t)req.param1, &task_ref);
        if (ret) {
            return ret;
        }
        wuji_put_task_ref(&task_ref);
        if (payload_size >= sizeof(handle)) {
            ret = compat_copy_payload_to_user(payload, &handle,
                                              sizeof(handle));
            if (ret) {
                return ret;
            }
        }
        return 0;
    }

    case WUJI_CMD_HWBP_READ_PROCESS_MEM:
    case WUJI_CMD_HWBP_READ_USER_INSN: {
        size_t want = payload_size;
        int bytes;

        if ((unsigned char)req.cmd == WUJI_CMD_HWBP_READ_USER_INSN) {
            want = sizeof(uint32_t);
            if (payload_size < want) {
                return -EINVAL;
            }
        }
        if (want > WUJI_COMPAT_IO_MAX) {
            return -EINVAL;
        }

        bytes = compat_access_process((pid_t)req.param1, req.param2,
                                      payload, want, 0, 1);
        if (bytes <= 0) {
            return bytes ? bytes : -EFAULT;
        }
        return bytes;
    }

    case WUJI_CMD_HWBP_WRITE_PROCESS_MEM:
        if (payload_size == 0 || payload_size > WUJI_COMPAT_IO_MAX) {
            return -EINVAL;
        }
        ret = compat_access_process((pid_t)req.param1, req.param2,
                                    payload, payload_size, 1, 2);
        return ret <= 0 ? (ret ? ret : -EFAULT) : ret;

    case WUJI_CMD_HWBP_GET_NUM_BRPS:
    case WUJI_CMD_HWBP_GET_NUM_WRPS: {
        uint64_t num = WUJI_HWBP_MAX;
        if (payload_size >= sizeof(num)) {
            ret = compat_copy_payload_to_user(payload, &num, sizeof(num));
            if (ret) {
                return ret;
            }
        }
        return sizeof(num);
    }

    case WUJI_CMD_HWBP_INST_PROCESS_HWBP: {
        uint64_t handle = 0;
        uint64_t len = req.param3 & 0xffU;
        uint64_t type = (req.param3 >> 8) & 0xffU;
        uint64_t flags = req.param3 & ~0xffffULL;

        ret = worker_install_breakpoint((pid_t)req.param1, req.param2,
                                        len, type, flags, &handle);
        if (ret) {
            return ret;
        }
        if (payload_size >= sizeof(handle)) {
            ret = compat_copy_payload_to_user(payload, &handle,
                                              sizeof(handle));
            if (ret) {
                return ret;
            }
        }
        return 0;
    }

    case WUJI_CMD_HWBP_UNINST_PROCESS_HWBP:
        return worker_uninstall_handle(req.param1);

    case WUJI_CMD_HWBP_CLEAR_HWBP_HIT: {
        struct hwbp_slot *slot = find_slot_by_handle(req.param1);
        if (!req.param1) {
            return worker_uninstall_all();
        }
        if (!slot) {
            return -ENOENT;
        }
        slot->hit_head = 0;
        slot->hit_count = 0;
        return 0;
    }

    case WUJI_CMD_HWBP_GET_HWBP_HIT_COUNT: {
        struct hwbp_slot *slot = find_slot_by_handle(req.param1);
        struct wuji_hwbp_hit_count count_reply;

        if (!slot || payload_size < sizeof(count_reply)) {
            return !slot ? -ENOENT : -EINVAL;
        }
        count_reply.hit_total_count = slot->hits;
        count_reply.hit_item_arr_count = slot->hit_count;
        ret = compat_copy_payload_to_user(payload, &count_reply,
                                          sizeof(count_reply));
        if (ret) {
            return ret;
        }
        return 0;
    }

    case WUJI_CMD_HWBP_GET_HWBP_HIT_DETAIL:
        return compat_copy_hit_detail(req.param1, payload, payload_size, 0);

    case WUJI_CMD_HWBP_GET_HWBP_HIT_DETAIL_EX:
        return compat_copy_hit_detail(req.param1, payload, payload_size, 1);

    case WUJI_CMD_HWBP_START_HIT_SESSION:
        g_hit_session_running = 1;
        g_hit_session_done = 0;
        g_hit_session_stop_reason = 0;
        g_hit_session_requested = req.param1 ? req.param1 : UINT64_MAX;
        g_hit_session_remaining = g_hit_session_requested;
        return 0;

    case WUJI_CMD_HWBP_STOP_HIT_SESSION:
        g_hit_session_running = 0;
        g_hit_session_done = 1;
        g_hit_session_stop_reason = 2;
        return 0;

    case WUJI_CMD_HWBP_GET_HIT_STATUS: {
        struct wuji_hwbp_hit_status status_reply;
        if (payload_size < sizeof(status_reply)) {
            return -EINVAL;
        }
        memset(&status_reply, 0, sizeof(status_reply));
        status_reply.running = g_hit_session_running;
        status_reply.done = g_hit_session_done;
        status_reply.stop_reason = g_hit_session_stop_reason;
        status_reply.requested_hits = g_hit_session_requested;
        status_reply.remaining_hits = g_hit_session_remaining;
        ret = compat_copy_payload_to_user(payload, &status_reply,
                                          sizeof(status_reply));
        if (ret) {
            return ret;
        }
        return sizeof(status_reply);
    }

    case WUJI_CMD_HWBP_GET_DRIVER_LOG: {
        size_t out_size = payload_size;

        if (!payload || out_size == 0) {
            return -EINVAL;
        }
        if (out_size > WUJI_COMPAT_IO_MAX) {
            out_size = WUJI_COMPAT_IO_MAX;
        }

        (void)resolve_symbols();
        (void)resolve_step_symbols();
        (void)resolve_compat_phys_symbols();

        ret = build_status_reply(g_compat_io_buf, out_size);
        if (ret < 0) {
            return ret;
        }
        if ((size_t)ret > out_size) {
            ret = (int)out_size;
        }
        if (compat_copy_payload_to_user(payload, g_compat_io_buf,
                                        (size_t)ret)) {
            return -EFAULT;
        }
        return ret;
    }

    case WUJI_CMD_HWBP_CLEAR_DRIVER_LOG:
        g_last_worker_error = 0;
        g_last_prepare_error = 0;
        g_last_resolve_error = 0;
        g_last_step_error = 0;
        g_last_worker_msg[0] = '\0';
        return 0;

    case WUJI_CMD_HWBP_GET_STATE_SNAPSHOT:
        return compat_copy_state_snapshot(req.param1, req.param2, payload,
                                          payload_size);

    case WUJI_CMD_HWBP_CLEAR_STATE_SNAPSHOT:
        return compat_clear_state_snapshot(req.param1, req.param2);

    default:
        COMBINED_SILENT_LOG("wuji-hwbp: unknown compat cmd=0x%x p1=0x%llx p2=0x%llx p3=0x%llx size=%llu\n",
               (unsigned int)(unsigned char)req.cmd,
               (unsigned long long)req.param1,
               (unsigned long long)req.param2,
               (unsigned long long)req.param3,
               (unsigned long long)req.buf_size);
        return -EINVAL;
    }
}

static long prepare_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                    char *__user out_msg, int outlen)
{
    struct wuji_task_ref task_ref;
    int ret;
    char reply[256];

    g_prepare_attempts++;
    g_last_prepare_error = 0;

    if (pid <= 0 || !addr) {
        g_prepare_failures++;
        g_last_prepare_error = -EINVAL;
        return copy_reply(out_msg, outlen, "error: invalid pid/address\n");
    }
    if (!validate_len(len)) {
        g_prepare_failures++;
        g_last_prepare_error = -EINVAL;
        return copy_reply(out_msg, outlen, "error: invalid breakpoint length\n");
    }

    ret = resolve_symbols();
    if (ret) {
        g_prepare_failures++;
        g_last_prepare_error = ret;
        snprintf(reply, sizeof(reply), "error: required symbols missing ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    ret = resolve_step_symbols();
    if (ret) {
        g_prepare_failures++;
        g_last_prepare_error = ret;
        snprintf(reply, sizeof(reply), "error: step symbols missing ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    ret = wuji_get_task_ref(pid, &task_ref);
    if (ret) {
        g_prepare_failures++;
        g_last_prepare_error = ret;
        return copy_reply(out_msg, outlen, "error: task not found\n");
    }
    wuji_put_task_ref(&task_ref);

    snprintf(reply, sizeof(reply),
             "ok: prepare-only pid=%d addr=0x%llx len=%llu symbols=1 step_symbols=1 install=async-worker\n",
             pid, (unsigned long long)addr, (unsigned long long)len);
    return copy_reply(out_msg, outlen, reply);
}

static int build_status_reply(char *reply, size_t reply_size)
{
    int off = 0;
    int i;
    int symbols_ok;
    int step_symbols_ok;
    int phys_symbols_ok;
    int phys_linear_ok;
    int hit_capture_ok;
    int phys_page_shift;
    int phys_va_bits;
    int phys_kernel_va_bits;

    if (!reply || reply_size == 0) {
        return -EINVAL;
    }
    reply[0] = '\0';

    symbols_ok = g_register_user_hw_breakpoint && g_unregister_hw_breakpoint &&
                 ((g_find_get_task_by_vpid && g_put_task_struct) ||
                  (g_find_task_by_pid && g_put_task_struct) ||
                  (g_find_get_pid && g_put_pid && g_get_pid_task &&
                   g_put_task_struct) ||
                  (g_find_vpid && g_pid_task && g_rcu_read_lock &&
                   g_rcu_read_unlock)) ? 1 : 0;
    step_symbols_ok = g_user_enable_single_step && g_user_disable_single_step &&
                      g_perf_event_disable_inatomic && g_perf_event_enable &&
                      g_single_step_handler_addr ? 1 : 0;
    phys_linear_ok = (g_pfn_is_map_memory || g_pfn_valid) &&
                     g_memstart_addr ? 1 : 0;
    phys_symbols_ok = g_get_task_mm_fn && g_mmput_fn &&
                      ((g_memremap && g_memunmap) ||
                       (g_ioremap_ready && g_ioremap_cache && g_iounmap) ||
                       phys_linear_ok) &&
                      g_copy_from_user && g_copy_to_user &&
                      mm_struct_offset.pgd_offset >= 0 ? 1 : 0;
    phys_page_shift = wuji_cached_page_shift();
    phys_va_bits = wuji_cached_user_va_bits();
    phys_kernel_va_bits = wuji_cached_kernel_va_bits();
    hit_capture_ok = phys_symbols_ok;

    off += snprintf(reply + off, reply_size - off,
                    "wuji-hwbp: mode=single-step+wuji-proc+phys-mem hit_capture=phys:%d slots=%d total_hits=%llu unknown_hits=%llu last_hit_pc=0x%llx last_hit_event=0x%llx hit_session=%u/%u remaining=%llu proc=%d step_starts=%llu step_completes=%llu step_failures=%llu step_symbols=%d step_hook=%d single_step_handler=0x%llx phys_symbols=%d phys_linear=%d page_shift=%d va_bits=%d kernel_va_bits=%d mm_pgd_off=%d last_step=%d install_attempts=%llu install_failures=%llu uninstall_attempts=%llu uninstall_failures=%llu prepare_attempts=%llu prepare_failures=%llu symbols=%d resolver=%s last_resolve=%d last_prepare=%d worker_alive=%d worker_busy=%d pending=%d submit_seq=%llu done_seq=%llu last_worker=%d last_msg=%s\n",
                    hit_capture_ok,
                    WUJI_HWBP_MAX, (unsigned long long)g_total_hits,
                    (unsigned long long)g_unknown_hits,
                    (unsigned long long)g_last_hit_pc,
                    (unsigned long long)g_last_hit_event,
                    g_hit_session_running, g_hit_session_done,
                    (unsigned long long)g_hit_session_remaining,
                    g_proc_file ? 1 : 0,
                    (unsigned long long)g_step_starts,
                    (unsigned long long)g_step_completes,
                    (unsigned long long)g_step_failures,
                    step_symbols_ok, g_step_hook_installed,
                    (unsigned long long)g_single_step_handler_addr,
                    phys_symbols_ok, phys_linear_ok, phys_page_shift,
                    phys_va_bits, phys_kernel_va_bits,
                    mm_struct_offset.pgd_offset,
                    g_last_step_error,
                    (unsigned long long)g_install_attempts,
                    (unsigned long long)g_install_failures,
                    (unsigned long long)g_uninstall_attempts,
                    (unsigned long long)g_uninstall_failures,
                    (unsigned long long)g_prepare_attempts,
                    (unsigned long long)g_prepare_failures,
                    symbols_ok, g_resolver_name, g_last_resolve_error,
                    g_last_prepare_error, WUJI_READ_ONCE(g_worker_alive),
                    WUJI_READ_ONCE(g_worker_busy), WUJI_READ_ONCE(g_req_type),
                    (unsigned long long)g_submit_seq,
                    (unsigned long long)g_done_seq, g_last_worker_error,
                    g_last_worker_msg);

    if (off < 0) {
        off = 0;
    } else if (off >= (int)reply_size) {
        off = (int)reply_size - 1;
    }

    for (i = 0; i < WUJI_HWBP_MAX && off < (int)reply_size; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        off += snprintf(reply + off, reply_size - off,
                        "slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu type=%llu hits=%llu pending_hits=%u last_pc=0x%llx stepping=%d step_starts=%llu step_completes=%llu last_step_pc=0x%llx\n",
                        i, (unsigned long long)(uintptr_t)g_slots[i].event,
                        g_slots[i].pid, (unsigned long long)g_slots[i].addr,
                        (unsigned long long)g_slots[i].len,
                        (unsigned long long)g_slots[i].type,
                        (unsigned long long)g_slots[i].hits,
                        g_slots[i].hit_count,
                        (unsigned long long)g_slots[i].last_pc,
                        g_slots[i].stepping ? 1 : 0,
                        (unsigned long long)g_slots[i].step_starts,
                        (unsigned long long)g_slots[i].step_completes,
                        (unsigned long long)g_slots[i].last_step_pc);
        if (off < 0) {
            off = 0;
        } else if (off >= (int)reply_size) {
            off = (int)reply_size - 1;
        }
    }

    reply[off] = '\0';
    return off + 1;
}

static long status(char *__user out_msg, int outlen)
{
    char *reply;
    long ret;
    int len;

    reply = kmalloc(2048, GFP_KERNEL);
    if (!reply) {
        return -ENOMEM;
    }

    len = build_status_reply(reply, 2048);
    if (len < 0) {
        ret = len;
    } else {
        ret = copy_reply(out_msg, outlen, reply);
    }
    kfree(reply);
    return ret;
}

long wuji_hwbp_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    (void)args;
    (void)event;
    (void)reserved;

    memset(g_slots, 0, sizeof(g_slots));
    g_total_hits = 0;
    g_unknown_hits = 0;
    g_last_hit_pc = 0;
    g_last_hit_event = 0;
    g_hit_seq = 0;
    g_hit_session_requested = 0;
    g_hit_session_remaining = 0;
    g_hit_session_running = 0;
    g_hit_session_done = 0;
    g_hit_session_stop_reason = 0;
    g_step_starts = 0;
    g_step_completes = 0;
    g_step_failures = 0;
    g_last_step_error = 0;
    g_step_hook_installed = 0;
    g_single_step_handler_addr = 0;
    g_install_attempts = 0;
    g_install_failures = 0;
    g_uninstall_attempts = 0;
    g_uninstall_failures = 0;
    g_prepare_attempts = 0;
    g_prepare_failures = 0;
    g_submit_seq = 0;
    g_done_seq = 0;
    g_req_type = WUJI_REQ_NONE;
    g_worker_alive = 0;
    g_worker_busy = WUJI_REQ_NONE;
    g_req_pid = 0;
    g_req_addr = 0;
    g_req_len = 0;
    g_req_handle = 0;
    g_proc_dir = NULL;
    g_proc_file = NULL;
    g_worker_task = NULL;
    g_last_prepare_error = 0;
    g_last_worker_error = 0;
    g_last_worker_msg[0] = '\0';

    ret = resolve_symbols();
    if (ret) {
        COMBINED_SILENT_LOG("wuji-hwbp: loaded without hw breakpoint symbols ret=%d\n", ret);
        return 0;
    }

    ret = create_compat_proc();
    if (ret) {
        COMBINED_SILENT_LOG("wuji-hwbp: loaded without compat proc ret=%d\n", ret);
    }

    COMBINED_SILENT_LOG("wuji-hwbp: loaded async-worker compat-proc=%d\n",
            g_proc_file ? 1 : 0);
    return 0;
}

long wuji_hwbp_control(const char *args, char *__user out_msg, int outlen)
{
    pid_t pid = 0;
    unsigned long long addr = 0;
    unsigned long long len = HW_BREAKPOINT_LEN_4;
    unsigned long long handle = 0;
    int matched;

    if (!args || !*args) {
        return copy_reply(out_msg, outlen,
                          "usage: status | prepare <pid> <hex_addr> [len] | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
    }

    if (!strcmp(args, "status")) {
        (void)resolve_symbols();
        (void)resolve_step_symbols();
        (void)resolve_compat_phys_symbols();
        return status(out_msg, outlen);
    }

    matched = sscanf(args, "install %d %llx %llu", &pid, &addr, &len);
    if (matched >= 2) {
        return install_exec_breakpoint(pid, (uint64_t)addr, (uint64_t)len,
                                       out_msg, outlen);
    }

    len = HW_BREAKPOINT_LEN_4;
    matched = sscanf(args, "prepare %d %llx %llu", &pid, &addr, &len);
    if (matched >= 2) {
        return prepare_exec_breakpoint(pid, (uint64_t)addr, (uint64_t)len,
                                       out_msg, outlen);
    }

    matched = sscanf(args, "uninstall %llx", &handle);
    if (matched == 1) {
        return submit_worker_request(WUJI_REQ_UNINSTALL, 0, 0, 0,
                                     (uint64_t)handle, out_msg, outlen);
    }

    if (!strcmp(args, "clear")) {
        return submit_worker_request(WUJI_REQ_CLEAR, 0, 0, 0, 0,
                                     out_msg, outlen);
    }

    return copy_reply(out_msg, outlen,
                      "error: unknown command; use status | prepare <pid> <hex_addr> [len] | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
}

long wuji_hwbp_exit(void *__user reserved)
{
    int active = 0;
    int i;

    (void)reserved;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used) {
            active++;
        }
    }

    if (WUJI_READ_ONCE(g_worker_alive) ||
        WUJI_READ_ONCE(g_worker_busy) != WUJI_REQ_NONE || g_worker_task) {
        COMBINED_SILENT_LOG("wuji-hwbp: unsafe unload while worker active alive=%d busy=%d active_slots=%d\n",
               WUJI_READ_ONCE(g_worker_alive), WUJI_READ_ONCE(g_worker_busy),
               active);
        return -EBUSY;
    }

    if (active) {
        COMBINED_SILENT_LOG("wuji-hwbp: unsafe unload with active hardware breakpoints active_slots=%d; run clear and wait done first\n",
               active);
        return -EBUSY;
    }

    remove_step_hook();
    remove_compat_proc();
    COMBINED_SILENT_LOG("wuji-hwbp: unloaded idle\n");
    return 0;
}
