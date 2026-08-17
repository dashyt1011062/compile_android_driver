/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef WUJISHADOW_COMPAT_H
#define WUJISHADOW_COMPAT_H

#include <linux/capability.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>

typedef __u8 uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
typedef __s32 int32_t;
typedef __s64 int64_t;

/* KPM exposes kallsyms_lookup_name to its payloads rather than to modules.
 * The module entry point initializes this pointer through a kprobe lookup. */
typedef unsigned long (*wujishadow_kallsyms_lookup_name_t)(const char *name);
extern wujishadow_kallsyms_lookup_name_t ws_kallsyms_lookup_name;
#define kallsyms_lookup_name ws_kallsyms_lookup_name

typedef enum {
    HOOK_NO_ERR = 0,
    HOOK_BAD_ADDRESS = 4095,
    HOOK_DUPLICATED = 4094,
    HOOK_NO_MEM = 4093,
} hook_err_t;

typedef struct {
    union {
        struct {
            uint64_t data0, data1, data2, data3;
            uint64_t data4, data5, data6, data7;
        };
        uint64_t data[8];
    };
} hook_local_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
            uint64_t arg0, arg1, arg2, arg3;
        };
        uint64_t args[4];
    };
} hook_fargs4_t;

typedef hook_fargs4_t hook_fargs1_t;
typedef hook_fargs4_t hook_fargs2_t;
typedef hook_fargs4_t hook_fargs3_t;

typedef struct {
    void *chain;
    int skip_origin;
    hook_local_t local;
    uint64_t ret;
    union {
        struct {
            uint64_t arg0, arg1, arg2, arg3;
            uint64_t arg4, arg5, arg6, arg7;
        };
        uint64_t args[8];
    };
} hook_fargs8_t;

typedef hook_fargs8_t hook_fargs5_t;

static inline uint64_t *wujishadow_syscall_args(void *fargs)
{
    hook_fargs4_t *args = fargs;
    struct pt_regs *regs;

    if (!args || !args->arg0)
        return NULL;
    regs = (struct pt_regs *)(uintptr_t)args->arg0;
    return regs->regs;
}

static inline uint64_t syscall_argn(void *fargs, int n)
{
    uint64_t *args = wujishadow_syscall_args(fargs);
    return args && n >= 0 && n < 8 ? args[n] : 0;
}

static inline void set_syscall_argn(void *fargs, int n, uint64_t value)
{
    uint64_t *args = wujishadow_syscall_args(fargs);
    if (args && n >= 0 && n < 8)
        args[n] = value;
}

static inline int compat_copy_to_user(void __user *to, const void *from,
                                      int size)
{
    return copy_to_user(to, from, size) ? -EFAULT : 0;
}

typedef void (*hook_callback4_t)(hook_fargs4_t *fargs, void *udata);
typedef void (*hook_callback8_t)(hook_fargs8_t *fargs, void *udata);

bool shadow_syscall_should_intercept(int nr, int compat,
                                     const struct pt_regs *regs);

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after,
                         void *udata);
void unhook_syscalln(int nr, void *before, void *after);
hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after,
                                void *udata);
void unhook_compat_syscalln(int nr, void *before, void *after);
hook_err_t hook_wrap3(void *target, void *before, void *after, void *udata);
void hook_unwrap(void *target, void *before, void *after);
void wujishadow_remove_all_hooks(void);
int wujishadow_resolve_kallsyms(void);

#endif
