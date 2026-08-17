/* SPDX-License-Identifier: GPL-2.0-only */

#include "wujishadow_compat.h"

wujishadow_kallsyms_lookup_name_t ws_kallsyms_lookup_name;

typedef long (*ws_syscall_fn_t)(const struct pt_regs *regs);
typedef void (*ws_step_fn_t)(struct perf_event *event,
                             struct perf_sample_data *data,
                             struct pt_regs *regs);

struct ws_hook_entry {
    int used;
    int compat;
    int nr;
    unsigned long target;
    void *wrapper;
    void *before;
    void *after;
    void *udata;
    struct ftrace_ops ops;
};

static struct ws_hook_entry ws_hooks[16];
static struct ws_hook_entry ws_step_hook;

typedef int (*ws_ftrace_set_filter_ip_t)(struct ftrace_ops *ops,
                                         unsigned long ip, int remove,
                                         int reset);
typedef int (*ws_register_ftrace_function_t)(struct ftrace_ops *ops);
typedef int (*ws_unregister_ftrace_function_t)(struct ftrace_ops *ops);

static ws_ftrace_set_filter_ip_t ws_ftrace_set_filter_ip;
static ws_register_ftrace_function_t ws_register_ftrace_function;
static ws_unregister_ftrace_function_t ws_unregister_ftrace_function;

static int ws_resolve_ftrace(void)
{
    if (ws_ftrace_set_filter_ip && ws_register_ftrace_function &&
        ws_unregister_ftrace_function)
        return 0;
    if (!kallsyms_lookup_name)
        return -ENOSYS;
    ws_ftrace_set_filter_ip = (ws_ftrace_set_filter_ip_t)
        kallsyms_lookup_name("ftrace_set_filter_ip");
    ws_register_ftrace_function = (ws_register_ftrace_function_t)
        kallsyms_lookup_name("register_ftrace_function");
    ws_unregister_ftrace_function = (ws_unregister_ftrace_function_t)
        kallsyms_lookup_name("unregister_ftrace_function");
    return ws_ftrace_set_filter_ip && ws_register_ftrace_function &&
           ws_unregister_ftrace_function ? 0 : -ENOSYS;
}

static struct ws_hook_entry *ws_entry_from_ops(struct ftrace_ops *ops)
{
    if (ops == &ws_step_hook.ops)
        return &ws_step_hook;
    return container_of(ops, struct ws_hook_entry, ops);
}

static void notrace ws_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    struct ws_hook_entry *entry = ws_entry_from_ops(ops);

    (void)ip;
    if (!entry || !entry->used || within_module(parent_ip, THIS_MODULE))
        return;
    ftrace_regs_set_instruction_pointer(fregs,
                                        (unsigned long)entry->wrapper);
}

static const char *ws_syscall_symbol(int nr, int compat)
{
    if (compat) {
        switch (nr) {
        case 26:  return "__arm64_compat_sys_ptrace";
        case 364: return "__arm64_compat_sys_perf_event_open";
        case 54:  return "__arm64_compat_sys_ioctl";
        case 322: return "__arm64_compat_sys_openat";
        case 3:   return "__arm64_compat_sys_read";
        case 6:   return "__arm64_compat_sys_close";
        case 114: return "__arm64_compat_sys_wait4";
        default:  return NULL;
        }
    }

    switch (nr) {
    case __NR_ptrace:          return "__arm64_sys_ptrace";
    case __NR_perf_event_open: return "__arm64_sys_perf_event_open";
    case __NR_ioctl:           return "__arm64_sys_ioctl";
    case __NR_openat:          return "__arm64_sys_openat";
    case __NR_read:            return "__arm64_sys_read";
    case __NR_close:           return "__arm64_sys_close";
    case __NR_wait4:           return "__arm64_sys_wait4";
    default:                   return NULL;
    }
}

static long ws_call_syscall(struct ws_hook_entry *entry,
                            const struct pt_regs *regs)
{
    hook_fargs8_t args;
    ws_syscall_fn_t origin;
    long ret;

    memset(&args, 0, sizeof(args));
    args.arg0 = (uint64_t)(uintptr_t)regs;
    origin = (ws_syscall_fn_t)(uintptr_t)entry->target;

    if (entry->before)
        ((hook_callback_t)entry->before)(&args, entry->udata);

    if (!args.skip_origin)
        args.ret = (uint64_t)origin(regs);

    if (entry->after)
        ((hook_callback_t)entry->after)(&args, entry->udata);

    ret = (long)args.ret;
    return ret;
}

#define WS_SYSCALL_WRAPPER(name, index) \
    static asmlinkage long ws_##name(const struct pt_regs *regs) \
    { return ws_call_syscall(&ws_hooks[index], regs); }

WS_SYSCALL_WRAPPER(native_ptrace, 0)
WS_SYSCALL_WRAPPER(native_perf, 1)
WS_SYSCALL_WRAPPER(native_ioctl, 2)
WS_SYSCALL_WRAPPER(native_openat, 3)
WS_SYSCALL_WRAPPER(native_read, 4)
WS_SYSCALL_WRAPPER(native_close, 5)
WS_SYSCALL_WRAPPER(native_wait4, 6)
WS_SYSCALL_WRAPPER(compat_ptrace, 7)
WS_SYSCALL_WRAPPER(compat_perf, 8)
WS_SYSCALL_WRAPPER(compat_ioctl, 9)
WS_SYSCALL_WRAPPER(compat_openat, 10)
WS_SYSCALL_WRAPPER(compat_read, 11)
WS_SYSCALL_WRAPPER(compat_close, 12)
WS_SYSCALL_WRAPPER(compat_wait4, 13)

static void *ws_wrapper_for(int index)
{
    static void *const wrappers[] = {
        ws_native_ptrace, ws_native_perf, ws_native_ioctl,
        ws_native_openat, ws_native_read, ws_native_close, ws_native_wait4,
        ws_compat_ptrace, ws_compat_perf, ws_compat_ioctl,
        ws_compat_openat, ws_compat_read, ws_compat_close, ws_compat_wait4,
    };

    return index >= 0 && index < ARRAY_SIZE(wrappers) ? wrappers[index] : NULL;
}

static int ws_hook_index(int nr, int compat)
{
    if (compat) {
        switch (nr) {
        case 26:  return 7;
        case 364: return 8;
        case 54:  return 9;
        case 322: return 10;
        case 3:   return 11;
        case 6:   return 12;
        case 114: return 13;
        default:  return -1;
        }
    }

    switch (nr) {
    case __NR_ptrace:           return 0;
    case __NR_perf_event_open: return 1;
    case __NR_ioctl:            return 2;
    case __NR_openat:           return 3;
    case __NR_read:             return 4;
    case __NR_close:            return 5;
    case __NR_wait4:            return 6;
    default:                    return -1;
    }
}

static hook_err_t ws_install_ftrace(struct ws_hook_entry *entry)
{
    int ret;

    ret = ws_resolve_ftrace();
    if (ret)
        return HOOK_BAD_ADDRESS;

    entry->ops.func = ws_ftrace_thunk;
    entry->ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                       FTRACE_OPS_FL_RECURSION |
                       FTRACE_OPS_FL_IPMODIFY;
    ret = ws_ftrace_set_filter_ip(&entry->ops, entry->target, 0, 0);
    if (ret)
        return HOOK_BAD_ADDRESS;
    ret = ws_register_ftrace_function(&entry->ops);
    if (ret) {
        ws_ftrace_set_filter_ip(&entry->ops, entry->target, 1, 0);
        return HOOK_BAD_ADDRESS;
    }
    entry->used = 1;
    return HOOK_NO_ERR;
}

static void ws_remove_ftrace(struct ws_hook_entry *entry)
{
    if (!entry || !entry->used)
        return;
    ws_unregister_ftrace_function(&entry->ops);
    ws_ftrace_set_filter_ip(&entry->ops, entry->target, 1, 0);
    memset(entry, 0, sizeof(*entry));
}

static struct ws_hook_entry *ws_find_entry(int nr, int compat,
                                           void *before, void *after)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ws_hooks); ++i) {
        if (ws_hooks[i].used && ws_hooks[i].nr == nr &&
            ws_hooks[i].compat == compat && ws_hooks[i].before == before &&
            ws_hooks[i].after == after)
            return &ws_hooks[i];
    }
    return NULL;
}

static hook_err_t ws_hook_syscall(int nr, int compat, void *before,
                                  void *after, void *udata)
{
    struct ws_hook_entry *entry;
    const char *symbol;
    int index;

    if (ws_find_entry(nr, compat, before, after))
        return HOOK_DUPLICATED;
    index = ws_hook_index(nr, compat);
    symbol = ws_syscall_symbol(nr, compat);
    if (index < 0 || !symbol || !kallsyms_lookup_name)
        return HOOK_BAD_ADDRESS;
    entry = &ws_hooks[index];
    if (entry->used)
        return HOOK_DUPLICATED;
    memset(entry, 0, sizeof(*entry));
    entry->nr = nr;
    entry->compat = compat;
    entry->before = before;
    entry->after = after;
    entry->udata = udata;
    entry->wrapper = ws_wrapper_for(index);
    entry->target = kallsyms_lookup_name(symbol);
    if (!entry->target)
        return HOOK_BAD_ADDRESS;
    return ws_install_ftrace(entry);
}

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after,
                         void *udata)
{
    (void)narg;
    return ws_hook_syscall(nr, 0, before, after, udata);
}

void unhook_syscalln(int nr, void *before, void *after)
{
    struct ws_hook_entry *entry = ws_find_entry(nr, 0, before, after);
    ws_remove_ftrace(entry);
}

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after,
                                void *udata)
{
    (void)narg;
    return ws_hook_syscall(nr, 1, before, after, udata);
}

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    struct ws_hook_entry *entry = ws_find_entry(nr, 1, before, after);
    ws_remove_ftrace(entry);
}

static void ws_step_dispatch(struct ws_hook_entry *entry,
                             struct perf_event *event,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    hook_fargs4_t args;
    ws_step_fn_t origin;

    memset(&args, 0, sizeof(args));
    args.arg0 = (uint64_t)(uintptr_t)event;
    args.arg1 = (uint64_t)(uintptr_t)data;
    args.arg2 = (uint64_t)(uintptr_t)regs;
    origin = (ws_step_fn_t)(uintptr_t)entry->target;
    if (entry->before)
        ((hook_callback_t)entry->before)(&args, entry->udata);
    if (!args.skip_origin)
        origin(event, data, regs);
    if (entry->after)
        ((hook_callback_t)entry->after)(&args, entry->udata);
}

static void ws_step_wrapper(struct perf_event *event,
                            struct perf_sample_data *data,
                            struct pt_regs *regs)
{
    ws_step_dispatch(&ws_step_hook, event, data, regs);
}

hook_err_t hook_wrap3(void *target, void *before, void *after, void *udata)
{
    if (!target || ws_step_hook.used)
        return HOOK_DUPLICATED;
    memset(&ws_step_hook, 0, sizeof(ws_step_hook));
    ws_step_hook.target = (unsigned long)target;
    ws_step_hook.wrapper = ws_step_wrapper;
    ws_step_hook.before = before;
    ws_step_hook.after = after;
    ws_step_hook.udata = udata;
    return ws_install_ftrace(&ws_step_hook);
}

void hook_unwrap(void *target, void *before, void *after)
{
    if (ws_step_hook.used && ws_step_hook.target == (unsigned long)target &&
        ws_step_hook.before == before && ws_step_hook.after == after)
        ws_remove_ftrace(&ws_step_hook);
}

void wujishadow_remove_all_hooks(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ws_hooks); ++i)
        ws_remove_ftrace(&ws_hooks[i]);
    ws_remove_ftrace(&ws_step_hook);
}

int wujishadow_resolve_kallsyms(void)
{
    struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };
    int ret;

    ret = register_kprobe(&probe);
    if (ret)
        return ret;
    kallsyms_lookup_name = (wujishadow_kallsyms_lookup_name_t)probe.addr;
    unregister_kprobe(&probe);
    return kallsyms_lookup_name ? 0 : -ENOSYS;
}
