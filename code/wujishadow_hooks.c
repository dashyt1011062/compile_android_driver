/* SPDX-License-Identifier: GPL-2.0-only */

#include "wujishadow_compat.h"

wujishadow_kallsyms_lookup_name_t ws_kallsyms_lookup_name;

typedef long (*ws_syscall_fn_t)(const struct pt_regs *regs);
typedef int (*ws_step_fn_t)(unsigned long unused, unsigned long esr,
                            struct pt_regs *regs);

struct ws_hook_entry {
    int used;
    int compat;
    int nr;
    int narg;
    unsigned long target;
    void *before;
    void *after;
    void *udata;
    struct kprobe probe;
};

static struct ws_hook_entry ws_hooks[16];
static struct ws_hook_entry ws_step_hook;

static void *ws_wrapper_for(int index);
static int ws_step_wrapper(unsigned long unused, unsigned long esr,
                           struct pt_regs *regs);

static struct ws_hook_entry *ws_entry_from_probe(struct kprobe *probe)
{
    if (probe == &ws_step_hook.probe)
        return &ws_step_hook;
    return container_of(probe, struct ws_hook_entry, probe);
}

static int ws_kprobe_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct ws_hook_entry *entry = ws_entry_from_probe(probe);
    unsigned long parent_ip = procedure_link_pointer(regs);
    const struct pt_regs *syscall_regs;
    void *wrapper;
    int index;

    if (!entry || !entry->used || within_module(parent_ip, THIS_MODULE))
        return 0;

    if (entry == &ws_step_hook) {
        wrapper = ws_step_wrapper;
    } else {
        index = (int)(entry - ws_hooks);
        if (index < 0 || index >= ARRAY_SIZE(ws_hooks))
            return 0;
        syscall_regs = (const struct pt_regs *)(uintptr_t)regs->regs[0];
        if (!syscall_regs ||
            !shadow_syscall_should_intercept(entry->nr, entry->compat,
                                              syscall_regs))
            return 0;
        /* Keep executable destinations out of writable hook state. */
        wrapper = ws_wrapper_for(index);
    }

    if (!wrapper || !within_module((unsigned long)wrapper, THIS_MODULE))
        return 0;
    instruction_pointer_set(regs, (unsigned long)wrapper);
    return 1;
}
NOKPROBE_SYMBOL(ws_kprobe_pre_handler);

static void ws_kprobe_post_handler(struct kprobe *probe,
                                   struct pt_regs *regs,
                                   unsigned long flags)
{
    (void)probe;
    (void)regs;
    (void)flags;
}
NOKPROBE_SYMBOL(ws_kprobe_post_handler);

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

static void ws_call_callback(struct ws_hook_entry *entry, void *callback,
                             hook_fargs8_t *args)
{
    if (!callback || !within_module((unsigned long)callback, THIS_MODULE))
        return;
    if (entry->narg > 4)
        ((hook_callback8_t)callback)(args, entry->udata);
    else
        ((hook_callback4_t)callback)((hook_fargs4_t *)args, entry->udata);
}

static noinline long ws_call_syscall(struct ws_hook_entry *entry,
                                     const struct pt_regs *regs)
{
    hook_fargs8_t args;
    ws_syscall_fn_t origin;
    unsigned long target;
    long ret;

    if (!entry || !regs)
        return -EFAULT;
    target = READ_ONCE(entry->target);
    if (!target || target != (unsigned long)READ_ONCE(entry->probe.addr) ||
        within_module(target, THIS_MODULE))
        return -EFAULT;

    memset(&args, 0, sizeof(args));
    args.arg0 = (uint64_t)(uintptr_t)regs;
    origin = (ws_syscall_fn_t)(uintptr_t)target;

    ws_call_callback(entry, READ_ONCE(entry->before), &args);

    if (!args.skip_origin)
        args.ret = (uint64_t)origin(regs);

    ws_call_callback(entry, READ_ONCE(entry->after), &args);

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

static hook_err_t ws_install_kprobe(struct ws_hook_entry *entry)
{
    int ret;

    entry->probe.addr = (kprobe_opcode_t *)(uintptr_t)entry->target;
    entry->probe.pre_handler = ws_kprobe_pre_handler;
    /* A post handler prevents Kprobe optimization from bypassing PC changes. */
    entry->probe.post_handler = ws_kprobe_post_handler;
    ret = register_kprobe(&entry->probe);
    if (ret)
        return HOOK_BAD_ADDRESS;
    entry->used = 1;
    return HOOK_NO_ERR;
}

static void ws_remove_kprobe(struct ws_hook_entry *entry)
{
    if (!entry || !entry->used)
        return;
    entry->used = 0;
    unregister_kprobe(&entry->probe);
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

static hook_err_t ws_hook_syscall(int nr, int compat, int narg,
                                  void *before, void *after, void *udata)
{
    struct ws_hook_entry *entry;
    const char *symbol;
    int index;

    if (narg < 1 || narg > 8)
        return HOOK_BAD_ADDRESS;
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
    entry->narg = narg;
    entry->before = before;
    entry->after = after;
    entry->udata = udata;
    entry->target = kallsyms_lookup_name(symbol);
    if (!entry->target)
        return HOOK_BAD_ADDRESS;
    return ws_install_kprobe(entry);
}

hook_err_t hook_syscalln(int nr, int narg, void *before, void *after,
                         void *udata)
{
    return ws_hook_syscall(nr, 0, narg, before, after, udata);
}

void unhook_syscalln(int nr, void *before, void *after)
{
    struct ws_hook_entry *entry = ws_find_entry(nr, 0, before, after);
    ws_remove_kprobe(entry);
}

hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after,
                                void *udata)
{
    return ws_hook_syscall(nr, 1, narg, before, after, udata);
}

void unhook_compat_syscalln(int nr, void *before, void *after)
{
    struct ws_hook_entry *entry = ws_find_entry(nr, 1, before, after);
    ws_remove_kprobe(entry);
}

static int ws_step_dispatch(struct ws_hook_entry *entry, unsigned long unused,
                            unsigned long esr, struct pt_regs *regs)
{
    hook_fargs4_t args;
    ws_step_fn_t origin;

    memset(&args, 0, sizeof(args));
    args.arg0 = (uint64_t)unused;
    args.arg1 = (uint64_t)esr;
    args.arg2 = (uint64_t)(uintptr_t)regs;
    origin = (ws_step_fn_t)(uintptr_t)entry->target;
    if (entry->before)
        ((hook_callback4_t)entry->before)(&args, entry->udata);
    if (!args.skip_origin)
        args.ret = (uint64_t)origin(unused, esr, regs);
    if (entry->after)
        ((hook_callback4_t)entry->after)(&args, entry->udata);
    return (int)args.ret;
}

static int ws_step_wrapper(unsigned long unused, unsigned long esr,
                           struct pt_regs *regs)
{
    return ws_step_dispatch(&ws_step_hook, unused, esr, regs);
}

hook_err_t hook_wrap3(void *target, void *before, void *after, void *udata)
{
    if (!target || ws_step_hook.used)
        return HOOK_DUPLICATED;
    memset(&ws_step_hook, 0, sizeof(ws_step_hook));
    ws_step_hook.target = (unsigned long)target;
    ws_step_hook.narg = 3;
    ws_step_hook.before = before;
    ws_step_hook.after = after;
    ws_step_hook.udata = udata;
    return ws_install_kprobe(&ws_step_hook);
}

void hook_unwrap(void *target, void *before, void *after)
{
    if (ws_step_hook.used && ws_step_hook.target == (unsigned long)target &&
        ws_step_hook.before == before && ws_step_hook.after == after)
        ws_remove_kprobe(&ws_step_hook);
}

void wujishadow_remove_all_hooks(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ws_hooks); ++i)
        ws_remove_kprobe(&ws_hooks[i]);
    ws_remove_kprobe(&ws_step_hook);
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
