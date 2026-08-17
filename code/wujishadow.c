/* SPDX-License-Identifier: GPL-2.0-only */

#include "wujishadow_compat.h"

#define WUJISHADOW_DEVICE_NAME "wujishadow"
#define WUJISHADOW_CMD_LEN 1024
#define WUJISHADOW_REPLY_LEN 4096
#define WUJISHADOW_IOC_MAGIC 'W'

struct wujishadow_ctl {
    char command[WUJISHADOW_CMD_LEN];
    char reply[WUJISHADOW_REPLY_LEN];
};

#define WUJISHADOW_IOC_CONTROL \
    _IOWR(WUJISHADOW_IOC_MAGIC, 1, struct wujishadow_ctl)

extern long wuji_hwbp_init(const char *args, const char *event,
                           void __user *reserved);
extern long wuji_hwbp_control(const char *args, char __user *out_msg,
                              int outlen);
extern long wuji_hwbp_exit(void __user *reserved);
extern long shadow_init(const char *args, const char *event,
                        void __user *reserved);
extern long shadow_control(const char *args, char __user *out_msg,
                           int outlen);
extern long shadow_exit(void __user *reserved);

static bool wujishadow_ready;

static bool has_command_prefix(const char *args, const char *prefix)
{
    size_t prefix_len;

    if (!args || !prefix)
        return false;
    prefix_len = strlen(prefix);
    if (strncmp(args, prefix, prefix_len))
        return false;
    return args[prefix_len] == '\0' || args[prefix_len] == ' ' ||
           args[prefix_len] == '\t';
}

static const char *skip_command_prefix(const char *args, const char *prefix)
{
    const char *tail = args + strlen(prefix);

    while (*tail == ' ' || *tail == '\t')
        ++tail;
    return tail;
}

static long wujishadow_control(const char *command, char __user *reply,
                               int reply_len)
{
    if (has_command_prefix(command, "shadow"))
        return shadow_control(skip_command_prefix(command, "shadow"),
                              reply, reply_len);
    if (has_command_prefix(command, "wuji"))
        return wuji_hwbp_control(skip_command_prefix(command, "wuji"),
                                 reply, reply_len);
    return wuji_hwbp_control(command, reply, reply_len);
}

static long wujishadow_ioctl(struct file *file, unsigned int cmd,
                             unsigned long arg)
{
    struct wujishadow_ctl __user *user_ctl = (void __user *)arg;
    char *command;
    long ret;

    (void)file;
    if (cmd != WUJISHADOW_IOC_CONTROL)
        return -ENOTTY;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN))
        return -EPERM;

    command = memdup_user_nul(&user_ctl->command, WUJISHADOW_CMD_LEN);
    if (IS_ERR(command))
        return PTR_ERR(command);
    command[WUJISHADOW_CMD_LEN - 1] = '\0';
    ret = wujishadow_control(command, user_ctl->reply,
                             WUJISHADOW_REPLY_LEN);
    kfree(command);
    return ret;
}

static ssize_t wujishadow_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *ppos)
{
    char *command;
    size_t len;
    long ret;

    (void)file;
    (void)ppos;
    if (!uid_eq(current_uid(), GLOBAL_ROOT_UID) && !capable(CAP_SYS_ADMIN))
        return -EPERM;
    len = min_t(size_t, count, WUJISHADOW_CMD_LEN - 1);
    command = memdup_user_nul(buf, len);
    if (IS_ERR(command))
        return PTR_ERR(command);
    ret = wujishadow_control(command, NULL, 0);
    kfree(command);
    return ret ? ret : count;
}

static const struct file_operations wujishadow_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = wujishadow_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = wujishadow_ioctl,
#endif
    .write = wujishadow_write,
    .llseek = no_llseek,
};

static struct miscdevice wujishadow_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = WUJISHADOW_DEVICE_NAME,
    .fops = &wujishadow_fops,
    .mode = 0600,
};

static int __init wujishadow_init(void)
{
    long ret;

    ret = wujishadow_resolve_kallsyms();
    if (ret) {
        pr_err("wujishadow: kallsyms resolver failed: %ld\n", ret);
        return ret;
    }

    ret = wuji_hwbp_init(NULL, "module_load", NULL);
    if (ret)
        return ret;
    ret = shadow_init(NULL, "module_load", NULL);
    if (ret) {
        wuji_hwbp_exit(NULL);
        wujishadow_remove_all_hooks();
        return ret;
    }
    ret = misc_register(&wujishadow_device);
    if (ret) {
        shadow_exit(NULL);
        wuji_hwbp_exit(NULL);
        wujishadow_remove_all_hooks();
        return ret;
    }

    wujishadow_ready = true;
    pr_info("wujishadow: loaded, control=/dev/%s\n",
            WUJISHADOW_DEVICE_NAME);
    return 0;
}

static void __exit wujishadow_exit(void)
{
    long ret;

    if (wujishadow_ready)
        misc_deregister(&wujishadow_device);
    ret = wuji_hwbp_exit(NULL);
    if (ret)
        pr_err("wujishadow: WuJi shutdown returned %ld\n", ret);
    shadow_exit(NULL);
    wujishadow_remove_all_hooks();
    ws_kallsyms_lookup_name = NULL;
    pr_info("wujishadow: unloaded\n");
}

module_init(wujishadow_init);
module_exit(wujishadow_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dashyt1011062");
MODULE_VERSION("1.1.0-ko1");
MODULE_DESCRIPTION("WuJi hardware breakpoints and shadow ptrace hwdebug virtualization");
