// SPDX-License-Identifier: GPL-2.0-only

#include <linux/module.h>

static int __init devkit_probe_init(void)
{
    return 0;
}

static void __exit devkit_probe_exit(void)
{
}

module_init(devkit_probe_init);
module_exit(devkit_probe_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Build-only probe used to produce the Android 15 6.6 DDK package");
