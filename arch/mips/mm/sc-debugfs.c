// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2015 Imagination Technologies
 * Author: Paul Burton <paul.burton@mips.com>
 */

#include <asm/bcache.h>
#include <asm/debug.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/init.h>

static ssize_t sc_prefetch_read(struct kiocb *iocb, struct iov_iter *to)
{
	bool enabled = bc_prefetch_is_enabled();
	char buf[3];

	buf[0] = enabled ? 'Y' : 'N';
	buf[1] = '\n';
	buf[2] = 0;

	return simple_copy_to_iter(buf, &iocb->ki_pos, 2, to);
}

static ssize_t sc_prefetch_write(struct kiocb *iocb, struct iov_iter *from)
{
	size_t count = iov_iter_count(from);
	bool enabled;
	int err;

	err = kstrtobool_from_iter(from, count, &enabled);
	if (err)
		return err;

	if (enabled)
		bc_prefetch_enable();
	else
		bc_prefetch_disable();

	return count;
}

static const struct file_operations sc_prefetch_fops = {
	.open = simple_open,
	.llseek = default_llseek,
	.read_iter = sc_prefetch_read,
	.write_iter = sc_prefetch_write,
};

static int __init sc_debugfs_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("l2cache", mips_debugfs_dir);
	debugfs_create_file("prefetch", S_IRUGO | S_IWUSR, dir, NULL,
			    &sc_prefetch_fops);
	return 0;
}
late_initcall(sc_debugfs_init);
