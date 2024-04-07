/* Broadcom NetXtreme-C/E network driver.
 *
 * Copyright (c) 2017-2018 Broadcom Limited
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 */

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/bnxt/hsi.h>
#include <linux/dim.h>
#include "bnxt.h"
#include "bnxt_debugfs.h"

static struct dentry *bnxt_debug_mnt;

static ssize_t debugfs_dim_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct dim *dim = iocb->ki_filp->private_data;
	int len;
	char *buf;
	size_t count = iov_iter_count(to);

	if (iocb->ki_pos)
		return 0;
	if (!dim)
		return -ENODEV;
	buf = kasprintf(GFP_KERNEL,
			"state = %d\n" \
			"profile_ix = %d\n" \
			"mode = %d\n" \
			"tune_state = %d\n" \
			"steps_right = %d\n" \
			"steps_left = %d\n" \
			"tired = %d\n",
			dim->state,
			dim->profile_ix,
			dim->mode,
			dim->tune_state,
			dim->steps_right,
			dim->steps_left,
			dim->tired);
	if (!buf)
		return -ENOMEM;
	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}
	len = simple_copy_to_iter(buf, &iocb->ki_pos, strlen(buf), to);
	kfree(buf);
	return len;
}

static const struct file_operations debugfs_dim_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read_iter = debugfs_dim_read_iter,
};

static void debugfs_dim_ring_init(struct dim *dim, int ring_idx,
				  struct dentry *dd)
{
	static char qname[12];

	snprintf(qname, sizeof(qname), "%d", ring_idx);
	debugfs_create_file(qname, 0600, dd, dim, &debugfs_dim_fops);
}

void bnxt_debug_dev_init(struct bnxt *bp)
{
	const char *pname = pci_name(bp->pdev);
	struct dentry *dir;
	int i;

	bp->debugfs_pdev = debugfs_create_dir(pname, bnxt_debug_mnt);
	dir = debugfs_create_dir("dim", bp->debugfs_pdev);

	/* create files for each rx ring */
	for (i = 0; i < bp->cp_nr_rings; i++) {
		struct bnxt_cp_ring_info *cpr = &bp->bnapi[i]->cp_ring;

		if (cpr && bp->bnapi[i]->rx_ring)
			debugfs_dim_ring_init(&cpr->dim, i, dir);
	}
}

void bnxt_debug_dev_exit(struct bnxt *bp)
{
	if (bp) {
		debugfs_remove_recursive(bp->debugfs_pdev);
		bp->debugfs_pdev = NULL;
	}
}

void bnxt_debug_init(void)
{
	bnxt_debug_mnt = debugfs_create_dir("bnxt_en", NULL);
}

void bnxt_debug_exit(void)
{
	debugfs_remove_recursive(bnxt_debug_mnt);
}
