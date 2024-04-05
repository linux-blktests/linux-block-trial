// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 */

#include <linux/efi.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mount.h>

#include "internal.h"

static ssize_t efivarfs_file_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct efivar_entry *var = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	void *data;
	u32 attributes;
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	unsigned long datasize = count - sizeof(attributes);
	ssize_t bytes;
	bool set = false;

	if (count < sizeof(attributes))
		return -EINVAL;

	if (!copy_from_iter_full(&attributes, sizeof(attributes), from))
		return -EFAULT;

	if (attributes & ~(EFI_VARIABLE_MASK))
		return -EINVAL;

	data = iterdup(from, datasize);
	if (IS_ERR(data))
		return PTR_ERR(data);

	bytes = efivar_entry_set_get_size(var, attributes, &datasize,
					  data, &set);
	if (!set && bytes) {
		if (bytes == -ENOENT)
			bytes = -EIO;
		goto out;
	}

	if (bytes == -ENOENT) {
		drop_nlink(inode);
		d_delete(iocb->ki_filp->f_path.dentry);
		dput(iocb->ki_filp->f_path.dentry);
	} else {
		inode_lock(inode);
		i_size_write(inode, datasize + sizeof(attributes));
		inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
		inode_unlock(inode);
	}

	bytes = count;

out:
	kfree(data);

	return bytes;
}

static ssize_t efivarfs_file_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct efivar_entry *var = iocb->ki_filp->private_data;
	unsigned long datasize = 0;
	u32 attributes;
	void *data;
	ssize_t size = 0;
	int err;

	while (!__ratelimit(&iocb->ki_filp->f_cred->user->ratelimit))
		msleep(50);

	err = efivar_entry_size(var, &datasize);

	/*
	 * efivarfs represents uncommitted variables with
	 * zero-length files. Reading them should return EOF.
	 */
	if (err == -ENOENT)
		return 0;
	else if (err)
		return err;

	data = kmalloc(datasize + sizeof(attributes), GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	size = efivar_entry_get(var, &attributes, &datasize,
				data + sizeof(attributes));
	if (size)
		goto out_free;

	memcpy(data, &attributes, sizeof(attributes));
	size = simple_copy_to_iter(data, &iocb->ki_pos,
				   datasize + sizeof(attributes), to);
out_free:
	kfree(data);

	return size;
}

const struct file_operations efivarfs_file_operations = {
	.open	= simple_open,
	.read_iter	= efivarfs_file_read,
	.write_iter	= efivarfs_file_write,
};
