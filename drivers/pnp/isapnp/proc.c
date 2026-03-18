// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  ISA Plug & Play support
 *  Copyright (c) by Jaroslav Kysela <perex@perex.cz>
 */

#include <linux/module.h>
#include <linux/isapnp.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/uaccess.h>

extern struct pnp_protocol isapnp_protocol;

static struct proc_dir_entry *isapnp_proc_bus_dir = NULL;

static loff_t isapnp_proc_bus_lseek(struct file *file, loff_t off, int whence)
{
	return fixed_size_llseek(file, off, whence, 256);
}

static ssize_t isapnp_proc_bus_read_iter(struct kiocb *iocb,
					 struct iov_iter *to)
{
	struct pnp_dev *dev = pde_data(file_inode(iocb->ki_filp));
	int pos = iocb->ki_pos;
	size_t nbytes = iov_iter_count(to);
	int cnt, size = 256;
	u8 buf[256];

	if (pos >= size)
		return 0;
	if (nbytes >= size)
		nbytes = size;
	if (pos + nbytes > size)
		nbytes = size - pos;
	cnt = nbytes;

	isapnp_cfg_begin(dev->card->number, dev->number);
	for (; pos < 256 && cnt > 0; pos++, cnt--)
		buf[pos] = isapnp_read_byte(pos);
	isapnp_cfg_end();

	if (copy_to_iter(buf + (int)iocb->ki_pos, nbytes, to) != nbytes)
		return -EFAULT;

	iocb->ki_pos = pos;
	return nbytes;
}

static const struct proc_ops isapnp_proc_bus_proc_ops = {
	.proc_lseek	= isapnp_proc_bus_lseek,
	.proc_read_iter	= isapnp_proc_bus_read_iter,
};

static int isapnp_proc_attach_device(struct pnp_dev *dev)
{
	struct pnp_card *bus = dev->card;
	char name[16];

	if (!bus->procdir) {
		sprintf(name, "%02x", bus->number);
		bus->procdir = proc_mkdir(name, isapnp_proc_bus_dir);
		if (!bus->procdir)
			return -ENOMEM;
	}
	sprintf(name, "%02x", dev->number);
	dev->procent = proc_create_data(name, S_IFREG | S_IRUGO, bus->procdir,
					    &isapnp_proc_bus_proc_ops, dev);
	if (!dev->procent)
		return -ENOMEM;
	proc_set_size(dev->procent, 256);
	return 0;
}

int __init isapnp_proc_init(void)
{
	struct pnp_dev *dev;

	isapnp_proc_bus_dir = proc_mkdir("bus/isapnp", NULL);
	protocol_for_each_dev(&isapnp_protocol, dev) {
		isapnp_proc_attach_device(dev);
	}
	return 0;
}
