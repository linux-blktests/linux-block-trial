// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 1999 - 2018 Intel Corporation. */

#include <linux/debugfs.h>
#include <linux/module.h>

#include "ixgbe.h"

static struct dentry *ixgbe_dbg_root;

static char ixgbe_dbg_reg_ops_buf[256] = "";

static ssize_t ixgbe_dbg_common_ops_read(struct kiocb *iocb,
					 struct iov_iter *to,
					 char *dbg_buf)
{
	struct ixgbe_adapter *adapter = iocb->ki_filp->private_data;
	char *buf;
	int len;
	size_t count = iov_iter_count(to);

	/* don't allow partial reads */
	if (iocb->ki_pos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "%s: %s\n",
			adapter->netdev->name, dbg_buf);
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

/**
 * ixgbe_dbg_reg_ops_read_iter - read for reg_ops datum
 * @iocb: the kernel io callback (kiocb) struct
 * @to: iovec iterator
 **/
static ssize_t ixgbe_dbg_reg_ops_read_iter(struct kiocb *iocb,
					   struct iov_iter *to)
{
	return ixgbe_dbg_common_ops_read(iocb, to, ixgbe_dbg_reg_ops_buf);
}

/**
 * ixgbe_dbg_reg_ops_write_iter - write into reg_ops datum
 * @iocb: the kernel io callback (kiocb) struct
 * @from: iovec iterator
 **/
static ssize_t ixgbe_dbg_reg_ops_write_iter(struct kiocb *iocb,
					    struct iov_iter *from)
{
	struct ixgbe_adapter *adapter = iocb->ki_filp->private_data;
	int len;
	size_t count = iov_iter_count(from);

	/* don't allow partial writes */
	if (iocb->ki_pos != 0)
		return 0;
	if (count >= sizeof(ixgbe_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_copy_from_iter(ixgbe_dbg_reg_ops_buf, &iocb->ki_pos,
				    sizeof(ixgbe_dbg_reg_ops_buf) - 1, from);
	if (len < 0)
		return len;

	ixgbe_dbg_reg_ops_buf[len] = '\0';

	if (strncmp(ixgbe_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&ixgbe_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			IXGBE_WRITE_REG(&adapter->hw, reg, value);
			value = IXGBE_READ_REG(&adapter->hw, reg);
			e_dev_info("write: 0x%08x = 0x%08x\n", reg, value);
		} else {
			e_dev_info("write <reg> <value>\n");
		}
	} else if (strncmp(ixgbe_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&ixgbe_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = IXGBE_READ_REG(&adapter->hw, reg);
			e_dev_info("read 0x%08x = 0x%08x\n", reg, value);
		} else {
			e_dev_info("read <reg>\n");
		}
	} else {
		e_dev_info("Unknown command %s\n", ixgbe_dbg_reg_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("   read <reg>\n");
		e_dev_info("   write <reg> <value>\n");
	}
	return count;
}

static const struct file_operations ixgbe_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read_iter = ixgbe_dbg_reg_ops_read_iter,
	.write_iter = ixgbe_dbg_reg_ops_write_iter,
};

static char ixgbe_dbg_netdev_ops_buf[256] = "";

/**
 * ixgbe_dbg_netdev_ops_read_iter - read for netdev_ops datum
 * @iocb: the kernel io callback (kiocb) struct
 * @to: iovec iterator
 **/
static ssize_t ixgbe_dbg_netdev_ops_read_iter(struct kiocb *iocb,
					      struct iov_iter *to)
{
	return ixgbe_dbg_common_ops_read(iocb, to, ixgbe_dbg_netdev_ops_buf);
}

/**
 * ixgbe_dbg_netdev_ops_write_iter - write into netdev_ops datum
 * @iocb: the kernel io callback (kiocb) struct
 * @from: iovec iterator
 **/
static ssize_t ixgbe_dbg_netdev_ops_write_iter(struct kiocb *iocb,
					       struct iov_iter *from)
{
	struct ixgbe_adapter *adapter = iocb->ki_filp->private_data;
	int len;
	size_t count = iov_iter_count(from);

	/* don't allow partial writes */
	if (iocb->ki_pos != 0)
		return 0;
	if (count >= sizeof(ixgbe_dbg_netdev_ops_buf))
		return -ENOSPC;

	len = simple_copy_from_iter(ixgbe_dbg_netdev_ops_buf, &iocb->ki_pos,
				    sizeof(ixgbe_dbg_netdev_ops_buf) - 1, from);
	if (len < 0)
		return len;

	ixgbe_dbg_netdev_ops_buf[len] = '\0';

	if (strncmp(ixgbe_dbg_netdev_ops_buf, "tx_timeout", 10) == 0) {
		/* TX Queue number below is wrong, but ixgbe does not use it */
		adapter->netdev->netdev_ops->ndo_tx_timeout(adapter->netdev,
							    UINT_MAX);
		e_dev_info("tx_timeout called\n");
	} else {
		e_dev_info("Unknown command: %s\n", ixgbe_dbg_netdev_ops_buf);
		e_dev_info("Available commands:\n");
		e_dev_info("    tx_timeout\n");
	}
	return count;
}

static const struct file_operations ixgbe_dbg_netdev_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read_iter = ixgbe_dbg_netdev_ops_read_iter,
	.write_iter = ixgbe_dbg_netdev_ops_write_iter,
};

/**
 * ixgbe_dbg_adapter_init - setup the debugfs directory for the adapter
 * @adapter: the adapter that is starting up
 **/
void ixgbe_dbg_adapter_init(struct ixgbe_adapter *adapter)
{
	const char *name = pci_name(adapter->pdev);

	adapter->ixgbe_dbg_adapter = debugfs_create_dir(name, ixgbe_dbg_root);
	debugfs_create_file("reg_ops", 0600, adapter->ixgbe_dbg_adapter,
			    adapter, &ixgbe_dbg_reg_ops_fops);
	debugfs_create_file("netdev_ops", 0600, adapter->ixgbe_dbg_adapter,
			    adapter, &ixgbe_dbg_netdev_ops_fops);
}

/**
 * ixgbe_dbg_adapter_exit - clear out the adapter's debugfs entries
 * @adapter: the adapter that is exiting
 **/
void ixgbe_dbg_adapter_exit(struct ixgbe_adapter *adapter)
{
	debugfs_remove_recursive(adapter->ixgbe_dbg_adapter);
	adapter->ixgbe_dbg_adapter = NULL;
}

/**
 * ixgbe_dbg_init - start up debugfs for the driver
 **/
void ixgbe_dbg_init(void)
{
	ixgbe_dbg_root = debugfs_create_dir(ixgbe_driver_name, NULL);
}

/**
 * ixgbe_dbg_exit - clean out the driver's debugfs entries
 **/
void ixgbe_dbg_exit(void)
{
	debugfs_remove_recursive(ixgbe_dbg_root);
}
