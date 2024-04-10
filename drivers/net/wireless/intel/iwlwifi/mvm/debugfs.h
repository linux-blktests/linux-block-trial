/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/*
 * Copyright (C) 2023 Intel Corporation
 * Copyright (C) 2012-2014 Intel Corporation
 * Copyright (C) 2013-2014 Intel Mobile Communications GmbH
 */
#define MVM_DEBUGFS_READ_FILE_OPS(name)					\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.read_iter = iwl_dbgfs_##name##_read,				\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

#define MVM_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)		\
static ssize_t _iwl_dbgfs_##name##_write(struct kiocb *iocb,		\
					 struct iov_iter *from)		\
{									\
	argtype *arg = iocb->ki_filp->private_data;			\
	char buf[buflen] = {};						\
	size_t buf_size = min(iov_iter_count(from), sizeof(buf) -  1);	\
									\
	if (!copy_from_iter_full(buf, buf_size, from))			\
		return -EFAULT;						\
									\
	return iwl_dbgfs_##name##_write(arg, buf, buf_size,		\
					&iocb->ki_pos);			\
}									\

#define _MVM_DEBUGFS_READ_WRITE_FILE_OPS(name, buflen, argtype)		\
MVM_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)			\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write_iter = _iwl_dbgfs_##name##_write,			\
	.read_iter = iwl_dbgfs_##name##_read,				\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
};

#define _MVM_DEBUGFS_WRITE_FILE_OPS(name, buflen, argtype)		\
MVM_DEBUGFS_WRITE_WRAPPER(name, buflen, argtype)			\
static const struct file_operations iwl_dbgfs_##name##_ops = {		\
	.write_iter = _iwl_dbgfs_##name##_write,			\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
};
