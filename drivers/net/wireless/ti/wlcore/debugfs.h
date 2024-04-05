/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * This file is part of wl1271
 *
 * Copyright (C) 2009 Nokia Corporation
 *
 * Contact: Luciano Coelho <luciano.coelho@nokia.com>
 */

#ifndef __DEBUGFS_H__
#define __DEBUGFS_H__

#include "wlcore.h"

__printf(3, 4) int wl1271_format_buffer(struct kiocb *iocb, struct iov_iter *to,
					char *fmt, ...);

int wl1271_debugfs_init(struct wl1271 *wl);
void wl1271_debugfs_exit(struct wl1271 *wl);
void wl1271_debugfs_reset(struct wl1271 *wl);
void wl1271_debugfs_update_stats(struct wl1271 *wl);

#define DEBUGFS_FORMAT_BUFFER_SIZE 256

#define DEBUGFS_READONLY_FILE(name, fmt, value...)			\
static ssize_t name## _read(struct kiocb *iocb, struct iov_iter *to)	\
{									\
	struct wl1271 *wl = iocb->ki_filp->private_data;		\
	return wl1271_format_buffer(iocb, to, fmt "\n", ##value);	\
}									\
									\
static const struct file_operations name## _ops = {			\
	.read_iter = name## _read,					\
	.open = simple_open,						\
	.llseek	= generic_file_llseek,					\
};

#define DEBUGFS_ADD(name, parent)					\
	do {								\
		debugfs_create_file(#name, 0400, parent,		\
				    wl, &name## _ops);			\
	} while (0)


#define DEBUGFS_ADD_PREFIX(prefix, name, parent)			\
	do {								\
		debugfs_create_file(#name, 0400, parent,		\
				    wl, &prefix## _## name## _ops);	\
	} while (0)

#define DEBUGFS_FWSTATS_FILE(sub, name, fmt, struct_type)		\
static ssize_t sub## _ ##name## _read(struct kiocb *iocb,		\
				      struct iov_iter *to)		\
{									\
	struct wl1271 *wl = iocb->ki_filp->private_data;		\
	struct struct_type *stats = wl->stats.fw_stats;			\
									\
	wl1271_debugfs_update_stats(wl);				\
									\
	return wl1271_format_buffer(iocb, to, fmt "\n", stats->sub.name);\
}									\
									\
static const struct file_operations sub## _ ##name## _ops = {		\
	.read_iter = sub## _ ##name## _read,				\
	.open = simple_open,						\
	.llseek	= generic_file_llseek,					\
};

#define DEBUGFS_FWSTATS_FILE_ARRAY(sub, name, len, struct_type)		\
static ssize_t sub## _ ##name## _read(struct kiocb *iocb,		\
				      struct iov_iter *to)		\
{									\
	struct wl1271 *wl = iocb->ki_filp->private_data;		\
	struct struct_type *stats = wl->stats.fw_stats;			\
	char buf[DEBUGFS_FORMAT_BUFFER_SIZE] = "";			\
	int pos = 0;							\
	int i;								\
									\
	wl1271_debugfs_update_stats(wl);				\
									\
	for (i = 0; i < len && pos < sizeof(buf); i++)			\
		pos += snprintf(buf + pos, sizeof(buf) - pos,		\
			 "[%d] = %d\n", i, stats->sub.name[i]);		\
									\
	return wl1271_format_buffer(iocb, to, "%s", buf);		\
}									\
									\
static const struct file_operations sub## _ ##name## _ops = {		\
	.read_iter = sub## _ ##name## _read,				\
	.open = simple_open,						\
	.llseek	= generic_file_llseek,					\
};

#define DEBUGFS_FWSTATS_ADD(sub, name)					\
	DEBUGFS_ADD(sub## _ ##name, stats)


#endif /* WL1271_DEBUGFS_H */
