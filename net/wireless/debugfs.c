// SPDX-License-Identifier: GPL-2.0-only
/*
 * cfg80211 debugfs
 *
 * Copyright 2009	Luis R. Rodriguez <lrodriguez@atheros.com>
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright (C) 2023 Intel Corporation
 */

#include <linux/slab.h>
#include "core.h"
#include "debugfs.h"

#define DEBUGFS_READONLY_FILE(name, buflen, fmt, value...)		\
static ssize_t name## _read(struct kiocb *iocb, struct iov_iter *to)	\
{									\
	struct wiphy *wiphy = iocb->ki_filp->private_data;		\
	char buf[buflen];						\
	int res;							\
									\
	res = scnprintf(buf, buflen, fmt "\n", ##value);		\
	return simple_copy_to_iter(buf, &iocb->ki_pos, res, to);	\
}									\
									\
static const struct file_operations name## _ops = {			\
	.read_iter = name## _read,					\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

#define DEBUGFS_RADIO_READONLY_FILE(name, buflen, fmt, value...)	\
static ssize_t name## _read(struct kiocb *iocb, struct iov_iter *to)	\
{									\
	struct wiphy_radio_cfg *radio_cfg = iocb->ki_filp->private_data;\
	char buf[buflen];						\
	int res;							\
									\
	res = scnprintf(buf, buflen, fmt "\n", ##value);		\
	return simple_copy_to_iter(buf, &iocb->ki_pos, res, to);	\
}									\
									\
static const struct file_operations name## _ops = {			\
	.read_iter = name## _read,					\
	.open = simple_open,						\
	.llseek = generic_file_llseek,					\
}

DEBUGFS_READONLY_FILE(rts_threshold, 20, "%d",
		      wiphy->rts_threshold);
DEBUGFS_READONLY_FILE(fragmentation_threshold, 20, "%d",
		      wiphy->frag_threshold);
DEBUGFS_READONLY_FILE(short_retry_limit, 20, "%d",
		      wiphy->retry_short);
DEBUGFS_READONLY_FILE(long_retry_limit, 20, "%d",
		      wiphy->retry_long);

DEBUGFS_RADIO_READONLY_FILE(radio_rts_threshold, 20, "%d",
			    radio_cfg->rts_threshold);

static int ht_print_chan(struct ieee80211_channel *chan,
			 char *buf, int buf_size, int offset)
{
	if (WARN_ON(offset > buf_size))
		return 0;

	if (chan->flags & IEEE80211_CHAN_DISABLED)
		return scnprintf(buf + offset,
				 buf_size - offset,
				 "%d Disabled\n",
				 chan->center_freq);

	return scnprintf(buf + offset,
			 buf_size - offset,
			 "%d HT40 %c%c\n",
			 chan->center_freq,
			 (chan->flags & IEEE80211_CHAN_NO_HT40MINUS) ?
				' ' : '-',
			 (chan->flags & IEEE80211_CHAN_NO_HT40PLUS) ?
				' ' : '+');
}

static ssize_t ht40allow_map_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct wiphy *wiphy = iocb->ki_filp->private_data;
	char *buf;
	unsigned int offset = 0, buf_size = PAGE_SIZE, i;
	enum nl80211_band band;
	struct ieee80211_supported_band *sband;
	ssize_t r;

	buf = kzalloc(buf_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	for (band = 0; band < NUM_NL80211_BANDS; band++) {
		sband = wiphy->bands[band];
		if (!sband)
			continue;
		for (i = 0; i < sband->n_channels; i++)
			offset += ht_print_chan(&sband->channels[i],
						buf, buf_size, offset);
	}

	r = simple_copy_to_iter(buf, &iocb->ki_pos, offset, to);
	kfree(buf);
	return r;
}

static const struct file_operations ht40allow_map_ops = {
	.read_iter = ht40allow_map_read_iter,
	.open = simple_open,
	.llseek = default_llseek,
};

#define DEBUGFS_ADD(name)						\
	debugfs_create_file(#name, 0444, phyd, &rdev->wiphy, &name## _ops)

#define DEBUGFS_RADIO_ADD(name, radio_idx)				\
	debugfs_create_file(#name, 0444, radiod,			\
			    &rdev->wiphy.radio_cfg[radio_idx],		\
			    &name## _ops)

void cfg80211_debugfs_rdev_add(struct cfg80211_registered_device *rdev)
{
	struct dentry *phyd = rdev->wiphy.debugfsdir;
	struct dentry *radiod;
	u8 i;

	DEBUGFS_ADD(rts_threshold);
	DEBUGFS_ADD(fragmentation_threshold);
	DEBUGFS_ADD(short_retry_limit);
	DEBUGFS_ADD(long_retry_limit);
	DEBUGFS_ADD(ht40allow_map);

	for (i = 0; i < rdev->wiphy.n_radio; i++) {
		radiod = rdev->wiphy.radio_cfg[i].radio_debugfsdir;
		DEBUGFS_RADIO_ADD(radio_rts_threshold, i);
	}
}

struct debugfs_read_work {
	struct wiphy_work work;
	ssize_t (*handler)(struct wiphy *wiphy,
			   char *buf,
			   size_t count,
			   void *data);
	struct wiphy *wiphy;
	char *buf;
	size_t bufsize;
	void *data;
	ssize_t ret;
	struct completion completion;
};

static void wiphy_locked_debugfs_read_work(struct wiphy *wiphy,
					   struct wiphy_work *work)
{
	struct debugfs_read_work *w = container_of(work, typeof(*w), work);

	w->ret = w->handler(w->wiphy, w->buf, w->bufsize, w->data);
	complete(&w->completion);
}

static void wiphy_locked_debugfs_read_cancel(struct dentry *dentry,
					     void *data)
{
	struct debugfs_read_work *w = data;

	wiphy_work_cancel(w->wiphy, &w->work);
	complete(&w->completion);
}

ssize_t wiphy_locked_debugfs_read(struct wiphy *wiphy, struct kiocb *iocb,
				  char *buf, size_t bufsize,
				  struct iov_iter *to,
				  ssize_t (*handler)(struct wiphy *wiphy,
						     char *buf,
						     size_t bufsize,
						     void *data),
				  void *data)
{
	struct debugfs_read_work work = {
		.handler = handler,
		.wiphy = wiphy,
		.buf = buf,
		.bufsize = bufsize,
		.data = data,
		.ret = -ENODEV,
		.completion = COMPLETION_INITIALIZER_ONSTACK(work.completion),
	};
	struct debugfs_cancellation cancellation = {
		.cancel = wiphy_locked_debugfs_read_cancel,
		.cancel_data = &work,
	};

	/* don't leak stack data or whatever */
	memset(buf, 0, bufsize);

	wiphy_work_init(&work.work, wiphy_locked_debugfs_read_work);
	wiphy_work_queue(wiphy, &work.work);

	debugfs_enter_cancellation(iocb->ki_filp, &cancellation);
	wait_for_completion(&work.completion);
	debugfs_leave_cancellation(iocb->ki_filp, &cancellation);

	if (work.ret < 0)
		return work.ret;

	if (WARN_ON(work.ret > bufsize))
		return -EINVAL;

	return simple_copy_to_iter(buf, &iocb->ki_pos, work.ret, to);
}
EXPORT_SYMBOL_GPL(wiphy_locked_debugfs_read);

struct debugfs_write_work {
	struct wiphy_work work;
	ssize_t (*handler)(struct wiphy *wiphy,
			   char *buf,
			   size_t count,
			   void *data);
	struct wiphy *wiphy;
	char *buf;
	size_t count;
	void *data;
	ssize_t ret;
	struct completion completion;
};

static void wiphy_locked_debugfs_write_work(struct wiphy *wiphy,
					    struct wiphy_work *work)
{
	struct debugfs_write_work *w = container_of(work, typeof(*w), work);

	w->ret = w->handler(w->wiphy, w->buf, w->count, w->data);
	complete(&w->completion);
}

static void wiphy_locked_debugfs_write_cancel(struct dentry *dentry,
					      void *data)
{
	struct debugfs_write_work *w = data;

	wiphy_work_cancel(w->wiphy, &w->work);
	complete(&w->completion);
}

ssize_t wiphy_locked_debugfs_write(struct wiphy *wiphy,
				   struct kiocb *iocb, char *buf, size_t bufsize,
				   struct iov_iter *from,
				   ssize_t (*handler)(struct wiphy *wiphy,
						      char *buf,
						      size_t count,
						      void *data),
				   void *data)
{
	struct debugfs_write_work work = {
		.handler = handler,
		.wiphy = wiphy,
		.buf = buf,
		.count = bufsize,
		.data = data,
		.ret = -ENODEV,
		.completion = COMPLETION_INITIALIZER_ONSTACK(work.completion),
	};
	struct debugfs_cancellation cancellation = {
		.cancel = wiphy_locked_debugfs_write_cancel,
		.cancel_data = &work,
	};
	size_t count = iov_iter_count(from);

	/* mostly used for strings so enforce NUL-termination for safety */
	if (count >= bufsize)
		return -EINVAL;

	memset(buf, 0, bufsize);

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	wiphy_work_init(&work.work, wiphy_locked_debugfs_write_work);
	wiphy_work_queue(wiphy, &work.work);

	debugfs_enter_cancellation(iocb->ki_filp, &cancellation);
	wait_for_completion(&work.completion);
	debugfs_leave_cancellation(iocb->ki_filp, &cancellation);

	return work.ret;
}
EXPORT_SYMBOL_GPL(wiphy_locked_debugfs_write);
