// SPDX-License-Identifier: GPL-2.0-only
/*
 * mac80211 debugfs for wireless PHYs
 *
 * Copyright 2007	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
 * Copyright (C) 2018 - 2019, 2021-2025 Intel Corporation
 */

#include <linux/debugfs.h>
#include <linux/rtnetlink.h>
#include <linux/vmalloc.h>
#include "ieee80211_i.h"
#include "driver-ops.h"
#include "rate.h"
#include "debugfs.h"

#define DEBUGFS_FORMAT_BUFFER_SIZE 100

#define DEBUGFS_READONLY_FILE_FN(name, fmt, value...)			\
static ssize_t name## _read(struct kiocb *iocb, struct iov_iter *to)	\
{									\
	struct ieee80211_local *local = iocb->ki_filp->private_data;	\
	char buf[DEBUGFS_FORMAT_BUFFER_SIZE];				\
	int res;							\
									\
	res = scnprintf(buf, sizeof(buf), fmt "\n", ##value);		\
	return simple_copy_to_iter(buf, &iocb->ki_pos, res, to);	\
}

#define DEBUGFS_READONLY_FILE_OPS(name)			\
static const struct debugfs_short_fops name## _ops = {				\
	.read_iter = name## _read,					\
	.llseek = generic_file_llseek,					\
};

#define DEBUGFS_READONLY_FILE(name, fmt, value...)		\
	DEBUGFS_READONLY_FILE_FN(name, fmt, value)		\
	DEBUGFS_READONLY_FILE_OPS(name)

#define DEBUGFS_ADD(name)						\
	debugfs_create_file(#name, 0400, phyd, local, &name## _ops)

#define DEBUGFS_ADD_MODE(name, mode)					\
	debugfs_create_file(#name, mode, phyd, local, &name## _ops);


DEBUGFS_READONLY_FILE(hw_conf, "%x",
		      local->hw.conf.flags);
DEBUGFS_READONLY_FILE(user_power, "%d",
		      local->user_power_level);
DEBUGFS_READONLY_FILE(power, "%d",
		      local->hw.conf.power_level);
DEBUGFS_READONLY_FILE(total_ps_buffered, "%d",
		      local->total_ps_buffered);
DEBUGFS_READONLY_FILE(wep_iv, "%#08x",
		      local->wep_iv & 0xffffff);
DEBUGFS_READONLY_FILE(rate_ctrl_alg, "%s",
	local->rate_ctrl ? local->rate_ctrl->ops->name : "hw/driver");

static ssize_t aqm_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	struct fq *fq = &local->fq;
	char buf[200];
	int len = 0;

	spin_lock_bh(&local->fq.lock);

	len = scnprintf(buf, sizeof(buf),
			"access name value\n"
			"R fq_flows_cnt %u\n"
			"R fq_backlog %u\n"
			"R fq_overlimit %u\n"
			"R fq_overmemory %u\n"
			"R fq_collisions %u\n"
			"R fq_memory_usage %u\n"
			"RW fq_memory_limit %u\n"
			"RW fq_limit %u\n"
			"RW fq_quantum %u\n",
			fq->flows_cnt,
			fq->backlog,
			fq->overmemory,
			fq->overlimit,
			fq->collisions,
			fq->memory_usage,
			fq->memory_limit,
			fq->limit,
			fq->quantum);

	spin_unlock_bh(&local->fq.lock);

	return simple_copy_to_iter(buf, &iocb->ki_pos, len, to);
}

static ssize_t aqm_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	char buf[100];

	if (count >= sizeof(buf))
		return -EINVAL;

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	if (count && buf[count - 1] == '\n')
		buf[count - 1] = '\0';
	else
		buf[count] = '\0';

	if (sscanf(buf, "fq_limit %u", &local->fq.limit) == 1)
		return count;
	else if (sscanf(buf, "fq_memory_limit %u", &local->fq.memory_limit) == 1)
		return count;
	else if (sscanf(buf, "fq_quantum %u", &local->fq.quantum) == 1)
		return count;

	return -EINVAL;
}

static const struct debugfs_short_fops aqm_ops = {
	.write_iter = aqm_write,
	.read_iter = aqm_read,
	.llseek = default_llseek,
};

static ssize_t airtime_flags_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	char buf[128] = {}, *pos, *end;

	pos = buf;
	end = pos + sizeof(buf) - 1;

	if (local->airtime_flags & AIRTIME_USE_TX)
		pos += scnprintf(pos, end - pos, "AIRTIME_TX\t(%lx)\n",
				 AIRTIME_USE_TX);
	if (local->airtime_flags & AIRTIME_USE_RX)
		pos += scnprintf(pos, end - pos, "AIRTIME_RX\t(%lx)\n",
				 AIRTIME_USE_RX);

	return simple_copy_to_iter(buf, &iocb->ki_pos, strlen(buf), to);
}

static ssize_t airtime_flags_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	char buf[16];

	if (count >= sizeof(buf))
		return -EINVAL;

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	if (count && buf[count - 1] == '\n')
		buf[count - 1] = '\0';
	else
		buf[count] = '\0';

	if (kstrtou16(buf, 0, &local->airtime_flags))
		return -EINVAL;

	return count;
}

static const struct debugfs_short_fops airtime_flags_ops = {
	.write_iter = airtime_flags_write,
	.read_iter = airtime_flags_read,
	.llseek = default_llseek,
};

static ssize_t aql_pending_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	char buf[400];
	int len = 0;

	len = scnprintf(buf, sizeof(buf),
			"AC     AQL pending\n"
			"VO     %u us\n"
			"VI     %u us\n"
			"BE     %u us\n"
			"BK     %u us\n"
			"total  %u us\n",
			atomic_read(&local->aql_ac_pending_airtime[IEEE80211_AC_VO]),
			atomic_read(&local->aql_ac_pending_airtime[IEEE80211_AC_VI]),
			atomic_read(&local->aql_ac_pending_airtime[IEEE80211_AC_BE]),
			atomic_read(&local->aql_ac_pending_airtime[IEEE80211_AC_BK]),
			atomic_read(&local->aql_total_pending_airtime));
	return simple_copy_to_iter(buf, &iocb->ki_pos, len, to);
}

static const struct debugfs_short_fops aql_pending_ops = {
	.read_iter = aql_pending_read,
	.llseek = default_llseek,
};

static ssize_t aql_txq_limit_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	char buf[400];
	int len = 0;

	len = scnprintf(buf, sizeof(buf),
			"AC	AQL limit low	AQL limit high\n"
			"VO	%u		%u\n"
			"VI	%u		%u\n"
			"BE	%u		%u\n"
			"BK	%u		%u\n",
			local->aql_txq_limit_low[IEEE80211_AC_VO],
			local->aql_txq_limit_high[IEEE80211_AC_VO],
			local->aql_txq_limit_low[IEEE80211_AC_VI],
			local->aql_txq_limit_high[IEEE80211_AC_VI],
			local->aql_txq_limit_low[IEEE80211_AC_BE],
			local->aql_txq_limit_high[IEEE80211_AC_BE],
			local->aql_txq_limit_low[IEEE80211_AC_BK],
			local->aql_txq_limit_high[IEEE80211_AC_BK]);
	return simple_copy_to_iter(buf, &iocb->ki_pos, len, to);
}

static ssize_t aql_txq_limit_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	char buf[100];
	u32 ac, q_limit_low, q_limit_high, q_limit_low_old, q_limit_high_old;
	struct sta_info *sta;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	if (count && buf[count - 1] == '\n')
		buf[count - 1] = '\0';
	else
		buf[count] = '\0';

	if (sscanf(buf, "%u %u %u", &ac, &q_limit_low, &q_limit_high) != 3)
		return -EINVAL;

	if (ac >= IEEE80211_NUM_ACS)
		return -EINVAL;

	q_limit_low_old = local->aql_txq_limit_low[ac];
	q_limit_high_old = local->aql_txq_limit_high[ac];

	guard(wiphy)(local->hw.wiphy);

	local->aql_txq_limit_low[ac] = q_limit_low;
	local->aql_txq_limit_high[ac] = q_limit_high;

	list_for_each_entry(sta, &local->sta_list, list) {
		/* If a sta has customized queue limits, keep it */
		if (sta->airtime[ac].aql_limit_low == q_limit_low_old &&
		    sta->airtime[ac].aql_limit_high == q_limit_high_old) {
			sta->airtime[ac].aql_limit_low = q_limit_low;
			sta->airtime[ac].aql_limit_high = q_limit_high;
		}
	}

	return count;
}

static const struct debugfs_short_fops aql_txq_limit_ops = {
	.write_iter = aql_txq_limit_write,
	.read_iter = aql_txq_limit_read,
	.llseek = default_llseek,
};

static ssize_t aql_enable_read(struct kiocb *iocb, struct iov_iter *to)
{
	char buf[3];
	int len;

	len = scnprintf(buf, sizeof(buf), "%d\n",
			!static_key_false(&aql_disable.key));

	return simple_copy_to_iter(buf, &iocb->ki_pos, len, to);
}

static ssize_t aql_enable_write(struct kiocb *iocb, struct iov_iter *from)
{
	bool aql_disabled = static_key_false(&aql_disable.key);
	size_t count = iov_iter_count(from);
	char buf[3];
	size_t len;

	if (count > sizeof(buf))
		return -EINVAL;

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	buf[sizeof(buf) - 1] = '\0';
	len = strlen(buf);
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = 0;

	if (buf[0] == '0' && buf[1] == '\0') {
		if (!aql_disabled)
			static_branch_inc(&aql_disable);
	} else if (buf[0] == '1' && buf[1] == '\0') {
		if (aql_disabled)
			static_branch_dec(&aql_disable);
	} else {
		return -EINVAL;
	}

	return count;
}

static const struct debugfs_short_fops aql_enable_ops = {
	.write_iter = aql_enable_write,
	.read_iter = aql_enable_read,
	.llseek = default_llseek,
};

static ssize_t force_tx_status_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	char buf[3];
	int len = 0;

	len = scnprintf(buf, sizeof(buf), "%d\n", (int)local->force_tx_status);

	return simple_copy_to_iter(buf, &iocb->ki_pos, len, to);
}

static ssize_t force_tx_status_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	char buf[3];

	if (count >= sizeof(buf))
		return -EINVAL;

	if (!copy_from_iter_full(buf, count, from))
		return -EFAULT;

	if (count && buf[count - 1] == '\n')
		buf[count - 1] = '\0';
	else
		buf[count] = '\0';

	if (buf[0] == '0' && buf[1] == '\0')
		local->force_tx_status = 0;
	else if (buf[0] == '1' && buf[1] == '\0')
		local->force_tx_status = 1;
	else
		return -EINVAL;

	return count;
}

static const struct debugfs_short_fops force_tx_status_ops = {
	.write_iter = force_tx_status_write,
	.read_iter = force_tx_status_read,
	.llseek = default_llseek,
};

#ifdef CONFIG_PM
static ssize_t reset_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t count = iov_iter_count(from);
	int ret;

	rtnl_lock();
	wiphy_lock(local->hw.wiphy);
	__ieee80211_suspend(&local->hw, NULL);
	ret = __ieee80211_resume(&local->hw);
	wiphy_unlock(local->hw.wiphy);

	if (ret)
		cfg80211_shutdown_all_interfaces(local->hw.wiphy);

	rtnl_unlock();

	return count;
}

static const struct debugfs_short_fops reset_ops = {
	.write_iter = reset_write,
	.llseek = noop_llseek,
};
#endif

static const char *hw_flag_names[] = {
#define FLAG(F)	[IEEE80211_HW_##F] = #F
	FLAG(HAS_RATE_CONTROL),
	FLAG(RX_INCLUDES_FCS),
	FLAG(HOST_BROADCAST_PS_BUFFERING),
	FLAG(SIGNAL_UNSPEC),
	FLAG(SIGNAL_DBM),
	FLAG(NEED_DTIM_BEFORE_ASSOC),
	FLAG(SPECTRUM_MGMT),
	FLAG(AMPDU_AGGREGATION),
	FLAG(SUPPORTS_PS),
	FLAG(PS_NULLFUNC_STACK),
	FLAG(SUPPORTS_DYNAMIC_PS),
	FLAG(MFP_CAPABLE),
	FLAG(WANT_MONITOR_VIF),
	FLAG(NO_VIRTUAL_MONITOR),
	FLAG(NO_AUTO_VIF),
	FLAG(SW_CRYPTO_CONTROL),
	FLAG(SUPPORT_FAST_XMIT),
	FLAG(REPORTS_TX_ACK_STATUS),
	FLAG(CONNECTION_MONITOR),
	FLAG(QUEUE_CONTROL),
	FLAG(SUPPORTS_PER_STA_GTK),
	FLAG(AP_LINK_PS),
	FLAG(TX_AMPDU_SETUP_IN_HW),
	FLAG(SUPPORTS_RC_TABLE),
	FLAG(P2P_DEV_ADDR_FOR_INTF),
	FLAG(TIMING_BEACON_ONLY),
	FLAG(SUPPORTS_HT_CCK_RATES),
	FLAG(CHANCTX_STA_CSA),
	FLAG(SUPPORTS_CLONED_SKBS),
	FLAG(SINGLE_SCAN_ON_ALL_BANDS),
	FLAG(TDLS_WIDER_BW),
	FLAG(SUPPORTS_AMSDU_IN_AMPDU),
	FLAG(BEACON_TX_STATUS),
	FLAG(NEEDS_UNIQUE_STA_ADDR),
	FLAG(SUPPORTS_REORDERING_BUFFER),
	FLAG(USES_RSS),
	FLAG(TX_AMSDU),
	FLAG(TX_FRAG_LIST),
	FLAG(REPORTS_LOW_ACK),
	FLAG(SUPPORTS_TX_FRAG),
	FLAG(SUPPORTS_TDLS_BUFFER_STA),
	FLAG(DOESNT_SUPPORT_QOS_NDP),
	FLAG(BUFF_MMPDU_TXQ),
	FLAG(SUPPORTS_VHT_EXT_NSS_BW),
	FLAG(STA_MMPDU_TXQ),
	FLAG(TX_STATUS_NO_AMPDU_LEN),
	FLAG(SUPPORTS_MULTI_BSSID),
	FLAG(SUPPORTS_ONLY_HE_MULTI_BSSID),
	FLAG(AMPDU_KEYBORDER_SUPPORT),
	FLAG(SUPPORTS_TX_ENCAP_OFFLOAD),
	FLAG(SUPPORTS_RX_DECAP_OFFLOAD),
	FLAG(SUPPORTS_CONC_MON_RX_DECAP),
	FLAG(DETECTS_COLOR_COLLISION),
	FLAG(MLO_MCAST_MULTI_LINK_TX),
	FLAG(DISALLOW_PUNCTURING),
	FLAG(HANDLES_QUIET_CSA),
	FLAG(STRICT),
#undef FLAG
};

static ssize_t hwflags_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	size_t bufsz = 30 * NUM_IEEE80211_HW_FLAGS;
	char *buf = kzalloc(bufsz, GFP_KERNEL);
	char *pos = buf, *end = buf + bufsz - 1;
	ssize_t rv;
	int i;

	if (!buf)
		return -ENOMEM;

	/* fail compilation if somebody adds or removes
	 * a flag without updating the name array above
	 */
	BUILD_BUG_ON(ARRAY_SIZE(hw_flag_names) != NUM_IEEE80211_HW_FLAGS);

	for (i = 0; i < NUM_IEEE80211_HW_FLAGS; i++) {
		if (test_bit(i, local->hw.flags))
			pos += scnprintf(pos, end - pos, "%s\n",
					 hw_flag_names[i]);
	}

	rv = simple_copy_to_iter(buf, &iocb->ki_pos, strlen(buf), to);
	kfree(buf);
	return rv;
}

static ssize_t hwflags_write(struct file *file, const char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	struct ieee80211_local *local = file->private_data;
	char buf[100];
	int val;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	if (count && buf[count - 1] == '\n')
		buf[count - 1] = '\0';
	else
		buf[count] = '\0';

	if (sscanf(buf, "strict=%d", &val) == 1) {
		switch (val) {
		case 0:
			ieee80211_hw_set(&local->hw, STRICT);
			return count;
		case 1:
			__clear_bit(IEEE80211_HW_STRICT, local->hw.flags);
			return count;
		default:
			return -EINVAL;
		}
	}

	return -EINVAL;
}
FOPS_WRITE_ITER_HELPER(hwflags_write);

static const struct file_operations hwflags_ops = {
	.open = simple_open,
	.read_iter = hwflags_read,
	.write_iter = hwflags_write_iter,
};

static ssize_t misc_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	/* Max len of each line is 16 characters, plus 9 for 'pending:\n' */
	size_t bufsz = IEEE80211_MAX_QUEUES * 16 + 9;
	char *buf;
	char *pos, *end;
	ssize_t rv;
	int i;
	int ln;

	buf = kzalloc(bufsz, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	pos = buf;
	end = buf + bufsz - 1;

	pos += scnprintf(pos, end - pos, "pending:\n");

	for (i = 0; i < IEEE80211_MAX_QUEUES; i++) {
		ln = skb_queue_len(&local->pending[i]);
		pos += scnprintf(pos, end - pos, "[%i] %d\n",
				 i, ln);
	}

	rv = simple_copy_to_iter(buf, &iocb->ki_pos, strlen(buf), to);
	kfree(buf);
	return rv;
}

static ssize_t queues_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct ieee80211_local *local = iocb->ki_filp->private_data;
	unsigned long flags;
	char buf[IEEE80211_MAX_QUEUES * 20];
	int q, res = 0;

	spin_lock_irqsave(&local->queue_stop_reason_lock, flags);
	for (q = 0; q < local->hw.queues; q++)
		res += sprintf(buf + res, "%02d: %#.8lx/%d\n", q,
				local->queue_stop_reasons[q],
				skb_queue_len(&local->pending[q]));
	spin_unlock_irqrestore(&local->queue_stop_reason_lock, flags);

	return simple_copy_to_iter(buf, &iocb->ki_pos, res, to);
}

DEBUGFS_READONLY_FILE_OPS(queues);
DEBUGFS_READONLY_FILE_OPS(misc);

/* statistics stuff */

static ssize_t format_devstat_counter(struct ieee80211_local *local,
	struct kiocb *iocb, struct iov_iter *to,
	int (*printvalue)(struct ieee80211_low_level_stats *stats, char *buf,
			  int buflen))
{
	struct ieee80211_low_level_stats stats;
	char buf[20];
	int res;

	wiphy_lock(local->hw.wiphy);
	res = drv_get_stats(local, &stats);
	wiphy_unlock(local->hw.wiphy);
	if (res)
		return res;
	res = printvalue(&stats, buf, sizeof(buf));
	return simple_copy_to_iter(buf, &iocb->ki_pos, res, to);
}

#define DEBUGFS_DEVSTATS_FILE(name)					\
static int print_devstats_##name(struct ieee80211_low_level_stats *stats,\
				 char *buf, int buflen)			\
{									\
	return scnprintf(buf, buflen, "%u\n", stats->name);		\
}									\
static ssize_t stats_ ##name## _read(struct kiocb *iocb,		\
				     struct iov_iter *to)		\
{									\
	return format_devstat_counter(iocb->ki_filp->private_data,	\
				      iocb, to,				\
				      print_devstats_##name);		\
}									\
									\
static const struct debugfs_short_fops stats_ ##name## _ops = {			\
	.read_iter = stats_ ##name## _read,				\
	.llseek = generic_file_llseek,					\
};

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
#define DEBUGFS_STATS_ADD(name)					\
	debugfs_create_u32(#name, 0400, statsd, &local->name);
#endif
#define DEBUGFS_DEVSTATS_ADD(name)					\
	debugfs_create_file(#name, 0400, statsd, local, &stats_ ##name## _ops);

DEBUGFS_DEVSTATS_FILE(dot11ACKFailureCount);
DEBUGFS_DEVSTATS_FILE(dot11RTSFailureCount);
DEBUGFS_DEVSTATS_FILE(dot11FCSErrorCount);
DEBUGFS_DEVSTATS_FILE(dot11RTSSuccessCount);

void debugfs_hw_add(struct ieee80211_local *local)
{
	struct dentry *phyd = local->hw.wiphy->debugfsdir;
	struct dentry *statsd;

	if (!phyd)
		return;

	local->debugfs.keys = debugfs_create_dir("keys", phyd);

	DEBUGFS_ADD(total_ps_buffered);
	DEBUGFS_ADD(wep_iv);
	DEBUGFS_ADD(rate_ctrl_alg);
	DEBUGFS_ADD(queues);
	DEBUGFS_ADD(misc);
#ifdef CONFIG_PM
	DEBUGFS_ADD_MODE(reset, 0200);
#endif
	DEBUGFS_ADD_MODE(hwflags, 0600);
	DEBUGFS_ADD(user_power);
	DEBUGFS_ADD(power);
	DEBUGFS_ADD(hw_conf);
	DEBUGFS_ADD_MODE(force_tx_status, 0600);
	DEBUGFS_ADD_MODE(aql_enable, 0600);
	DEBUGFS_ADD(aql_pending);
	DEBUGFS_ADD_MODE(aqm, 0600);

	DEBUGFS_ADD_MODE(airtime_flags, 0600);

	DEBUGFS_ADD(aql_txq_limit);
	debugfs_create_u32("aql_threshold", 0600,
			   phyd, &local->aql_threshold);

	statsd = debugfs_create_dir("statistics", phyd);

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
	DEBUGFS_STATS_ADD(dot11TransmittedFragmentCount);
	DEBUGFS_STATS_ADD(dot11MulticastTransmittedFrameCount);
	DEBUGFS_STATS_ADD(dot11FailedCount);
	DEBUGFS_STATS_ADD(dot11RetryCount);
	DEBUGFS_STATS_ADD(dot11MultipleRetryCount);
	DEBUGFS_STATS_ADD(dot11FrameDuplicateCount);
	DEBUGFS_STATS_ADD(dot11ReceivedFragmentCount);
	DEBUGFS_STATS_ADD(dot11MulticastReceivedFrameCount);
	DEBUGFS_STATS_ADD(dot11TransmittedFrameCount);
	DEBUGFS_STATS_ADD(tx_handlers_queued);
	DEBUGFS_STATS_ADD(tx_handlers_drop_wep);
	DEBUGFS_STATS_ADD(tx_handlers_drop_not_assoc);
	DEBUGFS_STATS_ADD(tx_handlers_drop_unauth_port);
	DEBUGFS_STATS_ADD(rx_handlers_drop);
	DEBUGFS_STATS_ADD(rx_handlers_queued);
	DEBUGFS_STATS_ADD(rx_handlers_drop_nullfunc);
	DEBUGFS_STATS_ADD(rx_handlers_drop_defrag);
	DEBUGFS_STATS_ADD(tx_expand_skb_head);
	DEBUGFS_STATS_ADD(tx_expand_skb_head_cloned);
	DEBUGFS_STATS_ADD(rx_expand_skb_head_defrag);
	DEBUGFS_STATS_ADD(rx_handlers_fragments);
	DEBUGFS_STATS_ADD(tx_status_drop);
#endif
	DEBUGFS_DEVSTATS_ADD(dot11ACKFailureCount);
	DEBUGFS_DEVSTATS_ADD(dot11RTSFailureCount);
	DEBUGFS_DEVSTATS_ADD(dot11FCSErrorCount);
	DEBUGFS_DEVSTATS_ADD(dot11RTSSuccessCount);
}
