// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_WAIT_H
#define IOU_WAIT_H

#include <linux/io_uring_types.h>

/*
 * No waiters. ->cq_wait_nr holds this when no task is waiting, and is
 * reset back to it by the task work add side when it claims a wake up,
 * so that only one wake up is issued per arming of the wait.
 */
#define IO_CQ_WAKE_INIT		(-1U)

/*
 * A waiter only sleeps on an empty work list (it checks for pending work after
 * arming), hence the number of lazy adds since arming is the full pending
 * count. The release pairs with the acquire in io_req_local_work_add(), hence
 * a producer observing the armed ->cq_wait_nr also observes the zeroed
 * ->cq_wait_added.
 */
static inline void io_cq_wait_arm(struct io_ring_ctx *ctx, int nr_wait)
{
	atomic_set(&ctx->cq_wait_added, 0);
	atomic_set_release(&ctx->cq_wait_nr, nr_wait);
}

struct ext_arg {
	size_t argsz;
	struct timespec64 ts;
	const sigset_t __user *sig;
	ktime_t min_time;
	bool ts_set;
	bool iowait;
};

int io_cqring_wait(struct io_ring_ctx *ctx, int min_events, u32 flags,
		   struct ext_arg *ext_arg);
int io_run_task_work_sig(struct io_ring_ctx *ctx);
void io_cqring_do_overflow_flush(struct io_ring_ctx *ctx);
void io_cqring_overflow_flush_locked(struct io_ring_ctx *ctx);

static inline unsigned int __io_cqring_events(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = io_get_rings(ctx);
	return ctx->cached_cq_tail - READ_ONCE(rings->cq.head);
}

static inline unsigned int __io_cqring_events_user(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = io_get_rings(ctx);

	return READ_ONCE(rings->cq.tail) - READ_ONCE(rings->cq.head);
}

/*
 * Reads the tail/head of the CQ ring while providing an acquire ordering,
 * see comment at top of io_uring.c.
 */
static inline unsigned io_cqring_events(struct io_ring_ctx *ctx)
{
	smp_rmb();
	return __io_cqring_events(ctx);
}

#endif
