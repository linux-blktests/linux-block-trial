// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_BPF_OPS_H
#define IOU_BPF_OPS_H

#include <linux/io_uring_types.h>

enum {
	IOU_REGION_MEM,
	IOU_REGION_CQ,
	IOU_REGION_SQ,
};

struct io_uring_poll_event_priv {
	struct io_uring_poll_event	pub;
	struct io_kiocb			*req;
};

struct io_uring_bpf_ops {
	int (*loop_step)(struct io_ring_ctx *ctx, struct iou_loop_params *lp);

	/*
	 * Invoked from io_poll_wake when a poll-armed request with
	 * REQ_F_POLL_BPF wakes. Returns 1 if no action should be taken,
	 * 0 otherwise to let the request proceed.
	 */
	int (*poll_gate)(struct io_uring_poll_event *ev);

	__u32 ring_fd;
	void *priv;
};

#ifdef CONFIG_IO_URING_BPF_OPS
void io_unregister_bpf_ops(struct io_ring_ctx *ctx);
#else
static inline void io_unregister_bpf_ops(struct io_ring_ctx *ctx)
{
}
#endif

#endif /* IOU_BPF_OPS_H */
