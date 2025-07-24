// SPDX-License-Identifier: GPL-2.0
struct io_queue_chan_entry {
	struct io_uring_cqe	cqes[2];
};

enum {
	/* channel destination ring in overflow */
	RING_CHAN_OVERFLOW	= 1,
	/* other end went away */
	RING_CHAN_DEAD		= 2,
};

struct io_queue_chan {
	struct {
		atomic_t		refs;
		__u32			head;
		struct io_kiocb		req;
	} ____cacheline_aligned_in_smp;
	__u32				nentries;
	__u32				mask;
	__u32				tail;
	__u32				resp_id;
	atomic_t			flags;
	struct io_ring_ctx __rcu	*dst_ring;
	struct io_queue_chan_entry	data[];
};

int io_register_add_queue_chan(struct io_ring_ctx *ctx, void __user *arg);
void io_unregister_queue_chans(struct io_ring_ctx *ctx);
void io_chan_clear_overflow(struct io_ring_ctx *ctx);

int io_chan_post_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_chan_post(struct io_kiocb *req, unsigned int issue_flags);
