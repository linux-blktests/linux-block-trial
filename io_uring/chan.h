// SPDX-License-Identifier: GPL-2.0
struct io_queue_chan_entry {
	struct io_uring_cqe	cqes[2];
};

struct io_queue_chan {
	struct {
		atomic_t		refs;
		__u32			head;
	} ____cacheline_aligned_in_smp;
	__u32				nentries;
	__u32				mask;
	__u32				tail;
	__u32				resp_id;
	struct rcu_head			rcu_head;
	struct io_queue_chan_entry	data[];
};

int io_register_add_queue_chan(struct io_ring_ctx *ctx, void __user *arg);
void io_unregister_queue_chans(struct io_ring_ctx *ctx);
