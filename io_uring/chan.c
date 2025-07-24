// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "register.h"
#include "chan.h"

struct io_chan_post {
	struct file		*file;
	unsigned int		queue;
	unsigned int		flags;
	struct io_uring_cqe	cqes[2];
};

/*
 * ctx1 is already locked on entry, both will be locked on return.
 */
static void io_ctx_double_lock(struct io_ring_ctx *ctx1,
			       struct io_ring_ctx *ctx2)
{
	if (ctx1 < ctx2) {
		mutex_lock_nested(&ctx2->uring_lock, SINGLE_DEPTH_NESTING);
	} else {
		mutex_unlock(&ctx1->uring_lock);
		mutex_lock(&ctx2->uring_lock);
		mutex_lock_nested(&ctx1->uring_lock, SINGLE_DEPTH_NESTING);
	}
}

void io_unregister_queue_chans(struct io_ring_ctx *ctx)
{
	struct io_queue_chan *c;
	unsigned long index;

	lockdep_assert_held(&ctx->uring_lock);

	rcu_read_lock();
	xa_for_each(&ctx->xa_src_chan, index, c) {
		atomic_or(RING_CHAN_DEAD, &c->flags);
		if (atomic_dec_and_test(&c->refs))
			kfree_rcu(c, req.rcu_head);
	}
	xa_for_each(&ctx->xa_dst_chan, index, c) {
		atomic_or(RING_CHAN_DEAD, &c->flags);
		if (rcu_dereference(c->dst_ring) == ctx) {
			percpu_ref_put(&ctx->refs);
			rcu_assign_pointer(c->dst_ring, NULL);
		}
		if (atomic_dec_and_test(&c->refs))
			kfree_rcu(c, req.rcu_head);
	}
	rcu_read_unlock();
	xa_destroy(&ctx->xa_src_chan);
	xa_destroy(&ctx->xa_dst_chan);
}

struct chan_ids {
	__u32 src_id;
	__u32 dst_id;
};

static struct io_queue_chan *__io_register_queue_chan(struct io_ring_ctx *ctx,
						      struct io_ring_ctx *dst,
						      struct io_uring_chan_reg *chan,
						      struct chan_ids *ids)
{
	struct xa_limit lim = { .max = SHRT_MAX, .min = 0 };
	struct io_queue_chan *c;
	size_t chan_size;
	int ret;

	if (percpu_ref_is_dying(&dst->refs))
		return ERR_PTR(-ENXIO);

	chan_size = struct_size(c, data, chan->nentries);
	if (chan_size == SIZE_MAX || chan_size > KMALLOC_MAX_SIZE)
		return ERR_PTR(-EOVERFLOW);

	c = kzalloc(chan_size, GFP_KERNEL_ACCOUNT);
	if (!c)
		return ERR_PTR(-ENOMEM);

	/*
	 * One ref for each ring that is attached to an endpoint. Having refs
	 * != 2 then also means that one end has detached and the channel
	 * can be considered dead.
	 */
	atomic_set(&c->refs, 2);
	c->nentries = chan->nentries;
	c->mask = chan->nentries - 1;
	c->req.ctx = dst;

	ret = xa_alloc(&ctx->xa_src_chan, &ids->src_id, c, lim, GFP_KERNEL_ACCOUNT);
	if (ret) {
		kfree_rcu(c, req.rcu_head);
		return ERR_PTR(ret);
	}

	ret = xa_alloc(&dst->xa_dst_chan, &ids->dst_id, c, lim, GFP_KERNEL_ACCOUNT);
	if (ret) {
		xa_erase(&ctx->xa_src_chan, ids->src_id);
		kfree_rcu(c, req.rcu_head);
		return ERR_PTR(ret);
	}

	percpu_ref_get(&dst->refs);
	rcu_assign_pointer(c->dst_ring, dst);
	return c;
}

static void io_chan_free(struct io_ring_ctx *ctx, struct io_ring_ctx *dst,
			 struct chan_ids *ids)
{
	struct io_queue_chan *c;

	c = xa_erase(&ctx->xa_src_chan, ids->src_id);
	xa_erase(&dst->xa_dst_chan, ids->dst_id);
	percpu_ref_put(&dst->refs);
	atomic_sub(2, &c->refs);
	kfree_rcu(c, req.rcu_head);
}

static bool valid_ring_flags(struct io_ring_ctx *ctx)
{
	/*
	 * Must be DEFER_TASKRUN (could be relaxed) and be able to post 32b
	 * CQEs.
	 */
	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN))
		return false;
	if (!(ctx->flags & (IORING_SETUP_CQE32|IORING_SETUP_CQE_MIXED)))
		return false;
	return true;
}

int io_register_add_queue_chan(struct io_ring_ctx *ctx, void __user *arg)
{
	struct chan_ids ids1 = { }, ids2 = { };
	struct io_uring_chan_reg chan;
	struct io_queue_chan *c;
	struct io_ring_ctx *dst;
	struct file *file;
	int ret;

	lockdep_assert_held(&ctx->uring_lock);

	if (copy_from_user(&chan, arg, sizeof(chan)))
		return -EFAULT;
	if (chan.flags & ~IORING_CHAN_REG_BIDI)
		return -EINVAL;
	if (!is_power_of_2(chan.nentries))
		return -EINVAL;
	if (memchr_inv(&chan.resv, 0, sizeof(chan.resv)))
		return -EINVAL;

	file = io_uring_register_get_file(chan.dst_fd, false);
	if (IS_ERR(file))
		return PTR_ERR(file);
	dst = file->private_data;
	if (dst == ctx) {
		ret = -EINVAL;
		goto err;
	}
	if (!valid_ring_flags(dst)) {
		ret = -EINVAL;
		goto err;
	}
	if (chan.flags & IORING_CHAN_REG_BIDI && !valid_ring_flags(ctx)) {
		ret = -EINVAL;
		goto err;
	}

	io_ctx_double_lock(ctx, dst);
	c = __io_register_queue_chan(ctx, dst, &chan, &ids1);
	if (IS_ERR(c)) {
		ret = PTR_ERR(c);
		goto unlock;
	}
	if (chan.flags & IORING_CHAN_REG_BIDI) {
		struct io_queue_chan *c2;

		c2 = __io_register_queue_chan(dst, ctx, &chan, &ids2);
		if (IS_ERR(c2)) {
			ret = PTR_ERR(c2);
			io_chan_free(ctx, dst, &ids1);
			goto unlock;
		}
		c->resp_id = ids2.src_id;
	}
	ret = ids1.src_id;
unlock:
	mutex_unlock(&dst->uring_lock);
err:
	fput(file);
	return ret;
}

static void io_flush_chan(struct io_ring_ctx *ctx, struct io_queue_chan *c)
{
	u32 tail, head = c->head;

	tail = smp_load_acquire(&c->tail);
	if (tail == head)
		return;

	if (atomic_read(&c->flags) & RING_CHAN_OVERFLOW)
		return;

	while (head < tail) {
		struct io_queue_chan_entry *e = &c->data[head & c->mask];

		/*
		 * If we fail posting a CQE, mark this ring as needing to
		 * ignore channel postings until overflow has been cleared.
		 * Overflow clearing will clear IO_CHECK_IGNORE_CHAN_BIT as
		 * well.
		 */
		if (!io_add_aux_cqe32(ctx, e->cqes)) {
			atomic_or(RING_CHAN_OVERFLOW, &c->flags);
			break;
		}
		head++;
	}
	smp_store_release(&c->head, head);
}

static void io_flush_chans(struct io_ring_ctx *ctx)
{
	struct io_queue_chan *c;
	unsigned long index;

	xa_for_each(&ctx->xa_dst_chan, index, c)
		io_flush_chan(ctx, c);
}

static void io_chan_tw(struct io_kiocb *req, io_tw_token_t tw)
{
	struct io_queue_chan *c = container_of(req, struct io_queue_chan, req);
	struct io_ring_ctx *ctx = req->ctx;

	atomic_fetch_andnot_acquire(1, &ctx->chan_flags);
	io_flush_chans(ctx);
	percpu_ref_put(&ctx->refs);
	if (atomic_dec_and_test(&c->refs))
		kfree_rcu(c, req.rcu_head);
}

static void io_chan_tw_queue(struct io_ring_ctx *ctx, struct io_queue_chan *c)
{
	struct io_kiocb *req = &c->req;

	if (atomic_fetch_or(1, &ctx->chan_flags))
		return;
	req->io_task_work.func = io_chan_tw;
	percpu_ref_get(&ctx->refs);
	atomic_inc(&c->refs);
	io_req_task_work_add_remote(req, 0);
}

void io_chan_clear_overflow(struct io_ring_ctx *ctx)
{
	struct io_queue_chan *c;
	unsigned long index;

	rcu_read_lock();
	xa_for_each(&ctx->xa_dst_chan, index, c) {
		struct io_ring_ctx *dst_ctx = rcu_dereference(c->dst_ring);

		atomic_andnot(RING_CHAN_OVERFLOW, &c->flags);
		if (dst_ctx)
			io_chan_tw_queue(dst_ctx, c);
	}
	rcu_read_unlock();
}

static struct io_queue_chan *io_chan_find_idle(struct io_ring_ctx *ctx)
{
	struct io_queue_chan *c;
	unsigned long index;

	xa_for_each(&ctx->xa_src_chan, index, c) {
		struct io_ring_ctx *dst_ctx = rcu_dereference(c->dst_ring);

		if (!dst_ctx)
			continue;

		if (c->head != c->tail)
			continue;

		/*
		 * Not 100% reliable, but should be good enough. It'll find
		 * a task waiting for io_uring events, which is what we
		 * care about. Could be combined with TASK_INTERRUPTIBLE
		 * ->submitter_task check for higher accuracy.
		 */
		if (atomic_read(&dst_ctx->cq_wait_nr) <= 0)
			continue;
		return c;
	}

	return NULL;
}

int io_chan_post_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_chan_post *icp = io_kiocb_to_cmd(req, struct io_chan_post);

	if (sqe->len || sqe->personality || sqe->splice_fd_in | sqe->addr3)
		return -EINVAL;

	icp->queue = READ_ONCE(sqe->fd);
	icp->flags = READ_ONCE(sqe->rw_flags);
	if (icp->flags & ~IORING_CHAN_POST_IDLE)
		return -EINVAL;

	icp->cqes->user_data = READ_ONCE(sqe->addr);
	icp->cqes->flags = 0;
	icp->cqes->big_cqe[0] = READ_ONCE(sqe->off);
	icp->cqes->big_cqe[1] = 0;
	return 0;
}

int io_chan_post(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_chan_post *icp = io_kiocb_to_cmd(req, struct io_chan_post);
	struct io_ring_ctx *dst_ctx, *ctx = req->ctx;
	struct io_queue_chan_entry *e;
	struct task_struct *task;
	struct io_queue_chan *c;
	__u32 head, tail;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	rcu_read_lock();
	if (icp->flags & IORING_CHAN_POST_IDLE)
		c = io_chan_find_idle(ctx);
	else
		c = xa_load(&ctx->xa_src_chan, icp->queue);

	if (unlikely(!c || atomic_read(&c->flags) & RING_CHAN_DEAD)) {
		ret = -ENXIO;
		goto err;
	}
	/* ours must be the source end of the channel */
	dst_ctx = rcu_dereference(c->dst_ring);
	if (unlikely(!dst_ctx))
		goto is_dead;
	task = READ_ONCE(dst_ctx->submitter_task);
	if (unlikely(!task)) {
is_dead:
		ret = -EOWNERDEAD;
		goto err;
	}

	head = smp_load_acquire(&c->head);
	tail = c->tail;
	if (tail - head >= c->nentries) {
		ret = -EXFULL;
		goto err;
	}
	/* fill in entry */
	e = &c->data[tail & c->mask];
	icp->cqes->res = c->resp_id;
	memcpy(e->cqes, icp->cqes, sizeof(icp->cqes));
	smp_store_release(&c->tail, tail + 1);
	io_chan_tw_queue(dst_ctx, c);
	ret = 0;
err:
	rcu_read_unlock();
	io_ring_submit_unlock(ctx, issue_flags);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}
