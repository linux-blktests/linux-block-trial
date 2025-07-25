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
		if (atomic_dec_and_test(&c->refs))
			kfree_rcu(c, rcu_head);
	}
	xa_for_each(&ctx->xa_dst_chan, index, c) {
		if (rcu_dereference(c->dst_ring) == ctx) {
			percpu_ref_put(&ctx->refs);
			rcu_assign_pointer(c->dst_ring, NULL);
		}
		if (atomic_dec_and_test(&c->refs))
			kfree_rcu(c, rcu_head);
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

	ret = xa_alloc(&ctx->xa_src_chan, &ids->src_id, c, lim, GFP_KERNEL_ACCOUNT);
	if (ret) {
		kfree_rcu(c, rcu_head);
		return ERR_PTR(ret);
	}

	ret = xa_alloc(&dst->xa_dst_chan, &ids->dst_id, c, lim, GFP_KERNEL_ACCOUNT);
	if (ret) {
		xa_erase(&ctx->xa_src_chan, ids->src_id);
		kfree_rcu(c, rcu_head);
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
	kfree_rcu(c, rcu_head);
}

static bool valid_ring_flags(struct io_ring_ctx *ctx)
{
	/*
	 * Must be DEFER_TASKRUN (could be relaxed) and CQE32 to be able to
	 * send enough data.
	 */
	if ((ctx->flags & (IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_CQE32)) !=
	    (IORING_SETUP_DEFER_TASKRUN|IORING_SETUP_CQE32))
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
