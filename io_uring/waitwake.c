// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/wait.h>
#include <linux/xarray.h>
#include <linux/slab.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "cancel.h"
#include "refs.h"
#include "waitwake.h"

static DEFINE_XARRAY_FLAGS(waitwake_ids, XA_FLAGS_ALLOC);

struct io_wait_head {
	atomic_t		refs;
	spinlock_t		lock;
	u32			id;
	struct list_head	list;
	struct rcu_head		rcu_head;
};

struct io_wait {
	struct file		*file;
	struct list_head	entry;
	struct io_wait_head	*head;
	atomic_t		refs;
	u32			id;
	unsigned int		flags;
};

struct io_wake {
	struct file		*file;
	__u64			key;
	int			id;
	unsigned int		flags;
};

#define IO_WAIT_CANCEL_FLAG	BIT(31)
#define IO_WAIT_REF_MASK	GENMASK(30, 0)

static void io_wait_head_free(struct rcu_head *rcu_head)
{
	struct io_wait_head *head;

	head = container_of(rcu_head, struct io_wait_head, rcu_head);
	WARN_ON_ONCE(!list_empty(&head->list));
	kfree(head);
}

static void io_wait_head_put(struct io_wait_head *head)
{
	if (atomic_dec_and_test(&head->refs)) {
		xa_erase(&waitwake_ids, head->id);
		call_rcu(&head->rcu_head, io_wait_head_free);
	}
}

static struct io_wait_head *io_wait_head_get(struct io_wait *w)
{
	struct io_wait_head *head;
	int ret;

retry:
	if (w->flags & IORING_WAIT_ID_SET) {
		guard(rcu)();
		head = xa_load(&waitwake_ids, w->id);
		if (head && atomic_inc_not_zero(&head->refs))
			return head;
	}

	head = kmalloc(sizeof(*head), GFP_KERNEL_ACCOUNT);
	if (unlikely(!head))
		return ERR_PTR(-ENOMEM);

	atomic_set(&head->refs, 1);
	spin_lock_init(&head->lock);
	INIT_LIST_HEAD(&head->list);

	if (w->flags & IORING_WAIT_ID_SET) {
		head->id = w->id;
		ret = xa_insert(&waitwake_ids, w->id, head, GFP_KERNEL_ACCOUNT);
		if (ret == -EBUSY) {
			kfree(head);
			goto retry;
		}
	} else {
		u32 next;

		ret = xa_alloc_cyclic(&waitwake_ids, &head->id, head,
					XA_LIMIT(0, INT_MAX), &next,
					GFP_KERNEL_ACCOUNT);
	}
	if (ret >= 0) {
		w->id = head->id;
		return head;
	}
	kfree(head);
	return ERR_PTR(ret);
}

static void __io_waitwake_complete(struct io_kiocb *req, int res)
{
	struct io_wait *w = io_kiocb_to_cmd(req, struct io_wait);
	struct io_wait_head *head;

	head = READ_ONCE(w->head);
	if (head) {
		w->head = NULL;
		spin_lock(&head->lock);
		list_del_rcu(&w->entry);
		spin_unlock(&head->lock);
		io_wait_head_put(head);
	}

	hlist_del_init(&req->hash_node);
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}

static void io_wait_single_cb(struct io_wait *w)
{
	struct io_kiocb *req = cmd_to_io_kiocb(w);

	__io_waitwake_complete(req, 0);
}

static void io_wait_multi_cb(struct io_wait *w)
{
	struct io_kiocb *req = cmd_to_io_kiocb(w);
	struct io_uring_cqe cqe[2];

	cqe[0].user_data = req->cqe.user_data;
	cqe[0].res = req->cqe.res;
	cqe[0].flags = req->cqe.flags | IORING_CQE_F_MORE;
	cqe[0].big_cqe[0]= req->big_cqe.extra1;
	cqe[0].big_cqe[1]= req->big_cqe.extra2;
	if (unlikely(!io_req_post_cqe32(req, cqe)))
		io_cqe_overflow(req->ctx, &req->cqe, &req->big_cqe);
}

static void io_wait_cb(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_wait *w = io_kiocb_to_cmd(tw_req.req, struct io_wait);
	int val, loops = 0;

	do {
		val = atomic_read(&w->refs);
		if (unlikely(val & IO_WAIT_CANCEL_FLAG)) {
			__io_waitwake_complete(tw_req.req, -ECANCELED);
			break;
		}
		if (loops)
			continue;
		else if (w->flags & IORING_WAIT_SINGLE_SHOT)
			io_wait_single_cb(w);
		else
			io_wait_multi_cb(w);
		loops++;
	} while (atomic_sub_return(val, &w->refs) & IO_WAIT_REF_MASK);
}

static int io_wait_func(struct io_wait *w, struct io_wake *wa)
{
	struct io_kiocb *req = cmd_to_io_kiocb(w);

	if (atomic_fetch_inc(&w->refs) & IO_WAIT_REF_MASK)
		return 0;

	io_req_set_res32(req, wa->id, 0, wa->key, 0);
	req->io_task_work.func = io_wait_cb;
	io_req_task_work_add(req);
	return 1;
}

#define IO_WAIT_VALID_FLAGS	(IORING_WAIT_SINGLE_SHOT | IORING_WAIT_ID_SET)

int io_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_wait *w = io_kiocb_to_cmd(req, struct io_wait);

	if (sqe->fd || sqe->off || sqe->addr || sqe->file_index || sqe->addr3)
		return -EINVAL;
	if (!(req->ctx->flags & (IORING_SETUP_CQE32|IORING_SETUP_CQE_MIXED)))
		return -EINVAL;

	w->id = READ_ONCE(sqe->len);
	w->flags = READ_ONCE(sqe->rw_flags);
	if (w->flags & ~IO_WAIT_VALID_FLAGS)
		return -EINVAL;

	w->head = NULL;
	atomic_set(&w->refs, 0);
	INIT_LIST_HEAD(&w->entry);
	return 0;
}

int io_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_wait *w = io_kiocb_to_cmd(req, struct io_wait);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_wait_head *head;

	head = io_wait_head_get(w);
	if (IS_ERR(head))
		return PTR_ERR(head);

	if (unlikely(!io_req_post_cqe(req, w->id, IORING_CQE_F_MORE))) {
		io_wait_head_put(head);
		return -EOVERFLOW;
	}

	w->head = head;
	spin_lock(&head->lock);
	list_add_tail_rcu(&w->entry, &head->list);
	spin_unlock(&head->lock);

	io_ring_submit_lock(ctx, issue_flags);
	hlist_add_head(&req->hash_node, &ctx->waitwake_list);
	io_ring_submit_unlock(ctx, issue_flags);

	return IOU_ISSUE_SKIP_COMPLETE;
}

int io_wake_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_wake *w = io_kiocb_to_cmd(req, struct io_wake);

	if (sqe->fd || sqe->addr || sqe->file_index || sqe->addr3)
		return -EINVAL;

	w->id = READ_ONCE(sqe->len);
	w->key = READ_ONCE(sqe->off);
	w->flags = READ_ONCE(sqe->rw_flags);
	if (w->flags & ~IORING_WAKE_ALL)
		return -EINVAL;

	return 0;
}

int io_wake(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_wake *w = io_kiocb_to_cmd(req, struct io_wake);
	struct io_wait_head *head;
	struct io_wait *we;
	int ret = 0;

	scoped_guard(rcu) {
		head = xa_load(&waitwake_ids, w->id);
		if (!head || !atomic_inc_not_zero(&head->refs))
			return -ENOENT;

		list_for_each_entry_rcu(we, &head->list, entry) {
			ret += io_wait_func(we, w);
			if (w->flags & IORING_WAKE_ALL)
				continue;
			if (ret)
				break;
		}
	}

	io_req_set_res(req, ret, 0);
	io_wait_head_put(head);
	return IOU_COMPLETE;
}

static bool __io_waitwake_cancel(struct io_kiocb *req)
{
	struct io_wait *w = io_kiocb_to_cmd(req, struct io_wait);

	lockdep_assert_held(&req->ctx->uring_lock);

	atomic_or(IO_WAIT_CANCEL_FLAG, &w->refs);

	if (atomic_fetch_inc(&w->refs) & IO_WAIT_REF_MASK)
		return false;

	io_req_set_res(req, -ECANCELED, 0);
	__io_waitwake_complete(req, -ECANCELED);
	return true;
}

int io_waitwake_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		       unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->waitwake_list,
				__io_waitwake_cancel);
}

int io_waitwake_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			   bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->waitwake_list, cancel_all,
					__io_waitwake_cancel);
}
