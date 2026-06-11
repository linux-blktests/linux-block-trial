// SPDX-License-Identifier: GPL-2.0
/*
 * Support for async file locking: flock and OFD style POSIX byte range
 * locks.
 *
 * For generic VFS managed locks, requests are issued with a single
 * locks_lock_inode() attempt. If a conflicting lock is held, the request
 * is queued on the blocking lock inside fs/locks.c and FILE_LOCK_DEFERRED
 * is returned. Rather than sleeping on the request waitqueue like the
 * sync syscalls do, the request sets ->lm_notify() in the lock manager
 * ops. That callback is invoked when the blocking lock goes away, at
 * which point task_work is queued to retry the lock attempt. A wakeup is
 * not a grant - the retry races with other waiters and may block and
 * defer again, in which case the cycle just repeats.
 *
 * If a file has a ->flock() or ->lock() file operation, the file system
 * manages the lock itself and the above doesn't apply - there's no
 * deferral contract for those, and even a non-blocking attempt may need
 * to sleep (eg a server round trip on a network file system). Such
 * requests are punted to io-wq, where they block like the equivalent
 * syscall would. Cancelation works as io-wq signals the worker, and all
 * file system lock waits are interruptible - but each pending request
 * does occupy an io-wq worker for as long as it waits.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/filelock.h>
#include <linux/security.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "io-wq.h"
#include "locks.h"

struct io_filelock {
	struct file			*file;
	int				type;
	bool				wait;
	bool				cancelled;
	loff_t				start;
	loff_t				end;
};

static void io_filelock_notify(struct file_lock *fl);

static const struct lock_manager_operations io_filelock_lmops = {
	.lm_notify	= io_filelock_notify,
};

static int io_filelock_prep_common(struct io_kiocb *req)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	struct io_filelock_async *ifa;

	ifa = io_uring_alloc_async_data(NULL, req);
	if (unlikely(!ifa))
		return -ENOMEM;
	ifa->req = req;
	/* ensure the request is always safe to release private state on */
	locks_init_lock(&ifa->fl);

	/* the request may be recycled from a previously cancelled one */
	ifl->cancelled = false;

	/* Mark as inflight, so task exit cancelation will find it */
	io_req_track_inflight(req);
	return 0;
}

int io_flock_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	unsigned int op;

	if (unlikely(sqe->ioprio || sqe->off || sqe->addr || sqe->len ||
		     sqe->buf_index || sqe->splice_fd_in || sqe->addr3))
		return -EINVAL;

	op = READ_ONCE(sqe->flock_flags);
	switch (op & ~LOCK_NB) {
	case LOCK_SH:
		ifl->type = F_RDLCK;
		break;
	case LOCK_EX:
		ifl->type = F_WRLCK;
		break;
	case LOCK_UN:
		ifl->type = F_UNLCK;
		break;
	default:
		return -EINVAL;
	}
	ifl->wait = !(op & LOCK_NB);
	return io_filelock_prep_common(req);
}

int io_ofd_lock_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	u64 start, len;
	u32 flags;

	if (unlikely(sqe->ioprio || sqe->buf_index || sqe->splice_fd_in ||
		     sqe->addr3))
		return -EINVAL;

	flags = READ_ONCE(sqe->lock_flags);
	if (flags & ~IORING_OFD_LOCK_NOWAIT)
		return -EINVAL;
	ifl->wait = !(flags & IORING_OFD_LOCK_NOWAIT);

	ifl->type = READ_ONCE(sqe->len);
	switch (ifl->type) {
	case F_RDLCK:
	case F_WRLCK:
	case F_UNLCK:
		break;
	default:
		return -EINVAL;
	}

	start = READ_ONCE(sqe->off);
	len = READ_ONCE(sqe->addr);
	if (start > OFFSET_MAX)
		return -EINVAL;
	ifl->start = start;
	if (!len) {
		ifl->end = OFFSET_MAX;
	} else {
		if (len - 1 > OFFSET_MAX - start)
			return -EOVERFLOW;
		ifl->end = start + len - 1;
	}
	return io_filelock_prep_common(req);
}

static int io_filelock_check(struct io_kiocb *req)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	struct file *file = req->file;

	if (req->opcode == IORING_OP_FLOCK) {
		if (ifl->type != F_UNLCK &&
		    !(file->f_mode & (FMODE_READ | FMODE_WRITE)))
			return -EBADF;
	} else {
		switch (ifl->type) {
		case F_RDLCK:
			if (!(file->f_mode & FMODE_READ))
				return -EBADF;
			break;
		case F_WRLCK:
			if (!(file->f_mode & FMODE_WRITE))
				return -EBADF;
			break;
		}
	}

	return security_file_lock(file, ifl->type);
}

static void io_filelock_init(struct io_kiocb *req)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	struct io_filelock_async *ifa = req->async_data;
	struct file_lock *fl = &ifa->fl;

	if (req->opcode == IORING_OP_FLOCK) {
		flock_make_lock(req->file, fl, ifl->type);
	} else {
		/*
		 * Same semantics as F_OFD_SETLK(W): the lock owner is the
		 * file, not the process.
		 */
		locks_init_lock(fl);
		fl->c.flc_file = req->file;
		fl->c.flc_owner = req->file;
		fl->c.flc_pid = current->tgid;
		fl->c.flc_flags = FL_POSIX | FL_OFDLCK;
		fl->c.flc_type = ifl->type;
		fl->fl_start = ifl->start;
		fl->fl_end = ifl->end;
	}
	if (ifl->wait)
		fl->c.flc_flags |= FL_SLEEP;
}

static bool io_filelock_fs_managed(struct io_kiocb *req)
{
	if (req->opcode == IORING_OP_FLOCK)
		return req->file->f_op->flock != NULL;
	return req->file->f_op->lock != NULL;
}

/*
 * Lock managed by the file system rather than by the generic VFS locking
 * code. Runs in io-wq context and may block, both on the operation itself
 * (eg a server round trip on a network file system) and while waiting for
 * a contended lock. Mirrors what sys_flock() and fcntl_setlk() do. Note
 * that ->lm_notify() must not be set on these requests: implementations
 * may fall back to locks_lock_inode_wait() internally (eg NFS "-o nolock"
 * mounts, or fuse without remote lock support), and that sleeps on the
 * request waitqueue that ->lm_notify() replaces.
 */
static int io_filelock_fs_lock(struct io_kiocb *req)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	unsigned int cmd = ifl->wait ? F_SETLKW : F_SETLK;
	struct io_filelock_async *ifa = req->async_data;
	struct file *file = req->file;
	struct file_lock *fl = &ifa->fl;
	int ret;

	if (req->opcode == IORING_OP_FLOCK)
		return file->f_op->flock(file, cmd, fl);

	for (;;) {
		ret = vfs_lock_file(file, cmd, fl, NULL);
		if (ret != FILE_LOCK_DEFERRED)
			break;
		ret = wait_event_interruptible(fl->c.flc_wait,
				list_empty(&fl->c.flc_blocked_member));
		if (ret)
			break;
	}
	locks_delete_block(fl);
	return ret;
}

/*
 * Runs in task context, with the ring locked. The request is here either
 * because an unblock notification fired and it should retry the lock
 * attempt, or because cancelation unparked it and queued it for
 * completion.
 */
static void io_filelock_tw(struct io_tw_req tw_req, io_tw_token_t tw)
{
	struct io_kiocb *req = tw_req.req;
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	struct io_filelock_async *ifa = req->async_data;
	int ret = -ECANCELED;

	io_tw_lock(req->ctx, tw);

	if (!ifl->cancelled && !tw.cancel) {
		ret = locks_lock_inode(file_inode(req->file), &ifa->fl);
		/*
		 * Lock is contended again, and the request is back on the
		 * blocked list of the conflicting lock. Another notify will
		 * arrive when there's reason to retry.
		 */
		if (ret == FILE_LOCK_DEFERRED)
			return;
	}

	hlist_del_init(&req->hash_node);
	locks_delete_block(&ifa->fl);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	locks_release_private(&ifa->fl);
	io_req_async_data_free(req);
	io_req_task_complete(tw_req, tw);
}

/*
 * Called by fs/locks.c when the lock that blocked us goes away. The
 * request has already been removed from the blocked list at this point,
 * and won't be notified again unless a retry attempt blocks again. Runs
 * under blocked_lock_lock, so it must not sleep.
 */
static void io_filelock_notify(struct file_lock *fl)
{
	struct io_filelock_async *ifa = container_of(fl, struct io_filelock_async, fl);
	struct io_kiocb *req = ifa->req;

	req->io_task_work.func = io_filelock_tw;
	io_req_task_work_add(req);
}

int io_filelock(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_filelock_async *ifa = req->async_data;
	bool fs_managed = io_filelock_fs_managed(req);
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	/* file system managed locks may block, punt to io-wq */
	if (fs_managed && (issue_flags & IO_URING_F_NONBLOCK))
		return -EAGAIN;

	ret = io_filelock_check(req);
	if (ret)
		goto done;

	io_filelock_init(req);

	if (fs_managed) {
		ret = io_filelock_fs_lock(req);
		if (ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
		    ret == -ERESTARTNOHAND) {
			if (atomic_read(&req->work.flags) & IO_WQ_WORK_CANCEL)
				ret = -ECANCELED;
			else
				ret = -EINTR;
		}
		goto done;
	}

	ifa->fl.fl_lmops = &io_filelock_lmops;
	io_ring_submit_lock(ctx, issue_flags);
	ret = locks_lock_inode(file_inode(req->file), &ifa->fl);
	if (ret == FILE_LOCK_DEFERRED) {
		/*
		 * Track the request for cancelation while it's parked on
		 * the blocking lock, then wait for the notify.
		 */
		hlist_add_head(&req->hash_node, &ctx->filelock_list);
		io_ring_submit_unlock(ctx, issue_flags);
		return IOU_ISSUE_SKIP_COMPLETE;
	}
	io_ring_submit_unlock(ctx, issue_flags);
	locks_delete_block(&ifa->fl);
done:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	locks_release_private(&ifa->fl);
	io_req_async_data_free(req);
	return IOU_COMPLETE;
}

static bool __io_filelock_cancel(struct io_kiocb *req)
{
	struct io_filelock *ifl = io_kiocb_to_cmd(req, struct io_filelock);
	struct io_filelock_async *ifa = req->async_data;

	ifl->cancelled = true;
	/*
	 * If the request was still parked on a blocking lock, no notify has
	 * fired, and locks_delete_block() unparking it means none will - we
	 * own completion, queue task_work to finish it. Otherwise a notify
	 * won the race and a retry is in flight; it runs under the ring
	 * lock after we drop it and will observe ->cancelled.
	 */
	if (!locks_delete_block(&ifa->fl)) {
		req->io_task_work.func = io_filelock_tw;
		io_req_task_work_add(req);
	}
	return true;
}

int io_filelock_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		       unsigned int issue_flags)
{
	return io_cancel_remove(ctx, cd, issue_flags, &ctx->filelock_list,
				__io_filelock_cancel);
}

bool io_filelock_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			    bool cancel_all)
{
	return io_cancel_remove_all(ctx, tctx, &ctx->filelock_list, cancel_all,
				    __io_filelock_cancel);
}
