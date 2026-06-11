// SPDX-License-Identifier: GPL-2.0

#include <linux/filelock.h>

#include "cancel.h"

struct io_filelock_async {
	struct io_kiocb		*req;
	struct file_lock	fl;
};

int io_flock_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_ofd_lock_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_filelock(struct io_kiocb *req, unsigned int issue_flags);

#if defined(CONFIG_FILE_LOCKING)
int io_filelock_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		       unsigned int issue_flags);
bool io_filelock_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			    bool cancel_all);
#else
static inline int io_filelock_cancel(struct io_ring_ctx *ctx,
				     struct io_cancel_data *cd,
				     unsigned int issue_flags)
{
	return -ENOENT;
}
static inline bool io_filelock_remove_all(struct io_ring_ctx *ctx,
					  struct io_uring_task *tctx,
					  bool cancel_all)
{
	return false;
}
#endif
