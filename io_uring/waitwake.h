// SPDX-License-Identifier: GPL-2.0

int io_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_wait(struct io_kiocb *req, unsigned int issue_flags);
int io_wake_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_wake(struct io_kiocb *req, unsigned int issue_flags);

int io_waitwake_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		       unsigned int issue_flags);
int io_waitwake_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			   bool cancel_all);
