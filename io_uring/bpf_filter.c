// SPDX-License-Identifier: GPL-2.0
/*
 * BPF filter support for io_uring. Supports SQE opcodes for now.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/io_uring.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "bpf_filter.h"
#include "net.h"

struct io_bpf_filter {
	struct bpf_prog		*prog;
	struct io_bpf_filter	*next;
};

/* Deny if this is set as the filter */
static const struct io_bpf_filter dummy_filter;

static bool io_uring_filter_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct io_uring_bpf_ctx))
		return false;
	if (off % size != 0)
		return false;

	return true;
}

/* Convert context field access if needed */
static u32 io_uring_filter_convert_ctx_access(enum bpf_access_type type,
					      const struct bpf_insn *si,
					      struct bpf_insn *insn_buf,
					      struct bpf_prog *prog,
					      u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;

	/* Direct access is fine - context is read-only and passed directly */
	switch (si->off) {
	case offsetof(struct io_uring_bpf_ctx, opcode):
	case offsetof(struct io_uring_bpf_ctx, sqe_flags):
	case offsetof(struct io_uring_bpf_ctx, user_data):
		*insn++ = BPF_LDX_MEM(BPF_SIZE(si->code), si->dst_reg,
				      si->src_reg, si->off);
		break;
	default:
		/* Union fields - also direct access */
		*insn++ = BPF_LDX_MEM(BPF_SIZE(si->code), si->dst_reg,
				      si->src_reg, si->off);
		break;
	}

	return insn - insn_buf;
}

const struct bpf_prog_ops io_uring_filter_prog_ops = { };

const struct bpf_verifier_ops io_uring_filter_verifier_ops = {
	.get_func_proto		= bpf_base_func_proto,
	.is_valid_access	= io_uring_filter_is_valid_access,
	.convert_ctx_access	= io_uring_filter_convert_ctx_access,
};

static void io_uring_populate_bpf_ctx(struct io_uring_bpf_ctx *bctx,
				      struct io_kiocb *req)
{
	memset(bctx, 0, sizeof(*bctx));
	bctx->opcode = req->opcode;
	bctx->sqe_flags = (__force int) req->flags & SQE_VALID_FLAGS;
	bctx->user_data = req->cqe.user_data;

	/*
	 * Opcodes can provide a handler fo populating more data into bctx,
	 * for filters to use.
	 */
	switch (req->opcode) {
	case IORING_OP_SOCKET:
		io_socket_bpf_populate(bctx, req);
		break;
	}
}

/*
 * Run registered filters for a given opcode. For filters, a return of 0 denies
 * execution of the request, a return of 1 allows it. If any filter for an
 * opcode returns 0, filter processing is stopped, and the request is denied.
 * This also stops the processing of filters.
 *
 * __io_uring_run_bpf_filters() returns 0 on success, allow running the
 * request, and -EACCES when a request is denied.
 */
int __io_uring_run_bpf_filters(struct io_restriction *res, struct io_kiocb *req)
{
	struct io_bpf_filter *filter;
	struct io_uring_bpf_ctx bpf_ctx;
	int ret;

	/* Fast check for existence of filters outside of RCU */
	if (!rcu_access_pointer(res->bpf_filters->filters[req->opcode]))
		return 0;

	/*
	 * req->opcode has already been validated to be within the range
	 * of what we expect, io_init_req() does this.
	 */
	rcu_read_lock();
	filter = rcu_dereference(res->bpf_filters->filters[req->opcode]);
	if (!filter) {
		ret = 1;
		goto out;
	} else if (filter == &dummy_filter) {
		ret = 0;
		goto out;
	}

	io_uring_populate_bpf_ctx(&bpf_ctx, req);

	/*
	 * Iterate registered filters. The opcode is allowed IFF all filters
	 * return 1. If any filter returns denied, opcode will be denied.
	 */
	do {
		if (filter == &dummy_filter)
			ret = 0;
		else
			ret = bpf_prog_run(filter->prog, &bpf_ctx);
		if (!ret)
			break;
		filter = filter->next;
	} while (filter);
out:
	rcu_read_unlock();
	return ret ? 0 : -EACCES;
}

static void io_free_bpf_filters(struct rcu_head *head)
{
	struct io_bpf_filter __rcu **filter;
	struct io_bpf_filters *filters;
	int i;

	filters = container_of(head, struct io_bpf_filters, rcu_head);
	spin_lock(&filters->lock);
	filter = filters->filters;
	if (!filter) {
		spin_unlock(&filters->lock);
		return;
	}
	spin_unlock(&filters->lock);

	for (i = 0; i < IORING_OP_LAST; i++) {
		struct io_bpf_filter *f;

		rcu_read_lock();
		f = rcu_dereference(filter[i]);
		while (f) {
			struct io_bpf_filter *next = f->next;

			/*
			 * Even if stacked, dummy filter will always be last
			 * as it can only get installed into an empty spot.
			 */
			if (f == &dummy_filter)
				break;
			if (f->prog)
				bpf_prog_put(f->prog);
			kfree(f);
			f = next;
		}
		rcu_read_unlock();
	}
	kfree(filters->filters);
	kfree(filters);
}

static void __io_put_bpf_filters(struct io_bpf_filters *filters)
{
	if (refcount_dec_and_test(&filters->refs))
		call_rcu(&filters->rcu_head, io_free_bpf_filters);
}

void io_put_bpf_filters(struct io_restriction *res)
{
	if (res->bpf_filters)
		__io_put_bpf_filters(res->bpf_filters);
}

static struct io_bpf_filters *io_new_bpf_filters(void)
{
	struct io_bpf_filters *filters;

	filters = kzalloc(sizeof(*filters), GFP_KERNEL_ACCOUNT);
	if (!filters)
		return ERR_PTR(-ENOMEM);

	filters->filters = kcalloc(IORING_OP_LAST,
				   sizeof(struct io_bpf_filter *),
				   GFP_KERNEL_ACCOUNT);
	if (!filters->filters) {
		kfree(filters);
		return ERR_PTR(-ENOMEM);
	}

	refcount_set(&filters->refs, 1);
	spin_lock_init(&filters->lock);
	return filters;
}

int io_register_bpf_filter(struct io_restriction *res,
			   struct io_uring_bpf __user *arg)
{
	struct io_bpf_filter *filter, *old_filter;
	struct io_bpf_filters *filters;
	struct io_uring_bpf reg;
	struct bpf_prog *prog;
	int ret;

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.cmd_type != IO_URING_BPF_CMD_FILTER)
		return -EINVAL;
	if (reg.cmd_flags || reg.resv)
		return -EINVAL;

	if (reg.filter.opcode >= IORING_OP_LAST)
		return -EINVAL;
	if ((reg.filter.flags & ~IO_URING_BPF_FILTER_DENY_REST) ||
	    !mem_is_zero(reg.filter.reserved, sizeof(reg.filter.reserved)))
		return -EINVAL;
	if (reg.filter.prog_fd < 0)
		return -EBADF;

	/*
	 * No existing filters, allocate set.
	 */
	filters = res->bpf_filters;
	if (!filters) {
		filters = io_new_bpf_filters();
		if (IS_ERR(filters))
			return PTR_ERR(filters);
	}

	prog = bpf_prog_get_type(reg.filter.prog_fd, BPF_PROG_TYPE_IO_URING);
	if (IS_ERR(prog)) {
		ret = PTR_ERR(prog);
		goto err;
	}

	filter = kzalloc(sizeof(*filter), GFP_KERNEL_ACCOUNT);
	if (!filter) {
		ret = -ENOMEM;
		goto err;
	}
	filter->prog = prog;
	res->bpf_filters = filters;

	/*
	 * Insert filter - if the current opcode already has a filter
	 * attached, add to the set.
	 */
	rcu_read_lock();
	spin_lock_bh(&filters->lock);
	old_filter = rcu_dereference(filters->filters[reg.filter.opcode]);
	if (old_filter)
		filter->next = old_filter;
	rcu_assign_pointer(filters->filters[reg.filter.opcode], filter);

	/*
	 * If IO_URING_BPF_FILTER_DENY_REST is set, fill any unregistered
	 * opcode with the dummy filter. That will cause them to be denied.
	 */
	if (reg.filter.flags & IO_URING_BPF_FILTER_DENY_REST) {
		for (int i = 0; i < IORING_OP_LAST; i++) {
			if (i == reg.filter.opcode)
				continue;
			old_filter = rcu_dereference(filters->filters[i]);
			if (old_filter)
				continue;
			rcu_assign_pointer(filters->filters[i], &dummy_filter);
		}
	}

	spin_unlock_bh(&filters->lock);
	rcu_read_unlock();
	return 0;
err:
	if (filters != res->bpf_filters)
		__io_put_bpf_filters(filters);
	if (!IS_ERR(prog))
		bpf_prog_put(prog);
	return ret;
}
