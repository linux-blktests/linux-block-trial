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
	refcount_t		refs;
	struct bpf_prog		*prog;
	struct io_bpf_filter	*next;
	bool			is_cbpf;
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
int __io_uring_run_bpf_filters(struct io_bpf_filter __rcu **filters,
			       struct io_kiocb *req)
{
	struct io_bpf_filter *filter;
	struct io_uring_bpf_ctx bpf_ctx;
	int ret;

	/* Fast check for existence of filters outside of RCU */
	if (!rcu_access_pointer(filters[req->opcode]))
		return 0;

	/*
	 * req->opcode has already been validated to be within the range
	 * of what we expect, io_init_req() does this.
	 */
	rcu_read_lock();
	filter = rcu_dereference(filters[req->opcode]);
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

			/* Someone still holds a ref, stop iterating. */
			if (!refcount_dec_and_test(&f->refs))
				break;

			if (f->is_cbpf)
				bpf_prog_destroy(f->prog);
			else if (f->prog)
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

/*
 * Validate classic BPF filter instructions. Only allow a safe subset of
 * operations - no packet data access, just context field loads and basic
 * ALU/jump operations.
 */
static int io_uring_check_cbpf_filter(struct sock_filter *filter,
				      unsigned int flen)
{
	int pc;

	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_LD | BPF_W | BPF_ABS:
			ftest->code = BPF_LDX | BPF_W | BPF_ABS;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct io_uring_bpf_ctx) || k & 3)
				return -EINVAL;
			continue;
		case BPF_LD | BPF_W | BPF_LEN:
			ftest->code = BPF_LD | BPF_IMM;
			ftest->k = sizeof(struct io_uring_bpf_ctx);
			continue;
		case BPF_LDX | BPF_W | BPF_LEN:
			ftest->code = BPF_LDX | BPF_IMM;
			ftest->k = sizeof(struct io_uring_bpf_ctx);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_RET | BPF_K:
		case BPF_RET | BPF_A:
		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_NEG:
		case BPF_LD | BPF_IMM:
		case BPF_LDX | BPF_IMM:
		case BPF_MISC | BPF_TAX:
		case BPF_MISC | BPF_TXA:
		case BPF_LD | BPF_MEM:
		case BPF_LDX | BPF_MEM:
		case BPF_ST:
		case BPF_STX:
		case BPF_JMP | BPF_JA:
		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

void io_bpf_filter_clone(struct io_restriction *dst, struct io_restriction *src)
{
	if (!src->bpf_filters)
		return;

	rcu_read_lock();
	/*
	 * If the src filter is going away, just ignore it.
	 */
	if (refcount_inc_not_zero(&src->bpf_filters->refs)) {
		dst->bpf_filters = src->bpf_filters;
		dst->bpf_filters_cow = true;
	}
	rcu_read_unlock();
}

/*
 * Allocate a new struct io_bpf_filters. Used when a filter is cloned and
 * modifications need to be made.
 */
static struct io_bpf_filters *io_bpf_filter_cow(struct io_restriction *src)
{
	struct io_bpf_filters *filters;
	struct io_bpf_filter *srcf;
	int i;

	filters = io_new_bpf_filters();
	if (IS_ERR(filters))
		return filters;

	/*
	 * Iterate filters from src and assign in destination. Grabbing
	 * a reference is enough, we don't need to duplicate the memory.
	 * This is safe because filters are only ever appended to the
	 * front of the list, hence the only memory ever touched inside
	 * a filter is the refcount.
	 */
	rcu_read_lock();
	for (i = 0; i < IORING_OP_LAST; i++) {
		srcf = rcu_dereference(src->bpf_filters->filters[i]);
		if (!srcf) {
			continue;
		} else if (srcf == &dummy_filter) {
			rcu_assign_pointer(filters->filters[i], &dummy_filter);
			continue;
		}

		/*
		 * Getting a ref on the first node is enough, putting the
		 * filter and iterating nodes to free will stop on the first
		 * one that doesn't hit zero when dropping.
		 */
		if (!refcount_inc_not_zero(&srcf->refs))
			goto err;
		rcu_assign_pointer(filters->filters[i], srcf);
	}
	rcu_read_unlock();
	return filters;
err:
	rcu_read_unlock();
	__io_put_bpf_filters(filters);
	return ERR_PTR(-EBUSY);
}

#define IO_URING_BPF_FILTER_FLAGS \
	(IO_URING_BPF_FILTER_DENY_REST | IO_URING_BPF_FILTER_CBPF)

int io_register_bpf_filter(struct io_restriction *res,
			   struct io_uring_bpf __user *arg)
{
	struct io_bpf_filter *filter, *old_filter;
	struct io_bpf_filters *filters;
	struct io_uring_bpf reg;
	struct bpf_prog *prog;
	bool is_cbpf;
	int ret;

	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.cmd_type != IO_URING_BPF_CMD_FILTER)
		return -EINVAL;
	if (reg.cmd_flags || reg.resv)
		return -EINVAL;

	if (reg.filter.opcode >= IORING_OP_LAST)
		return -EINVAL;
	if (reg.filter.flags & ~IO_URING_BPF_FILTER_FLAGS)
		return -EINVAL;
	if (!mem_is_zero(reg.filter.reserved, sizeof(reg.filter.reserved)))
		return -EINVAL;

	is_cbpf = reg.filter.flags & IO_URING_BPF_FILTER_CBPF;

	/* Validate type-specific fields */
	if (is_cbpf) {
		if (!reg.filter.filter_len ||
		    reg.filter.filter_len > BPF_MAXINSNS)
			return -EINVAL;
	} else {
		if (reg.filter.prog_fd < 0)
			return -EBADF;
	}

	/* Create the BPF program */
	if (is_cbpf) {
		struct sock_fprog fprog = {
			.len = reg.filter.filter_len,
			.filter = u64_to_user_ptr(reg.filter.filter_ptr),
		};

		ret = bpf_prog_create_from_user(&prog, &fprog,
						io_uring_check_cbpf_filter,
						false);
		if (ret)
			return ret;
	} else {
		prog = bpf_prog_get_type(reg.filter.prog_fd,
					 BPF_PROG_TYPE_IO_URING);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}

	/*
	 * No existing filters, allocate set.
	 */
	filters = res->bpf_filters;
	if (!filters) {
		filters = io_new_bpf_filters();
		if (IS_ERR(filters)) {
			ret = PTR_ERR(filters);
			goto err_prog;
		}
	} else if (res->bpf_filters_cow) {
		filters = io_bpf_filter_cow(res);
		if (IS_ERR(filters)) {
			ret = PTR_ERR(filters);
			goto err_prog;
		}
		__io_put_bpf_filters(res->bpf_filters);
		res->bpf_filters_cow = false;
	}

	filter = kzalloc(sizeof(*filter), GFP_KERNEL_ACCOUNT);
	if (!filter) {
		ret = -ENOMEM;
		goto err;
	}
	refcount_set(&filter->refs, 1);
	filter->prog = prog;
	filter->is_cbpf = is_cbpf;
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
err_prog:
	if (is_cbpf)
		bpf_prog_destroy(prog);
	else
		bpf_prog_put(prog);
	return ret;
}
