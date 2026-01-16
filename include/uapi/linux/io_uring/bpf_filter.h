/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Header file for the io_uring BPF filters.
 */
#ifndef LINUX_IO_URING_BPF_FILTER_H
#define LINUX_IO_URING_BPF_FILTER_H

#include <linux/types.h>

struct io_uring_bpf_ctx {
	__u8	opcode;
	__u8	sqe_flags;
	__u16	buf_index;
	__u32	resv;
	__u64	user_data;
	union {
		__u64	args[5];
		struct {
			__u32	family;
			__u32	type;
			__u32	protocol;
		} socket;
	};
};

enum {
	/*
	 * If set, any currently unset opcode will have a deny filter attached
	 */
	IO_URING_BPF_FILTER_DENY_REST	= 1,
};

struct io_uring_bpf_filter {
	__u32	opcode;		/* io_uring opcode to filter */
	__u32	flags;		/* flags associated with filter */
	__u32	filter_len;	/* number of instructions in filter */
	__u32	resv;
	__u64	filter_ptr;	/* pointer to filter */
	__u32	resv2[4];
};

#endif
