/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/*
 * Header file for the io_uring eBPF ops
 */
#ifndef LINUX_IO_URING_BPF_OPS_H
#define LINUX_IO_URING_BPF_OPS_H

#include <linux/types.h>

/*
 * Public BPF program data for poll_gate callback
 */
struct io_uring_poll_event {
	__u64		user_data;
	/* current peek output */
	__u32		gate_state;
	/* current poll mask */
	__u32		mask;
	/* opcode of request */
	__u8		opcode;
	__u8		resv[7];
};

#endif
