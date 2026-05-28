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

/*
 * Lockless snapshot of TCP socket state, populated by the
 * bpf_io_uring_sock_state() kfunc.
 *
 * inq:        bytes available to read (rcv_nxt - copied_seq).
 * rcvbuf:     current socket receive-buffer cap.
 * rmem_alloc: bytes accounted to sk->sk_rmem_alloc (truesize sum;
 *             includes per-skb overhead, so always >= inq).
 * mss:        receiver's tracked peer MSS (icsk_ack.rcv_mss). Used
 *             to mirror TCP's zero-window threshold of
 *             max(rcvbuf/16, mss) - the gate must fire when free
 *             space drops below that or the connection will deadlock
 *             with a partial frame buffered.
 */
struct io_uring_sock_state {
	__u32		inq;
	__u32		rcvbuf;
	__u32		rmem_alloc;
	__u32		mss;
};

#endif
