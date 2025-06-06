// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Pavel Begunkov */
#include <bpf/bpf_helpers.h>

struct io_uring {
	__u32 head;
	__u32 tail;
};

struct io_rings {
	struct io_uring		sq, cq;
	__u32			cq_overflow;
};

struct io_ring_ctx {
	unsigned int		flags;
	struct io_rings		*rings;
};

struct io_uring_sqe {
	__u8	opcode;		/* type of operation for this sqe */
	__u8	flags;		/* IOSQE_ flags */
	__u16	ioprio;		/* ioprio for the request */
	__s32	fd;		/* file descriptor to do IO on */
	union {
		__u64	off;	/* offset into file */
		__u64	addr2;
		struct {
			__u32	cmd_op;
			__u32	__pad1;
		};
	};
	union {
		__u64	addr;	/* pointer to buffer or iovecs */
		__u64	splice_off_in;
		struct {
			__u32	level;
			__u32	optname;
		};
	};
	__u32	len;		/* buffer size or number of iovecs */
	union {
		__u32		fsync_flags;
		__u16		poll_events;	/* compatibility */
		__u32		poll32_events;	/* word-reversed for BE */
		__u32		sync_range_flags;
		__u32		msg_flags;
		__u32		timeout_flags;
		__u32		accept_flags;
		__u32		cancel_flags;
		__u32		open_flags;
		__u32		statx_flags;
		__u32		fadvise_advice;
		__u32		splice_flags;
		__u32		rename_flags;
		__u32		unlink_flags;
		__u32		hardlink_flags;
		__u32		xattr_flags;
		__u32		msg_ring_flags;
		__u32		uring_cmd_flags;
		__u32		waitid_flags;
		__u32		futex_flags;
		__u32		install_fd_flags;
		__u32		nop_flags;
		__u32		pipe_flags;
	};
	__u64	user_data;	/* data to be passed back at completion time */
	/* pack this to avoid bogus arm OABI complaints */
	union {
		/* index into fixed buffers, if used */
		__u16	buf_index;
		/* for grouped buffer selection */
		__u16	buf_group;
	} __attribute__((packed));
	/* personality to use, if used */
	__u16	personality;
	union {
		__s32	splice_fd_in;
		__u32	file_index;
		__u32	zcrx_ifq_idx;
		__u32	optlen;
		struct {
			__u16	addr_len;
			__u16	__pad3[1];
		};
	};
	union {
		struct {
			__u64	addr3;
			__u64	__pad2[1];
		};
		struct {
			__u64	attr_ptr; /* pointer to attribute information */
			__u64	attr_type_mask; /* bit mask of attributes */
		};
		__u64	optval;
		/*
		 * If the ring is initialized with IORING_SETUP_SQE128, then
		 * this field is used for 80 bytes of arbitrary command data
		 */
		__u8	cmd[0];
	};
};

struct io_uring_cqe {
	__u64	user_data;
	__s32	res;
	__u32	flags;
};

struct io_cqwait_arg {
	__u32			target_cq_tail;
	__s64			timeout;
};

enum {
	IOU_EVENTS_WAIT,
	IOU_EVENTS_STOP,
};

struct io_uring_ops {
	__u32 ring_fd;

	int (*handle_events)(struct io_ring_ctx *ctx, struct io_cqwait_arg *arg);
};
