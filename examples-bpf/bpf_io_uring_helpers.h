// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Pavel Begunkov */
#include "bpf_io_uring_types.h"

extern struct io_uring_cqe *bpf_io_uring_get_cqe(struct io_ring_ctx *ring, __u32 idx) __weak __ksym;
extern struct io_uring_cqe *bpf_io_uring_extract_next_cqe(struct io_ring_ctx *ring) __weak __ksym;
extern int bpf_io_uring_post_cqe(struct io_ring_ctx *ring, __u64 data, __u32 res, __u32 cflags) __weak __ksym;
extern int bpf_io_uring_queue_sqe(struct io_ring_ctx *ring, void *bpf_sqe, int mem__sz) __weak __ksym;
extern int bpf_io_uring_submit_sqes(struct io_ring_ctx *ring, unsigned int nr) __weak __ksym;

static inline void io_bpf_wait_nr(struct io_ring_ctx *ring,
				  struct io_cqwait_arg *args, int nr)
{
	args->target_cq_tail = ring->rings->cq.head + nr;
}
