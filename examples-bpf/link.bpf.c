// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2025 Pavel Begunkov */
#include <linux/types.h>
#include <linux/stddef.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_io_uring_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int reqs_to_run;

SEC("struct_ops.s/example_handle_events")
int BPF_PROG(link_handle_events, struct io_ring_ctx *ring, struct io_cqwait_arg *args)
{
	struct io_uring_cqe *cqe;
	int ret;

	cqe = bpf_io_uring_extract_next_cqe(ring);
	if (cqe) {
		int left = --reqs_to_run;

		if (left <= 0)
			return IOU_EVENTS_STOP;
	}

	struct io_uring_sqe sqe = {}; // nop request
	bpf_io_uring_queue_sqe(ring, &sqe, sizeof(sqe));
	ret = bpf_io_uring_submit_sqes(ring, 1);
	if (ret != 1) {
		bpf_printk("bpf submit failed %i\n", ret);
		return IOU_EVENTS_STOP;
	}
	return IOU_EVENTS_WAIT;
}

SEC(".struct_ops")
struct io_uring_ops iou_ops = {
	.handle_events = (void *)link_handle_events,
};
