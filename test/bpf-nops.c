/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#include "liburing.h"

#include "nops_loop.skel.h"

static struct io_uring_params params;
static struct nops_loop_bpf *skel;
static struct bpf_link *nops_loop_bpf_link;

#define CQ_ENTRIES 8
#define SQ_ENTRIES 8
#define NR_ITERS 1000

static void setup_ring(struct io_uring *ring)
{
	int ret;

	memset(&params, 0, sizeof(params));
	params.cq_entries = CQ_ENTRIES;
	params.flags = IORING_SETUP_SINGLE_ISSUER |
			IORING_SETUP_DEFER_TASKRUN |
			IORING_SETUP_NO_SQARRAY |
			IORING_SETUP_CQSIZE;

	ret = io_uring_queue_init_params(SQ_ENTRIES, ring, &params);
	if (ret) {
		fprintf(stderr, "ring init failed\n");
		exit(1);
	}
}

static void setup_bpf_ops(struct io_uring *ring)
{
	int ret;

	skel = nops_loop_bpf__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		exit(1);
	}

	skel->struct_ops.nops_ops->ring_fd = ring->ring_fd;
	skel->bss->reqs_to_run = NR_ITERS;
	skel->rodata->sq_hdr_offset = params.sq_off.head;
	skel->rodata->cq_hdr_offset = params.cq_off.head;
	skel->rodata->cqes_offset = params.cq_off.cqes;

	ret = nops_loop_bpf__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	nops_loop_bpf_link = bpf_map__attach_struct_ops(skel->maps.nops_ops);
	if (!nops_loop_bpf_link) {
		fprintf(stderr, "failed to attach ops\n");
		exit(1);
	}
}

static void run_ring(struct io_uring *ring)
{
	__u32 key;
	__s64 res;
	int ret;

	ret = io_uring_enter(ring->ring_fd, 0, 0, IORING_ENTER_GETEVENTS, NULL);
	if (ret) {
		fprintf(stderr, "run failed\n");
		exit(1);
	}

	key = 0;
	ret = bpf_map__lookup_elem(skel->maps.res_map,
				&key, sizeof(key),
				&res, sizeof(res), 0);
	if (ret)
		fprintf(stderr, "can't read map: %i\n", ret);
	if (res != 1)
		fprintf(stderr, "run failed: %i\n", (int)res);
}

int main()
{
	struct io_uring ring;

	setup_ring(&ring);
	setup_bpf_ops(&ring);

	run_ring(&ring);

	bpf_link__destroy(nops_loop_bpf_link);
	nops_loop_bpf__destroy(skel);
	io_uring_queue_exit(&ring);
	return 0;
}
