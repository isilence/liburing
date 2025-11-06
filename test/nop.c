/* SPDX-License-Identifier: MIT */
/*
 * Description: run various nop tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"
#include "test.h"
#include "helpers.h"

static int seq;

static int test_nop_inject(struct io_uring *ring, unsigned req_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}

	io_uring_prep_nop(sqe);
	sqe->user_data = ++seq;
	sqe->nop_flags = IORING_NOP_INJECT_RESULT;
	sqe->flags |= req_flags;
	sqe->len = -EFAULT;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	if (cqe->res != -EINVAL && cqe->res != -EFAULT) {
		fprintf(stderr, "expected injected result, got %d\n", cqe->res);
		goto err;
	}
	io_uring_cqe_seen(ring, cqe);
	return 0;
err:
	return 1;
}

static int test_single_nop(struct io_uring *ring, unsigned req_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;
	bool cqe32 = (ring->flags & IORING_SETUP_CQE32);

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}

	io_uring_prep_nop(sqe);
	sqe->user_data = ++seq;
	sqe->flags |= req_flags;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	if (!cqe->user_data) {
		fprintf(stderr, "Unexpected 0 user_data: %ld\n", (long) cqe->user_data);
		goto err;
	}
	if (cqe32) {
		if (cqe->big_cqe[0] != 0) {
			fprintf(stderr, "Unexpected extra1\n");
			goto err;

		}
		if (cqe->big_cqe[1] != 0) {
			fprintf(stderr, "Unexpected extra2\n");
			goto err;
		}
	}
	io_uring_cqe_seen(ring, cqe);
	return 0;
err:
	return 1;
}

static int test_barrier_nop(struct io_uring *ring, unsigned req_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret, i;
	bool cqe32 = (ring->flags & IORING_SETUP_CQE32);

	for (i = 0; i < 8; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed\n");
			goto err;
		}

		io_uring_prep_nop(sqe);
		if (i == 4)
			sqe->flags = IOSQE_IO_DRAIN;
		sqe->user_data = ++seq;
		sqe->flags |= req_flags;
	}

	ret = io_uring_submit(ring);
	if (ret < 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	} else if (ret < 8) {
		fprintf(stderr, "Submitted only %d\n", ret);
		goto err;
	}

	for (i = 0; i < 8; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		if (!cqe->user_data) {
			fprintf(stderr, "Unexpected 0 user_data: %ld\n", (long) cqe->user_data);
			goto err;
		}
		if (cqe32) {
			if (cqe->big_cqe[0] != 0) {
				fprintf(stderr, "Unexpected extra1\n");
				goto err;
			}
			if (cqe->big_cqe[1] != 0) {
				fprintf(stderr, "Unexpected extra2\n");
				goto err;
			}
		}
		io_uring_cqe_seen(ring, cqe);
	}

	return 0;
err:
	return 1;
}

static int test_ring(unsigned flags)
{
	struct io_uring ring;
	struct io_uring_params p = { };
	int ret, i;

	unsigned sq_entries = 8;
	unsigned cq_entries = 32;

	size_t hdr_offset = 512;
	size_t cq_size = cq_entries * sizeof(struct io_uring_cqe);
	if (flags & IORING_SETUP_CQE32)
		cq_size *= 2;
	size_t sq_offset = hdr_offset + cq_size;
	size_t sq_size = sq_entries * sizeof(struct io_uring_sqe);

	size_t size = sq_offset + sq_size;
	void *buffer = t_aligned_alloc(4096, size);
	if (!buffer) {
		fprintf(stderr, "buffer alloc failed\n");
		exit(1);
	}

	struct io_uring_region_desc rd = {};
	struct io_uring_mem_region_reg mr = {};
	rd.user_addr = uring_ptr_to_u64(buffer);
	rd.size = size;
	rd.flags = IORING_MEM_REGION_TYPE_USER;
	mr.region_uptr = uring_ptr_to_u64(&rd);
	mr.flags = IORING_MEM_REGION_REG_WAIT_ARG;

	struct io_uring_params_ext e = {};
	e.mem_region = uring_ptr_to_u64(&mr);
	e.placement.flags = IORING_PLACEMENT_SCQ_HDR |
				IORING_PLACEMENT_SQ |
				IORING_PLACEMENT_CQ;
	e.placement.scq_hdr_off = 0;
	e.placement.cq_off = hdr_offset;
	e.placement.sq_off = sq_offset;

	p.flags = flags | IORING_SETUP_CQSIZE;
	p.cq_entries = cq_entries;
	p.params_ext = uring_ptr_to_u64(&e);

	ret = io_uring_queue_init_params(8, &ring, &p);
	if (ret) {
		if (ret == -EINVAL)
			return 0;
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	for (i = 0; i < 1000; i++) {
		unsigned req_flags = (i & 1) ? IOSQE_ASYNC : 0;

		ret = test_single_nop(&ring, req_flags);
		if (ret) {
			fprintf(stderr, "test_single_nop failed\n");
			goto err;
		}

		ret = test_barrier_nop(&ring, req_flags);
		if (ret) {
			fprintf(stderr, "test_barrier_nop failed\n");
			goto err;
		}
		ret = test_nop_inject(&ring, req_flags);
		if (ret) {
			fprintf(stderr, "test_nop_inject failed\n");
			goto err;
		}
	}
err:
	io_uring_queue_exit(&ring);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	FOR_ALL_TEST_CONFIGS {
		ret = test_ring(IORING_GET_TEST_CONFIG_FLAGS());
		if (ret) {
			fprintf(stderr, "Normal ring test failed: %s\n",
					IORING_GET_TEST_CONFIG_DESCRIPTION());
			return ret;
		}
	}

	return 0;
}
