/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"
#include "test.h"
#include "helpers.h"

#define IORING_REGISTER_QUERY		35

struct io_uring_query_hdr {
	__u64 next_entry;
	__u64 query_data;
	__u32 query_op;
	__u32 size;
	__s32 result;
	__u32 __resv[3];
};

enum {
	IO_URING_QUERY_OPCODES			= 0,

	__IO_URING_QUERY_MAX,
};

/* Doesn't require a ring */
struct io_uring_query_opcode {
	/* The number of supported IORING_OP_* opcodes */
	__u32	nr_request_opcodes;
	/* The number of supported IORING_[UN]REGISTER_* opcodes */
	__u32	nr_register_opcodes;
	/* Bitmask of all supported IORING_FEAT_* flags */
	__u64	feature_flags;
	/* Bitmask of all supported IORING_SETUP_* flags */
	__u64	ring_setup_flags;
	/* Bitmask of all supported IORING_ENTER_** flags */
	__u64	enter_flags;
	/* Bitmask of all supported IOSQE_* flags */
	__u64	sqe_flags;
};

struct io_uring_query_opcode_short {
	__u32	nr_request_opcodes;
	__u32	nr_register_opcodes;
};

struct io_uring_query_opcode_large {
	__u32	nr_request_opcodes;
	__u32	nr_register_opcodes;
	__u64	feature_flags;
	__u64	ring_setup_flags;
	__u64	enter_flags;
	__u64	sqe_flags;
	__u64	placeholder[8];
};

static struct io_uring_query_opcode sys_ops;

static int do_query(struct io_uring *ring, struct io_uring_query_hdr *op)
{
	int fd = ring ? ring->ring_fd : -1;

	return io_uring_register(fd, IORING_REGISTER_QUERY, op, 0);
}

static int test_basic_query(void)
{
	struct io_uring_query_opcode op;
	struct io_uring_query_hdr hdr = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op),
		.size = sizeof(op),
	};
	int ret;

	ret = do_query(NULL, &hdr);
	if (ret == -EINVAL)
		return T_EXIT_SKIP;

	if (ret != 0) {
		fprintf(stderr, "query failed %d\n", ret);
		return T_EXIT_FAIL;
	}

	if (hdr.size != sizeof(op)) {
		fprintf(stderr, "unexpected size %i vs %i\n",
				(int)hdr.size, (int)sizeof(op));
		return T_EXIT_FAIL;
	}

	if (hdr.result) {
		fprintf(stderr, "unexpected result %i\n", hdr.result);
		return T_EXIT_FAIL;
	}

	if (op.nr_register_opcodes <= IORING_REGISTER_QUERY) {
		fprintf(stderr, "too few opcodes (%i)\n", op.nr_register_opcodes);
		return T_EXIT_FAIL;
	}

	memcpy(&sys_ops, &op, sizeof(sys_ops));
	return T_EXIT_PASS;
}

static int test_invalid(void)
{
	int ret;
	struct io_uring_query_opcode op;
	struct io_uring_query_hdr invalid_hdr = {
		.query_op = -1U,
		.query_data = uring_ptr_to_u64(&op),
		.size = sizeof(struct io_uring_query_opcode),
	};

	ret = do_query(NULL, &invalid_hdr);
	if (ret || invalid_hdr.result != -EOPNOTSUPP) {
		fprintf(stderr, "failed invalid opcode %i (%i)\n",
			ret, invalid_hdr.result);
		return T_EXIT_FAIL;
	}

	struct io_uring_query_hdr invalid_next_hdr = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op),
		.size = sizeof(struct io_uring_query_opcode),
		.next_entry = 0xdeadbeefUL,
	};

	ret = do_query(NULL, &invalid_next_hdr);
	if (ret != -EFAULT) {
		fprintf(stderr, "invalid next %i\n", ret);
		return T_EXIT_FAIL;
	}

	struct io_uring_query_hdr invalid_data_hdr = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = 0xdeadbeefUL,
		.size = sizeof(struct io_uring_query_opcode),
	};

	ret = do_query(NULL, &invalid_data_hdr);
	if (ret != -EFAULT) {
		fprintf(stderr, "invalid next %i\n", ret);
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

static int test_chain(void)
{
	int ret;
	struct io_uring_query_opcode op1, op2, op3;
	struct io_uring_query_hdr hdr3 = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op3),
		.size = sizeof(struct io_uring_query_opcode),
	};
	struct io_uring_query_hdr hdr2 = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op2),
		.size = sizeof(struct io_uring_query_opcode),
		.next_entry = uring_ptr_to_u64(&hdr3),
	};
	struct io_uring_query_hdr hdr1 = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op1),
		.size = sizeof(struct io_uring_query_opcode),
		.next_entry = uring_ptr_to_u64(&hdr2),
	};

	ret = do_query(NULL, &hdr1);
	if (ret) {
		fprintf(stderr, "chain failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	if (hdr1.result || hdr2.result || hdr3.result) {
		fprintf(stderr, "chain invalid result entries %i %i %i\n",
			hdr1.result, hdr2.result, hdr3.result);
		return T_EXIT_FAIL;
	}

	if (op1.nr_register_opcodes != sys_ops.nr_register_opcodes ||
	    op2.nr_register_opcodes != sys_ops.nr_register_opcodes ||
	    op3.nr_register_opcodes != sys_ops.nr_register_opcodes) {
		fprintf(stderr, "chain invalid register opcodes\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

static int test_compatibile_shorter(void)
{
	int ret;
	struct io_uring_query_opcode_short op;
	struct io_uring_query_hdr hdr = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op),
		.size = sizeof(op),
	};

	ret = do_query(NULL, &hdr);
	if (ret || hdr.result) {
		fprintf(stderr, "failed invalid short result %i (%i)\n",
			ret, hdr.result);
		return T_EXIT_FAIL;
	}

	if (hdr.size != sizeof(struct io_uring_query_opcode_short)) {
		fprintf(stderr, "unexpected short query size %i %i\n",
			(int)hdr.size,
			(int)sizeof(struct io_uring_query_opcode_short));
		return T_EXIT_FAIL;
	}

	if (sys_ops.nr_register_opcodes != op.nr_register_opcodes ||
	    sys_ops.nr_request_opcodes != op.nr_request_opcodes) {
		fprintf(stderr, "invalid short data\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

static int test_compatibile_larger(void)
{
	int ret;
	struct io_uring_query_opcode_large op;
	struct io_uring_query_hdr hdr = {
		.query_op = IO_URING_QUERY_OPCODES,
		.query_data = uring_ptr_to_u64(&op),
		.size = sizeof(op),
	};

	ret = do_query(NULL, &hdr);
	if (ret || hdr.result) {
		fprintf(stderr, "failed invalid large result %i (%i)\n",
			ret, hdr.result);
		return T_EXIT_FAIL;
	}

	if (hdr.size < sizeof(struct io_uring_query_opcode)) {
		fprintf(stderr, "unexpected large query size %i %i\n",
			(int)hdr.size,
			(int)sizeof(struct io_uring_query_opcode));
		return T_EXIT_FAIL;
	}

	if (sys_ops.nr_register_opcodes != op.nr_register_opcodes ||
	    sys_ops.nr_request_opcodes != op.nr_request_opcodes ||
	    sys_ops.ring_setup_flags != op.ring_setup_flags ||
	    sys_ops.feature_flags != op.feature_flags) {
		fprintf(stderr, "invalid large data\n");
		return T_EXIT_FAIL;
	}

	return T_EXIT_PASS;
}

int main(int argc, char *argv[])
{
	struct io_uring ring;
	int ret;

	if (argc > 1)
		return 0;

	ret = test_basic_query();
	if (ret != T_EXIT_PASS) {
		if (ret == T_EXIT_SKIP)
			fprintf(stderr, "ring query not supported, skip\n");
		else
			fprintf(stderr, "test_basic_query failed\n");

		return T_EXIT_SKIP;
	}

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "init failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_invalid();
	if (ret)
		return T_EXIT_FAIL;

	ret = test_chain();
	if (ret) {
		fprintf(stderr, "test_chain failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_compatibile_shorter();
	if (ret) {
		fprintf(stderr, "test_compatibile_shorter failed\n");
		return T_EXIT_FAIL;
	}

	ret = test_compatibile_larger();
	if (ret) {
		fprintf(stderr, "test_compatibile_larger failed\n");
		return T_EXIT_FAIL;
	}

	return 0;
}
