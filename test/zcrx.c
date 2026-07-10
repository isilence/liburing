/* SPDX-License-Identifier: MIT */
/*
 * Zero copy receive tests
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <linux/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <net/if.h>

#include "liburing.h"
#include "helpers.h"

#define DEV_ENV_VAR	"LIBURING_TEST_NETIF"
#define RXQ_ENV_VAR	"LIBURING_TEST_NETRXQ"

#define RING_FLAGS	(IORING_SETUP_DEFER_TASKRUN | \
			 IORING_SETUP_CQE32 | \
			 IORING_SETUP_SINGLE_ISSUER | \
			 IORING_SETUP_SUBMIT_ALL)

#define RQ_ENTRIES		128
#define RQ_ENTRIES_SMALL	16
#define AREA_SZ_SMALL		(4096 * 2)
#define AREA_SZ			(4096 * 132)
#define HUGEPAGE_AREA_SZ	(16 << 20)

#define T_ALIGN_UP(v, align) (((v) + (align) - 1) & ~((align) - 1))

struct zcrx_reg {
	struct io_uring_zcrx_area_reg area;
	struct io_uring_region_desc rq_region;
	struct io_uring_zcrx_ifq_reg zcrx;
};

struct t_executor {
	struct io_uring_zcrx_rq rq;
	struct io_uring ring;
	struct zcrx_reg reg;
	int fds[2];
};

static struct io_uring_query_zcrx query;
static bool zcrx_supported = false;
static long page_size;

static void *def_rq_mem;
static void *def_area_mem;
static void *def_netdev_area_mem;
static size_t def_netdev_area_size;
static void *def_hugepage_area_mem;
static void *ro_param_mem;
static size_t ro_param_mem_size;

static int if_idx = -1;
static int if_queue_idx;
static bool nodev_supported;

enum {
	CONFIG_HUGEPAGE		= 1 << 0,
	CONFIG_SMALL_RQ		= 1 << 1,
	CONFIG_AREA_SMALL	= 1 << 2,
	CONFIG_DEVICE		= 1 << 3,
};

static void wait_device(struct io_uring_zcrx_ifq_reg *reg)
{
	if (!(reg->flags & ZCRX_REG_NODEV))
		usleep(500);
}

static void *write_ro_params(void *src, size_t bytes)
{
	int ret;

	if (bytes > ro_param_mem_size)
		t_error(0, 1, "write_to_ro: too large");
	ret = mprotect(ro_param_mem, ro_param_mem_size, PROT_READ | PROT_WRITE);
	if (ret)
		t_error(0, errno, "mprotect failed");

	memcpy(ro_param_mem, src, bytes);

	ret = mprotect(ro_param_mem, ro_param_mem_size, PROT_READ);
	if (ret)
		t_error(0, errno, "mprotect read failed");

	return ro_param_mem;
}

static struct io_uring_cqe *submit_and_wait_one(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	int ret;

	ret = io_uring_submit(ring);
	if (ret != 1)
		t_error(1, ret, "submit_and_wait_one: submit fail\n");

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0)
		t_error(1, ret, "submit_and_wait_one: wait fail\n");

	return cqe;
}

static void test_io_uring_prep_zcrx(struct io_uring_sqe *sqe, int fd, int zcrx_id)
{
	io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, fd, NULL, 0, 0);
	sqe->zcrx_ifq_idx = zcrx_id;
	sqe->ioprio |= IORING_RECV_MULTISHOT;
}

static bool rq_ctrl_op_supported(int op)
{
	return query.nr_ctrl_opcodes > op;
}

static int t_zcrx_ctrl(struct io_uring *ring, struct zcrx_ctrl *ctrl)
{
	return io_uring_register(ring->ring_fd, IORING_REGISTER_ZCRX_CTRL, ctrl, 0);
}

static void query_zcrx(void)
{
	struct io_uring_query_hdr hdr = {
		.size = sizeof(query),
		.query_data = uring_ptr_to_u64(&query),
		.query_op = IO_URING_QUERY_ZCRX,
	};
	int ret;

	ret = io_uring_register(-1, IORING_REGISTER_QUERY, &hdr, 0);
	if (ret < 0 || hdr.result < 0) {
		memset(&query, 0, sizeof(query));
		query.rq_hdr_size = page_size;
		query.rq_hdr_alignment = page_size;
	} else {
		zcrx_supported = true;
	}
}

static unsigned rq_nr_queued(struct io_uring_zcrx_rq *rq)
{
	return rq->rq_tail - io_uring_smp_load_acquire(rq->khead);
}

static int flush_rq(struct io_uring *ring, int zcrx_id)
{
	struct zcrx_ctrl ctrl = {
		.zcrx_id = zcrx_id,
		.op = ZCRX_CTRL_FLUSH_RQ,
	};

	return t_zcrx_ctrl(ring, &ctrl);
}

static int try_register_zcrx(struct io_uring_zcrx_ifq_reg *reg)
{
	struct io_uring ring;
	int ret;

	ret = t_create_ring(8, &ring, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring create failed: %d\n", ret);
		exit(T_EXIT_FAIL);
	}

	ret = io_uring_register_ifq(&ring, reg);
	io_uring_queue_exit(&ring);
	wait_device(reg);
	return ret;
}

static int clone_zcrx(int src_id, struct io_uring *src_ring, struct io_uring *dst_ring,
		      struct io_uring_zcrx_ifq_reg *out_reg)
{
	struct zcrx_ctrl export_ctrl;
	int box_fd, ret;

	export_ctrl = (struct zcrx_ctrl) {
		.zcrx_id = src_id,
		.op = ZCRX_CTRL_EXPORT,
	};
	ret = t_zcrx_ctrl(src_ring, &export_ctrl);
	box_fd = export_ctrl.zc_export.zcrx_fd;
	if (ret < 0) {
		fprintf(stderr, "Export failed %i %i\n", ret, box_fd);
		return ret;
	}

	*out_reg = (struct io_uring_zcrx_ifq_reg) {
		.flags = ZCRX_REG_IMPORT,
		.if_idx = box_fd,
	};
	ret = io_uring_register_ifq(dst_ring, out_reg);
	if (ret) {
		fprintf(stderr, "Import failed %i\n", ret);
		return -1;
	}

	close(box_fd);
	return 0;
}

static size_t get_rq_size(unsigned nr_entries)
{
	size_t sz;

	sz = T_ALIGN_UP(query.rq_hdr_size, query.rq_hdr_alignment);
	sz += nr_entries * sizeof(struct io_uring_zcrx_rqe);
	return T_ALIGN_UP(sz, page_size);
}

static void default_reg(struct zcrx_reg *reg, unsigned config_flags)
{
	unsigned rq_entries = RQ_ENTRIES;

	if ((config_flags & CONFIG_HUGEPAGE) && (config_flags & CONFIG_AREA_SMALL))
		t_error(0, 1, "Invalid test reg flags");

	if (config_flags & CONFIG_SMALL_RQ)
		rq_entries = RQ_ENTRIES_SMALL;

	reg->rq_region = (struct io_uring_region_desc) {
		.size = get_rq_size(rq_entries),
		.user_addr = uring_ptr_to_u64(def_rq_mem),
		.flags = IORING_MEM_REGION_TYPE_USER,
	};
	reg->area = (struct io_uring_zcrx_area_reg) {
		.addr = uring_ptr_to_u64(def_area_mem),
		.len = AREA_SZ,
		.flags = 0,
	};
	reg->zcrx = (struct io_uring_zcrx_ifq_reg) {
		.rq_entries = rq_entries,
		.area_ptr = uring_ptr_to_u64(&reg->area),
		.region_ptr = uring_ptr_to_u64(&reg->rq_region),
	};

	if (config_flags & CONFIG_AREA_SMALL) {
		reg->area.len = AREA_SZ_SMALL;
	}
	if (config_flags & CONFIG_HUGEPAGE) {
		reg->area.addr = uring_ptr_to_u64(def_hugepage_area_mem);
		reg->area.len = HUGEPAGE_AREA_SZ;
	} else if (config_flags & CONFIG_DEVICE) {
		reg->area.addr = uring_ptr_to_u64(def_netdev_area_mem);
		reg->area.len = def_netdev_area_size;
	}

	if (config_flags & CONFIG_DEVICE) {
		reg->zcrx.if_idx = if_idx,
		reg->zcrx.if_rxq = if_queue_idx;
	} else {
		reg->zcrx.flags |= ZCRX_REG_NODEV;
	}
}

static int test_register_basic(unsigned extra_flags)
{
	struct zcrx_reg reg;
	int ret;

	default_reg(&reg, extra_flags);
	ret = try_register_zcrx(&reg.zcrx);
	if (ret == -EPERM)
		return ret;
	if (ret) {
		fprintf(stderr, "default setup failed\n");
		return ret;
	}

	if (def_hugepage_area_mem) {
		default_reg(&reg, CONFIG_HUGEPAGE);
		ret = try_register_zcrx(&reg.zcrx);
		if (ret) {
			fprintf(stderr, "default setup+huge failed\n");
			return ret;
		}
	}

	return 0;
}

static int test_rq(unsigned extra_flags)
{
	struct zcrx_reg reg;
	unsigned entries;
	int ret;

	default_reg(&reg, extra_flags);
	reg.zcrx.region_ptr = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered w/o region\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.rq_region.user_addr = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered rq region with no memory\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.rq_region.size = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered rq region size=0\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	entries = reg.zcrx.rq_entries;
	reg.zcrx.rq_entries -= 1;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && reg.zcrx.rq_entries != entries) {
		fprintf(stderr, "registered rq with non pow2 rq\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	if (query.rq_hdr_size != page_size && reg.rq_region.size > page_size) {
		reg.rq_region.size = page_size;
		ret = try_register_zcrx(&reg.zcrx);
		if (ret != -EINVAL && ret != -EFAULT) {
			fprintf(stderr, "registered rq with non pow2 rq\n");
			return ret;
		}
	}

	default_reg(&reg, extra_flags);
	reg.zcrx.rq_entries = 0;
	reg.zcrx.rq_entries = ~reg.zcrx.rq_entries;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered rq with unlimited entries\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.zcrx.rq_entries += (page_size / sizeof(struct io_uring_zcrx_rqe));
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered rq with too many entries\n");
		return ret;
	}

	return 0;
}

static int test_area(unsigned extra_flags)
{
	struct zcrx_reg reg;
	int ret;

	default_reg(&reg, extra_flags);
	reg.area.len = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered area size=0, %i\n", ret);
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.area.addr = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered with NULL area mem\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.zcrx.area_ptr = 0;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -EFAULT) {
		fprintf(stderr, "registered with no area\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.area.addr -= page_size;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EFAULT) {
		fprintf(stderr, "registered lower than area\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.area.len += page_size;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EFAULT) {
		fprintf(stderr, "registered higher than area\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.area.len -= page_size / 2;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EFAULT && ret != -EINVAL) {
		fprintf(stderr, "registered unaligned area size\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.area.len /= 2;
	reg.area.addr += page_size / 2;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EFAULT && ret != -EINVAL) {
		fprintf(stderr, "registered unaligned area ptr\n");
		return ret;
	}

	return 0;
}

static int test_ro_params(unsigned extra_flags)
{
	struct zcrx_reg __reg, *reg;
	int ret;

	default_reg(&__reg, extra_flags);
	reg = write_ro_params(&__reg, sizeof(__reg));

	ret = try_register_zcrx(&reg->zcrx);
	if (ret != -EFAULT) {
		fprintf(stderr, "registered unaligned area ptr\n");
		return ret;
	}
	return 0;
}

static int test_invalid_rx_page(unsigned extra_flags)
{
	struct zcrx_reg reg;
	int ret;

	default_reg(&reg, extra_flags);
	reg.zcrx.rx_buf_len = ~reg.zcrx.rx_buf_len;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -ERANGE && ret != -EOVERFLOW) {
		fprintf(stderr, "registered UINT_MAX rx buf len\n");
		return ret;
	}

	default_reg(&reg, extra_flags);
	reg.zcrx.rx_buf_len = 1U << 31;
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EINVAL && ret != -ERANGE && ret != -EOVERFLOW && ret != -EOPNOTSUPP) {
		fprintf(stderr, "registered too_large rx buf len\n");
		return ret;
	}

	return 0;
}

static int prep_server(struct t_executor *ctx, unsigned config_flags)
{
	struct io_uring_zcrx_ifq_reg *zcrx_reg = &ctx->reg.zcrx;
	char *rqp;
	int ret;

	ret = t_create_ring(128, &ctx->ring, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring create failed: %d\n", ret);
		return -1;
	}

	default_reg(&ctx->reg, config_flags);
	rqp = (char *)(uintptr_t)ctx->reg.rq_region.user_addr;
	memset(rqp, 0, get_rq_size(0));

	ret = io_uring_register_ifq(&ctx->ring, zcrx_reg);
	if (ret) {
		fprintf(stderr, "Can't register zcrx %i\n", ret);
		return ret;
	}

	ctx->rq.khead = (unsigned int *)((char *)rqp + zcrx_reg->offsets.head);
	ctx->rq.ktail = (unsigned int *)((char *)rqp + zcrx_reg->offsets.tail);
	ctx->rq.rqes = (struct io_uring_zcrx_rqe *)((char *)rqp + zcrx_reg->offsets.rqes);
	ctx->rq.rq_tail = 0;
	ctx->rq.ring_entries = zcrx_reg->rq_entries;

	ret = t_create_socket_pair(ctx->fds, true);
	if (ret) {
		fprintf(stderr, "t_create_socket_pair failed: %d\n", ret);
		return ret;
	}

	return 0;
}

static void fill_pattern(char *b, size_t size, unsigned long seq)
{
	for (long i = 0; i < size; i++)
		b[i] = ((seq + i) * 1000000001UL) ^ 0xdeadbeef;
}

static int check_pattern(char *b, size_t size, unsigned long seq)
{
	for (long i = 0; i < size; i++) {
		char exp = ((seq + i) * 1000000001UL) ^ 0xdeadbeef;

		if (exp != b[i])
			return -3;
	}
	return 0;
}

enum {
	T_RETURN_BUFS = 0x1,
	T_RETURN_LAZY = 0x2,
};

static int return_buffer(struct t_executor *ctx, struct io_uring_cqe *cqe,
			 unsigned flags)
{
	struct io_uring_zcrx_rq *rq = &ctx->rq;
	const struct io_uring_zcrx_cqe *rcqe = (void *)(cqe + 1);
	struct io_uring_zcrx_rqe *rqe;
	unsigned rq_mask;
	int ret;

	rq_mask = rq->ring_entries - 1;
	rqe = &rq->rqes[rq->rq_tail & rq_mask];
	rqe->off = (rcqe->off & ~IORING_ZCRX_AREA_MASK) | ctx->reg.area.rq_area_token;
	rqe->len = cqe->res;
	io_uring_smp_store_release(rq->ktail, ++rq->rq_tail);

	if (rq_nr_queued(rq) >= rq->ring_entries || !(flags & T_RETURN_LAZY)) {
		/* flush eagerly for the test */
		ret = flush_rq(&ctx->ring, ctx->reg.zcrx.zcrx_id);
		if (ret) {
			fprintf(stderr, "RQ flush failed %i\n", ret);
			return ret;
		}
	}
	return 0;
}

static int transfer_bytes(struct t_executor *ctx, size_t length,
			  unsigned flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	ssize_t bytes_tx = 0, bytes_rx = 0;
	size_t tx_buf_size = page_size;
	char *tx_buffer;
	int ret;

	tx_buffer = t_aligned_alloc(page_size, tx_buf_size);
	if (!tx_buffer)
		t_error(1, 0, "Can't alloc tx buffer");

	sqe = io_uring_get_sqe(&ctx->ring);
	test_io_uring_prep_zcrx(sqe, ctx->fds[0], ctx->reg.zcrx.zcrx_id);
	sqe->len = length;
	ret = io_uring_submit(&ctx->ring);
	if (ret != 1)
		t_error(1, ret, "transfer_bytes: submit fail\n");

	while (bytes_rx < length) {
		if (bytes_tx < length && (ssize_t)(bytes_tx - bytes_rx) < 2 * tx_buf_size) {
			ssize_t to_send = length - bytes_tx;
			ssize_t sent;

			if (to_send > tx_buf_size)
				to_send = tx_buf_size;
			fill_pattern(tx_buffer, to_send, bytes_tx);
			sent = send(ctx->fds[1], tx_buffer, tx_buf_size, 0);
			if (sent <= 0)
				t_error(1, sent, "Send failed\n");
			bytes_tx += sent;
		}

		if (bytes_rx > bytes_tx)
			t_error(1, 0, "unexpected tx/rx state");
		if (bytes_tx == bytes_rx)
			continue;

		ret = io_uring_wait_cqe(&ctx->ring, &cqe);
		if (ret < 0)
			t_error(1, ret, "submit_and_wait_one: wait fail\n");
		ret = 0;

		if (!(cqe->flags & IORING_CQE_F_MORE)) {
			ret = cqe->res < 0 ? cqe->res : -1;
		} else if (cqe->res < 0) {
			ret = cqe->res;
		} else {
			const struct io_uring_zcrx_cqe *rcqe = (void *)(cqe + 1);
			__u64 mask = (1ULL << IORING_ZCRX_AREA_SHIFT) - 1;
			char *data = (char *)(uintptr_t)ctx->reg.area.addr + (rcqe->off & mask);

			if (check_pattern(data, cqe->res, bytes_rx)) {
				ret = -3;
				break;
			}
			bytes_rx += cqe->res;

			if (flags & T_RETURN_BUFS) {
				ret = return_buffer(ctx, cqe, flags);
				if (ret < 0)
					return ret;
			}
		}

		io_uring_cqe_seen(&ctx->ring, cqe);
		if (ret < 0)
			goto done;
	}

	ret = io_uring_wait_cqe(&ctx->ring, &cqe);
	if (ret < 0)
		t_error(1, ret, "submit_and_wait_one: wait fail\n");

	if ((cqe->flags & IORING_CQE_F_MORE) || cqe->res != 0) {
		ret = -2;
		goto done;
	}
	io_uring_cqe_seen(&ctx->ring, cqe);
	ret = 0;
done:
	free(tx_buffer);
	return ret;
}

static void clean_server_noring(struct t_executor *ctx)
{
	close(ctx->fds[0]);
	close(ctx->fds[1]);
}

static void clean_server(struct t_executor *ctx)
{
	io_uring_queue_exit(&ctx->ring);
	clean_server_noring(ctx);
	wait_device(&ctx->reg.zcrx);
}

static int test_invalid_recv(unsigned extra_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct t_executor ctx;
	unsigned zcrx_id;
	int ret;

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	zcrx_id = ctx.reg.zcrx.zcrx_id;

	sqe = io_uring_get_sqe(&ctx.ring);
	test_io_uring_prep_zcrx(sqe, -1, zcrx_id);
	cqe = submit_and_wait_one(&ctx.ring);
	if (cqe->flags & IORING_CQE_F_MORE) {
		fprintf(stderr, "unexpected F_MORE for sockfd=-1\n");
		return -1;
	}
	if (cqe->res != -ENOTSOCK && cqe->res != -EBADF) {
		fprintf(stderr, "received from fd=-1 %i\n", cqe->res);
		return -1;
	}
	io_uring_cqe_seen(&ctx.ring, cqe);

	sqe = io_uring_get_sqe(&ctx.ring);
	test_io_uring_prep_zcrx(sqe, ctx.ring.ring_fd, zcrx_id);
	cqe = submit_and_wait_one(&ctx.ring);
	if (cqe->flags & IORING_CQE_F_MORE) {
		fprintf(stderr, "unexpected F_MORE w/ sockfd=ring_fd\n");
		return -1;
	}
	if (cqe->res != -ENOTSOCK && cqe->res != -EBADF) {
		fprintf(stderr, "received form ring fd %i\n", cqe->res);
		return -1;
	}
	io_uring_cqe_seen(&ctx.ring, cqe);

	sqe = io_uring_get_sqe(&ctx.ring);
	test_io_uring_prep_zcrx(sqe, ctx.fds[0], zcrx_id + 1);
	cqe = submit_and_wait_one(&ctx.ring);
	if (cqe->flags & IORING_CQE_F_MORE) {
		fprintf(stderr, "unexpected F_MORE for invalid zcrx_id\n");
		return -1;
	}
	if (cqe->res != -EINVAL) {
		fprintf(stderr, "received w/ invalid zcrx_id %i\n", cqe->res);
		return -1;
	}
	io_uring_cqe_seen(&ctx.ring, cqe);

	clean_server(&ctx);
	return 0;
}

static int test_exit_with_inflight(unsigned extra_flags)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct t_executor ctx;
	unsigned zcrx_id;
	int ret;

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	zcrx_id = ctx.reg.zcrx.zcrx_id;

	sqe = io_uring_get_sqe(&ctx.ring);
	test_io_uring_prep_zcrx(sqe, ctx.fds[0], zcrx_id);
	ret = io_uring_submit(&ctx.ring);
	if (ret != 1)
		t_error(1, ret, "submit_and_wait_one: submit fail\n");

	ret = io_uring_peek_cqe(&ctx.ring, &cqe);
	if (ret == 0) {
		fprintf(stderr, "Early terminated request\n");
		return -1;
	}

	io_uring_queue_exit(&ctx.ring);
	sleep(1);
	clean_server_noring(&ctx);
	return 0;
}

static int test_zcrx_invalid_clone(void)
{
	struct io_uring_zcrx_ifq_reg import;
	struct io_uring r1, r2;
	struct zcrx_ctrl ctrl, *pctrl;
	struct zcrx_reg reg;
	unsigned box_fd;
	int ret;

	ret = t_create_ring(128, &r1, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring1 create failed: %d\n", ret);
		return -1;
	}
	ret = t_create_ring(128, &r2, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring1 create failed: %d\n", ret);
		return -1;
	}

	ctrl = (struct zcrx_ctrl) {
		.zcrx_id = 0,
		.op = ZCRX_CTRL_EXPORT,
	};
	ret = io_uring_register(-1, IORING_REGISTER_ZCRX_CTRL, &ctrl, 0);
	if (!ret) {
		fprintf(stderr, "exported with no ring %i\n", ret);
		return -1;
	}

	ctrl = (struct zcrx_ctrl) {
		.zcrx_id = 0,
		.op = ZCRX_CTRL_EXPORT,
	};
	ret = t_zcrx_ctrl(&r1, &ctrl);
	if (ret == 0) {
		fprintf(stderr, "exported without zcrx %i\n", ret);
		return -1;
	}

	import = (struct io_uring_zcrx_ifq_reg) {
		.flags = ZCRX_REG_IMPORT,
		.if_idx = -1,
	};
	ret = io_uring_register_ifq(&r1, &import);
	if (ret == 0) {
		fprintf(stderr, "register invalid box %i\n", ret);
		return -1;
	}

	default_reg(&reg, 0);
	ret = io_uring_register_ifq(&r1, &reg.zcrx);
	if (ret) {
		fprintf(stderr, "Can't register zcrx\n");
		return ret;
	}

	ctrl = (struct zcrx_ctrl) {
		.zcrx_id = reg.zcrx.zcrx_id,
		.op = ZCRX_CTRL_EXPORT,
	};
	pctrl = write_ro_params(&ctrl, sizeof(ctrl));
	ret = t_zcrx_ctrl(&r1, pctrl);
	if (ret == 0) {
		fprintf(stderr, "exported with ro params\n");
		return ret;
	}

	ctrl = (struct zcrx_ctrl) {
		.zcrx_id = reg.zcrx.zcrx_id,
		.op = ZCRX_CTRL_EXPORT,
	};
	ret = t_zcrx_ctrl(&r1, &ctrl);
	box_fd = ctrl.zc_export.zcrx_fd;
	if (ret < 0 || (int)box_fd < 0) {
		fprintf(stderr, "Can'r export zcrx %i\n", ret);
		return -1;
	}

	import = (struct io_uring_zcrx_ifq_reg) {
		.flags = ZCRX_REG_IMPORT,
		.if_idx = box_fd,
	};
	ret = io_uring_register(-1, IORING_REGISTER_ZCRX_IFQ, &import, 1);
	if (ret == 0) {
		fprintf(stderr, "Imported wo ring %i\n", ret);
		return ret;
	}

	close(box_fd);
	io_uring_queue_exit(&r1);
	io_uring_queue_exit(&r2);
	return 0;
}

static int test_zcrx_clone(void)
{
	struct io_uring ring_exp, ring_imp;
	struct io_uring_zcrx_ifq_reg import_reg;
	struct zcrx_reg reg;
	int ret;

	ret = t_create_ring(128, &ring_exp, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring1 create failed: %d\n", ret);
		return -1;
	}
	ret = t_create_ring(128, &ring_imp, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring2 create failed: %d\n", ret);
		return -1;
	}

	default_reg(&reg, 0);
	ret = io_uring_register_ifq(&ring_exp, &reg.zcrx);
	if (ret) {
		fprintf(stderr, "Can't register zcrx\n");
		return ret;
	}

	ret = clone_zcrx(reg.zcrx.zcrx_id, &ring_exp, &ring_imp, &import_reg);
	if (ret)
		return ret;

	io_uring_queue_exit(&ring_imp);
	io_uring_queue_exit(&ring_exp);
	return 0;
}

static int test_rq_flush(unsigned extra_flags)
{
	struct t_executor ctx;
	int ret;

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;

	ret = flush_rq(&ctx.ring, ctx.reg.zcrx.zcrx_id + 1);
	if (!ret) {
		fprintf(stderr, "Flushed non-existent zcrx %i\n", ret);
		return ret;
	}

	if (rq_ctrl_op_supported(ZCRX_CTRL_FLUSH_RQ)) {
		ret = flush_rq(&ctx.ring, ctx.reg.zcrx.zcrx_id);
		if (ret) {
			fprintf(stderr, "RQ flush failed %i\n", ret);
			return ret;
		}
	}

	clean_server(&ctx);
	return 0;
}

static int test_recv(unsigned extra_flags)
{
	struct t_executor ctx;
	int ret;

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;

	ret = transfer_bytes(&ctx, page_size, 0);
	if (ret) {
		fprintf(stderr, "Transfer page failed %i\n", ret);
		return ret;
	}

	ret = transfer_bytes(&ctx, ctx.reg.area.len * 2, 0);
	if (!ret) {
		fprintf(stderr, "Exhaust area test failed %i\n", ret);
		return ret;
	}
	clean_server(&ctx);

	if (rq_ctrl_op_supported(ZCRX_CTRL_FLUSH_RQ)) {
		ret = prep_server(&ctx, extra_flags);
		if (ret)
			return ret;

		ret = transfer_bytes(&ctx, page_size, T_RETURN_BUFS);
		if (ret) {
			fprintf(stderr, "Transfer page + flush failed %i\n", ret);
			return ret;
		}

		ret = transfer_bytes(&ctx, ctx.reg.area.len * 2, T_RETURN_BUFS);
		if (ret) {
			fprintf(stderr, "Transfer 2xAREA failed %i\n", ret);
			return ret;
		}
		clean_server(&ctx);

		if (ctx.reg.area.len > (RQ_ENTRIES_SMALL + 1) * page_size) {
			ret = prep_server(&ctx, CONFIG_SMALL_RQ | extra_flags);
			if (ret)
				return ret;

			ret = transfer_bytes(&ctx, ctx.reg.area.len * 2, T_RETURN_BUFS | T_RETURN_LAZY);
			if (ret) {
				fprintf(stderr, "Transfer lazy return failed %i\n", ret);
				return ret;
			}
			clean_server(&ctx);
		}
	}

	return 0;
}

static int test_abnormal_exit(bool iowq, bool pin_zcrx, unsigned extra_flags)
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	struct zcrx_reg reg;
	char buf[16] = {};
	char *refill_queue_ptr;
	int ret, fds[2];
	int box_fd = -1;

	ret = t_create_ring(16, &ring, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "ring create failed: %d\n", ret);
		return -1;
	}

	default_reg(&reg, extra_flags);
	refill_queue_ptr = (char *)(uintptr_t)reg.rq_region.user_addr;
	memset(refill_queue_ptr, 0, get_rq_size(0));

	ret = io_uring_register_ifq(&ring, &reg.zcrx);
	if (ret) {
		fprintf(stderr, "Can't register zcrx %i\n", ret);
		return ret;
	}

	ret = t_create_socket_pair(fds, true);
	if (ret) {
		fprintf(stderr, "t_create_socket_pair failed: %d\n", ret);
		return ret;
	}

	if (pin_zcrx) {
		struct zcrx_ctrl export_ctrl = {
			.zcrx_id = reg.zcrx.zcrx_id,
			.op = ZCRX_CTRL_EXPORT,
		};

		ret = t_zcrx_ctrl(&ring, &export_ctrl);
		box_fd = export_ctrl.zc_export.zcrx_fd;
		if (ret < 0) {
			fprintf(stderr, "Export failed %i %i\n", ret, box_fd);
			return ret;
		}
	}

	if (!iowq) {
		sqe = io_uring_get_sqe(&ring);
		test_io_uring_prep_zcrx(sqe, fds[0], reg.zcrx.zcrx_id);
		ret = io_uring_submit(&ring);
		if (ret != 1)
			t_error(1, ret, "zcrx submit fail\n");

		/* try to queue a task_work for the rx request */
		ret = send(fds[1], buf, sizeof(buf), 0);
		if (ret <= 0)
			t_error(1, ret, "Send failed\n");
		/* unregister zcrx with inflight request */
	} else {
		ret = send(fds[1], buf, sizeof(buf), 0);
		if (ret <= 0)
			t_error(1, ret, "Send failed\n");

		sqe = io_uring_get_sqe(&ring);
		test_io_uring_prep_zcrx(sqe, fds[0], reg.zcrx.zcrx_id);
		sqe->flags |= IOSQE_ASYNC;
		ret = io_uring_submit(&ring);
		if (ret != 1)
			t_error(1, ret, "zcrx submit fail\n");
		/* unregister zcrx while io-wq processes a request */
	}

	io_uring_queue_exit(&ring);
	/* give it time to exit before shutting the socket */
	usleep(300);
	close(fds[0]);
	close(fds[1]);
	if (box_fd != -1)
		close(box_fd);
	wait_device(&reg.zcrx);
	return 0;
}

static int test_area_add_invalid(unsigned extra_flags)
{
	struct io_uring_zcrx_area_reg area_reg;
	struct t_executor ctx;
	struct zcrx_ctrl ctrl, ctrl_base;
	size_t len;
	int ret;

	ret = prep_server(&ctx, CONFIG_AREA_SMALL);
	if (ret)
		return ret;

	len = ctx.reg.area.len;
	ctrl_base = (struct zcrx_ctrl) {
		.op = ZCRX_CTRL_ADD_AREA,
		.zcrx_id = ctx.reg.zcrx.zcrx_id,
		.zc_area.area_ptr = uring_ptr_to_u64(&area_reg),
	};

	ctrl = ctrl_base;
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = 0,
		.len = len,
	};
	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (!ret) {
		fprintf(stderr, "add area NULL failed %d\n", ret);
		return ret;
	}

	ctrl = ctrl_base;
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = ctx.reg.area.addr,
		.len = 0,
	};
	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (!ret) {
		fprintf(stderr, "add area 0 size failed %d\n", ret);
		return ret;
	}

	ctrl = ctrl_base;
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = ctx.reg.area.addr,
		.len = 1,
	};
	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (!ret) {
		fprintf(stderr, "add area unaligned failed %d\n", ret);
		return ret;
	}

	ctrl = ctrl_base;
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = ctx.reg.area.addr,
		.len = -1UL,
	};
	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (!ret) {
		fprintf(stderr, "add area unaligned failed %d\n", ret);
		return ret;
	}

	clean_server(&ctx);
	return 0;
}

static int test_area_add(void)
{
	struct io_uring_zcrx_area_reg area_reg;
	struct t_executor ctx;
	struct zcrx_ctrl ctrl;
	size_t len;
	int ret;

	ret = prep_server(&ctx, CONFIG_AREA_SMALL);
	if (ret)
		return ret;
	len = ctx.reg.area.len;

	ctrl = (struct zcrx_ctrl) {
		.op = ZCRX_CTRL_ADD_AREA,
		.zcrx_id = ctx.reg.zcrx.zcrx_id,
		.zc_area.area_ptr = uring_ptr_to_u64(&area_reg),
	};
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = ctx.reg.area.addr + len,
		.len = len,
	};

	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (ret) {
		fprintf(stderr, "add area failed %d\n", ret);
		return ret;
	}
	if (area_reg.rq_area_token == ctx.reg.area.rq_area_token) {
		fprintf(stderr, "area add: dup area tokens\n");
		return -EINVAL;
	}

	ret = transfer_bytes(&ctx, len * 2, 0);
	if (ret) {
		fprintf(stderr, "Transfer lazy return failed %i\n", ret);
		return ret;
	}

	ret = transfer_bytes(&ctx, len, 0);
	if (!ret) {
		fprintf(stderr, "Transfer without free buffers %i\n", ret);
		return ret;
	}

	clean_server(&ctx);
	return 0;
}

static int test_area_add_refill(void)
{
	struct io_uring_zcrx_area_reg area_reg;
	struct t_executor ctx;
	struct zcrx_ctrl ctrl;
	size_t len;
	int ret;

	ret = prep_server(&ctx, CONFIG_AREA_SMALL);
	if (ret)
		return ret;
	len = ctx.reg.area.len;

	ctrl = (struct zcrx_ctrl) {
		.op = ZCRX_CTRL_ADD_AREA,
		.zcrx_id = ctx.reg.zcrx.zcrx_id,
		.zc_area.area_ptr = uring_ptr_to_u64(&area_reg),
	};
	area_reg = (struct io_uring_zcrx_area_reg) {
		.addr = ctx.reg.area.addr + len,
		.len = len,
	};

	/* exhaust the initial pool */
	ret = transfer_bytes(&ctx, len, 0);
	if (ret) {
		fprintf(stderr, "test_area_add_refill: 1st transfer failed %i\n", ret);
		return ret;
	}

	ret = t_zcrx_ctrl(&ctx.ring, &ctrl);
	if (ret) {
		fprintf(stderr, "test_area_add_refill: add area failed %d\n", ret);
		return ret;
	}

	/* only the added pool left, make sure we can return buffers */
	ret = transfer_bytes(&ctx, 16 * len, T_RETURN_BUFS);
	if (ret) {
		fprintf(stderr, "test_area_add_refill: 2nd transfer failed %i\n", ret);
		return ret;
	}

	clean_server(&ctx);
	return 0;
}

struct area_add_job {
	int box_fd;
	pthread_barrier_t barrier;
	pthread_t thread;

	void *ptr;
	int len;
	int nr;
};

static void *area_add_job_cb(void *arg)
{
	struct area_add_job *job = arg;
	struct io_uring_zcrx_ifq_reg reg;
	struct io_uring ring;
	int i, ret;

	ret = t_create_ring(8, &ring, RING_FLAGS);
	if (ret != T_SETUP_OK) {
		fprintf(stderr, "area_add_job_cb() create failed: %d\n", ret);
		exit(-1);
	}
	reg = (struct io_uring_zcrx_ifq_reg) {
		.flags = ZCRX_REG_IMPORT,
		.if_idx = job->box_fd,
	};
	ret = io_uring_register_ifq(&ring, &reg);
	if (ret) {
		fprintf(stderr, "area_add_job_cb(): import failed %i\n", ret);
		exit(-1);
	}
	pthread_barrier_wait(&job->barrier);

	for (i = 0; i < job->nr; i++) {
		struct io_uring_zcrx_area_reg area_reg = {
			.addr = uring_ptr_to_u64(job->ptr + i * job->len),
			.len = job->len,
		};
		struct zcrx_ctrl ctrl = {
			.op = ZCRX_CTRL_ADD_AREA,
			.zcrx_id = reg.zcrx_id,
			.zc_area.area_ptr = uring_ptr_to_u64(&area_reg),
		};

		ret = t_zcrx_ctrl(&ring, &ctrl);
		if (ret) {
			fprintf(stderr, "test_area_add_refill: add area failed %d\n", ret);
			exit(ret);
		}
	}

	io_uring_queue_exit(&ring);
	return NULL;
}

static int test_area_add_concurrent(void)
{
	struct zcrx_ctrl export_ctrl;
	struct area_add_job job;
	struct t_executor ctx;
	int ret, box_fd;
	size_t len;

	ret = prep_server(&ctx, CONFIG_AREA_SMALL);
	if (ret)
		return ret;
	len = ctx.reg.area.len;

	export_ctrl = (struct zcrx_ctrl) {
		.zcrx_id = ctx.reg.zcrx.zcrx_id,
		.op = ZCRX_CTRL_EXPORT,
	};
	ret = t_zcrx_ctrl(&ctx.ring, &export_ctrl);
	box_fd = export_ctrl.zc_export.zcrx_fd;
	if (ret < 0) {
		fprintf(stderr, "Export failed %i %i\n", ret, box_fd);
		return ret;
	}

	job.box_fd = box_fd;
	job.ptr = (void *)(unsigned long)ctx.reg.area.addr + len;
	job.len = len;
	job.nr = (AREA_SZ - len) / len;
	if (job.nr > 128)
		job.nr = 128;

	if (pthread_barrier_init(&job.barrier, NULL, 2) != 0) {
		fprintf(stderr, "pthread_barrier_init failed %i\n", errno);
		return -1;
	}
	if (pthread_create(&job.thread, NULL, area_add_job_cb, &job) != 0) {
		fprintf(stderr, "pthread_create failed %i\n", errno);
		return -1;
	}
	pthread_barrier_wait(&job.barrier);

	ret = transfer_bytes(&ctx, 128 * len, T_RETURN_BUFS);
	if (ret) {
		fprintf(stderr, "test_area_add_concurrent() transfer failed %i\n", ret);
		return ret;
	}

	pthread_join(job.thread, NULL);
	pthread_barrier_destroy(&job.barrier);
	close(box_fd);
	clean_server(&ctx);
	return 0;
}

static int flush_invalid(struct t_executor *ctx, struct io_uring_zcrx_rqe *rqes,
			 unsigned nr)
{
	struct io_uring_zcrx_rq *rq = &ctx->rq;
	unsigned rq_mask = rq->ring_entries - 1;
	struct io_uring_zcrx_rqe *rqe;
	int i, ret;

	for (i = 0; i < nr; i++) {
		rqe = &rq->rqes[rq->rq_tail & rq_mask];
		memcpy(rqe, &rqes[i], sizeof(*rqe));

		io_uring_smp_store_release(rq->ktail, ++rq->rq_tail);

		ret = flush_rq(&ctx->ring, ctx->reg.zcrx.zcrx_id);
		if (ret)
			return ret;
	}
	return 0;
}

static int test_invalid_rq_pointers(unsigned extra_flags)
{
	struct t_executor ctx;
	struct io_uring_zcrx_rq *rq = &ctx.rq;
	int ret;

	if (!rq_ctrl_op_supported(ZCRX_CTRL_FLUSH_RQ))
		return 0;
	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	*rq->ktail = 0;
	*rq->khead = 1;
	(void)flush_rq(&ctx.ring, ctx.reg.zcrx.zcrx_id);
	clean_server(&ctx);

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	*rq->ktail = 2 * rq->ring_entries;
	(void)flush_rq(&ctx.ring, ctx.reg.zcrx.zcrx_id);
	clean_server(&ctx);
	return 0;
}

static int test_invalid_rqes(unsigned extra_flags)
{
	struct io_uring_zcrx_rqe *rqe, rqes[16];
	struct t_executor ctx;
	__u64 area_token;
	int ret, i;

	if (!rq_ctrl_op_supported(ZCRX_CTRL_FLUSH_RQ))
		return 0;

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	area_token = ctx.reg.area.rq_area_token;

	for (i = 0; i < 16; i++) {
		rqe = &rqes[i];
		rqe->off = area_token;
		rqe->len = 1;
	}
	ret = flush_invalid(&ctx, rqes, 16);
	if (ret)
		return ret;
	clean_server(&ctx);

	ret = prep_server(&ctx, extra_flags);
	if (ret)
		return ret;
	area_token = ctx.reg.area.rq_area_token;

	rqe = &rqes[0];
	rqe->off = area_token + ctx.reg.area.len;
	rqe->len = 1;

	rqe = &rqes[1];
	rqe->off = ((uint64_t)1 << IORING_ZCRX_AREA_SHIFT) - 1;
	rqe->len = 1;

	rqe = &rqes[2];
	rqe->off = area_token + ((__u64)1 << IORING_ZCRX_AREA_SHIFT);
	rqe->len = 1;

	rqe = &rqes[3];
	rqe->off = area_token;
	rqe->len = 1;
	rqe->__pad = 1;

	ret = flush_invalid(&ctx, rqes, 4);
	if (ret)
		return ret;
	clean_server(&ctx);
	return 0;
}

static int test_area_ro(unsigned extra_flags)
{
	struct zcrx_reg reg;
	void *area;
	int ret;

	default_reg(&reg, extra_flags);

	area = mmap(NULL, reg.area.len, PROT_READ,
		    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (area == MAP_FAILED) {
		perror("mmap");
		return T_EXIT_FAIL;
	}

	reg.area.addr = uring_ptr_to_u64(area);
	ret = try_register_zcrx(&reg.zcrx);
	if (ret != -EFAULT) {
		fprintf(stderr, "registered read-only memory\n");
		return T_EXIT_FAIL;
	}
	munmap(area, AREA_SZ);
	return 0;
}

static int run_tests(void)
{
	int ret, mode, i;

	for (mode = 0; mode < 2; mode++) {
		bool use_device = mode & 1;
		unsigned extra_flags = 0;

		if (use_device) {
			if (if_idx == -1)
				continue;
			extra_flags = CONFIG_DEVICE;
		} else {
			if (!nodev_supported)
				continue;
		}

		ret = test_register_basic(extra_flags);
		if (ret == -EPERM) {
			printf("-EPERM, zcrx requires NET_ADMIN, skip\n");
			return T_EXIT_SKIP;
		}
		if (ret) {
			fprintf(stderr, "test_register_basic() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_rq(extra_flags);
		if (ret) {
			fprintf(stderr, "test_rq() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_area(extra_flags);
		if (ret) {
			fprintf(stderr, "test_area() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_area_ro(extra_flags);
		if (ret) {
			fprintf(stderr, "test_area() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		if (query.features & ZCRX_FEATURE_RX_PAGE_SIZE) {
			ret = test_invalid_rx_page(extra_flags);
			if (ret) {
				fprintf(stderr, "test_invalid_rx_page() failed %i\n", ret);
				return T_EXIT_FAIL;
			}
		}

		ret = test_ro_params(extra_flags);
		if (ret) {
			fprintf(stderr, "test_ro_params() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_invalid_recv(extra_flags);
		if (ret) {
			fprintf(stderr, "test_invalid_recv() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_exit_with_inflight(extra_flags);
		if (ret) {
			fprintf(stderr, "test_exit_with_inflight() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_rq_flush(extra_flags);
		if (ret) {
			fprintf(stderr, "test_rq_flush() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_invalid_rqes(extra_flags);
		if (ret) {
			fprintf(stderr, "test_invalid_rqes() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_invalid_rq_pointers(extra_flags);
		if (ret) {
			fprintf(stderr, "test_invalid_rq_pointers() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_recv(extra_flags);
		if (ret) {
			fprintf(stderr, "test_recv() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		for (i = 0; i < 4; i++) {
			bool iowq = i & 1;
			bool pin_zcrx = i & 2;

			if (pin_zcrx && !(query.register_flags & ZCRX_REG_IMPORT))
				continue;
			ret = test_abnormal_exit(iowq, pin_zcrx, extra_flags);
			if (ret) {
				fprintf(stderr, "test_abnormal_exit(%i, %i) %i\n", iowq, pin_zcrx, ret);
				return T_EXIT_FAIL;
			}
		}

		if (rq_ctrl_op_supported(ZCRX_CTRL_ADD_AREA)) {
			ret = test_area_add_invalid(extra_flags);
			if (ret) {
				fprintf(stderr, "test_area_add_invalid() failed %i\n", ret);
				return T_EXIT_FAIL;
			}
		}
	}

	if (query.register_flags & ZCRX_REG_IMPORT) {
		ret = test_zcrx_invalid_clone();
		if (ret) {
			fprintf(stderr, "test_zcrx_invalid_clone() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_zcrx_clone();
		if (ret) {
			fprintf(stderr, "test_zcrx_clone() failed %i\n", ret);
			return T_EXIT_FAIL;
		}
	} else {
		printf("zcrx import is not supported, skip\n");
	}

	if (rq_ctrl_op_supported(ZCRX_CTRL_ADD_AREA)) {
		ret = test_area_add();
		if (ret) {
			fprintf(stderr, "test_area_add() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_area_add_refill();
		if (ret) {
			fprintf(stderr, "test_area_add_refill() failed %i\n", ret);
			return T_EXIT_FAIL;
		}

		ret = test_area_add_concurrent();
		if (ret) {
			fprintf(stderr, "test_area_add_refill() failed %i\n", ret);
			return T_EXIT_FAIL;
		}
	} else {
		printf("area add not supported, skip\n");
	}

	return T_EXIT_PASS;
}

static void setup(void)
{
	void *area_outer;

	area_outer = mmap(NULL, AREA_SZ + 2 * page_size, PROT_NONE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (area_outer == MAP_FAILED)
		perror("mmap");

	def_area_mem = mmap(area_outer + page_size, AREA_SZ, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (def_area_mem == MAP_FAILED)
		perror("mmap");
	madvise(def_area_mem, AREA_SZ, MADV_NOHUGEPAGE);

	def_hugepage_area_mem = mmap(NULL, HUGEPAGE_AREA_SZ, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB,
				     -1, 0);
	if (def_hugepage_area_mem == MAP_FAILED) {
		printf("can't allocate huge page, skip huge page tests\n");
		def_hugepage_area_mem = NULL;
	}

	def_rq_mem = mmap(NULL, get_rq_size(RQ_ENTRIES), PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
	if (def_rq_mem == MAP_FAILED)
		t_error(1, 0, "mmap(): refill ring");

	ro_param_mem_size = T_ALIGN_UP(4096 * 2, page_size);
	ro_param_mem = mmap(NULL, ro_param_mem_size, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (ro_param_mem == MAP_FAILED) {
		fprintf(stderr, "null ro\n");
		t_error(0, 1, "read-only mmap setup failed");
	}

	if (if_idx != -1) {
		def_netdev_area_size = 4 * 1024 * 4096;
		def_netdev_area_size = T_ALIGN_UP(def_netdev_area_size, page_size);

		area_outer = mmap(NULL, def_netdev_area_size + 2 * page_size, PROT_NONE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (area_outer == MAP_FAILED)
			perror("mmap");

		def_netdev_area_mem = mmap(area_outer + page_size, def_netdev_area_size, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
		if (def_netdev_area_mem == MAP_FAILED)
			perror("mmap");
	}
}

int main(int argc, char *argv[])
{
	const char *dev_name;

	if (argc > 1)
		return T_EXIT_SKIP;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return T_EXIT_FAIL;
	}

	query_zcrx();

	if (!zcrx_supported) {
		printf("zcrx and query are not supported, skip");
		return T_EXIT_SKIP;
	}

	dev_name = getenv(DEV_ENV_VAR);
	if (dev_name) {
		const char *rxq_str;
		char *rxq_end;

		if_idx = if_nametoindex(dev_name);
		if (!if_idx) {
			fprintf(stderr, "can't find netdev\n");
			return T_EXIT_FAIL;
		}
		rxq_str = getenv(RXQ_ENV_VAR);
		if (!rxq_str) {
			fprintf(stderr, "queue is not specified\n");
			return T_EXIT_FAIL;
		}
		if_queue_idx = strtol(rxq_str, &rxq_end, 10);
		if (rxq_end == rxq_str || *rxq_end != '\0') {
			fprintf(stderr, "invalid queue index\n");
			return T_EXIT_FAIL;
		}

		printf("note: using device %s(%i) queue idx %i\n",
			dev_name, if_idx, if_queue_idx);
	}

	nodev_supported = query.register_flags & ZCRX_REG_NODEV;

	if (!nodev_supported && !dev_name) {
		printf("zcrx nodev mode is not supported, netdev isn't specified, skip");
		return T_EXIT_SKIP;
	}

	setup();
	return run_tests();
}
