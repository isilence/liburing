#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/memfd.h>
#include <linux/udmabuf.h>

#include "liburing.h"
#include "helpers.h"

static int udmabuf_devfd;
static int page_size;

enum {
	FILL_ZERO,
	FILL_PATTERN,
};

struct t_buf {
	void *ptr;
	size_t size;
	int dmabuf_fd;
	int memfd;
};

struct t_dev {
	int fd;
	size_t block_size;
	size_t size;
};

static inline __u64 get_pattern(size_t off)
{
	return off;
}

static void fill_buffer_pattern(void *buf, size_t size, size_t off)
{
	size_t i;

	for (i = 0; i < size;) {
		size_t cur_off = off + i;
		__u64 *v = buf + i;

		*v = get_pattern(cur_off);
		i += sizeof(*v);
	}
}

static int __verify_data(void *ptr, size_t buf_off, size_t f_off, size_t size)
{
	for (size_t i = 0; i < size;) {
		__u64 *pbuf = ptr + buf_off + i;
		__u64 v = *pbuf;
		__u64 expected = get_pattern(f_off + i);

		if (v != expected) {
			fprintf(stderr, "Data mismatch %lu vs %lu, off %li\n",
				(long)v, (long)expected, (long)i);
			return -1;
		}
		i += sizeof(v);
	}
	return 0;
}

static int verify_data(struct t_buf *buf, size_t buf_off, size_t f_off, size_t size)
{
	return __verify_data(buf->ptr, buf_off, f_off, size);
}

static int pread_slice(int fd, void *buf, size_t size, size_t f_off)
{
	size_t off = 0;
	int ret;

	while (off < size) {
		ret = pread(fd, buf + off, size - off, f_off + off);
		if (ret < 0) {
			fprintf(stderr, "Can't read device %i, off %lu\n",
				errno, (long)off);
			return errno;
		}
		off += ret;
	}
	return 0;
}

static int read_verify(struct t_dev *dev)
{
	void *buf;
	int ret;

	buf = t_aligned_alloc(page_size, dev->size);
	if (!buf)
		return -ENOMEM;

	ret = pread_slice(dev->fd, buf, dev->size, 0);
	if (ret) {
		fprintf(stderr, "pread_slice failed\n");
		exit(1);
	}
	ret = __verify_data(buf, 0, 0, dev->size);
	if (ret) {
		fprintf(stderr, "read-verify failed\n");
		return -1;
	}

	free(buf);
	return 0;
}

static int fill_device(struct t_dev *dev, int mode)
{
	size_t buf_size = dev->block_size * 8;
	size_t size = dev->size;
	size_t off;
	void *buf;
	int ret;

	buf = t_aligned_alloc(page_size, buf_size);
	if (!buf)
		return -ENOMEM;

	for (off = 0; off < size; ) {
		if (mode == FILL_PATTERN)
			fill_buffer_pattern(buf, buf_size, off);
		else
			memset(buf, 0, buf_size);

		ret = pwrite(dev->fd, buf, buf_size, off);
		if (ret <= 0) {
			fprintf(stderr, "fill device write failed %i %i\n", ret, errno);
			return -1;
		}
		off += ret;
	}

	free(buf);
	return 0;
}

static int open_device(struct t_dev *dev, const char *dev_name)
{
	unsigned int size;
	int fd;

	fd = open(dev_name, O_DIRECT | O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Can't open device %i\n", fd);
		return T_EXIT_FAIL;
	}
	if (ioctl(fd, BLKSSZGET, &size) < 0) {
		fprintf(stderr, "Can't get block size, skip\n");
		return T_EXIT_SKIP;
	}

	dev->block_size = size;
	dev->fd = fd;
	return 0;
}

static void close_device(struct t_dev *dev)
{
	close(dev->fd);
	dev->fd = -1;
}

static int create_udmabuf(struct t_buf *b, size_t size)
{
	struct udmabuf_create create;
	int memfd, dmabuf_fd;
	void *p;
	int ret;

	memfd = memfd_create("udmabuf-test", MFD_ALLOW_SEALING);
	if (memfd < 0) {
		fprintf(stderr, "memfd_create failed %i\n", memfd);
		return memfd;
	}

	ret = fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0) {
		fprintf(stderr, "F_ADD_SEALS failed\n");
		return ret;
	}

	ret = ftruncate(memfd, size);
	if (ret == -1) {
		fprintf(stderr, "memfd truncate failed, %i\n", -errno);
		return -errno;
	}

	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.offset = 0;
	create.size = size;
	dmabuf_fd = ioctl(udmabuf_devfd, UDMABUF_CREATE, &create);
	if (dmabuf_fd < 0) {
		fprintf(stderr, "UDMABUF_CREATE failed %i\n", dmabuf_fd);
		return dmabuf_fd;
	}

	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf_fd, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "dmabuf_fd mmap failed\n");
		return -EFAULT;
	}

	b->size = size;
	b->dmabuf_fd = dmabuf_fd;
	b->memfd = memfd;
	b->ptr = p;
	return 0;
}

static void close_udmabuf(struct t_buf *b)
{
	munmap(b->ptr, b->size);
	close(b->dmabuf_fd);
	close(b->memfd);
}

static int register_buf(struct io_uring *ring, struct io_uring_rsrc_update2 *up)
{
	int ret;

	ret = io_uring_register(ring->ring_fd, IORING_REGISTER_BUFFERS_UPDATE,
				up, sizeof(*up));
	if (ret == 1)
		return 0;
	return ret < 0 ? ret : -1;
}

static int test_invalid_registration(struct t_dev *dev, struct t_buf *buf)
{
	struct io_uring_rsrc_update2 up;
	struct io_uring_regbuf_desc rd;
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init(64, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return -1;
	}

	ret = io_uring_register_buffers_sparse(&ring, 1);
	if (ret) {
		fprintf(stderr, "sparse buf table reg failed %i\n", ret);
		return ret;
	}

	memset(&up, 0, sizeof(up));
	up.data = uring_ptr_to_u64(&rd);
	up.nr = 1;
	up.resv = IORING_RSRC_UPDATE_EXTENDED;

	memset(&rd, 0, sizeof(rd));
	rd.type = IO_REGBUF_TYPE_DMABUF;
	rd.target_fd = dev->fd;
	rd.dmabuf_fd = ring.ring_fd;
	ret = register_buf(&ring, &up);
	if (!ret) {
		fprintf(stderr, "Registered invalid dmabuf %i\n", ret);
		return ret < 0 ? ret : -1;
	}

	rd.target_fd = ring.ring_fd;
	rd.dmabuf_fd = buf->dmabuf_fd;
	ret = register_buf(&ring, &up);
	if (!ret) {
		fprintf(stderr, "Registered invalid target_fd %i\n", ret);
		return ret < 0 ? ret : -1;
	}

	io_uring_queue_exit(&ring);
	return 0;
}

static __u64 idx_to_mask(unsigned i)
{
	return (__u64)1 << i;
}

static int find_free_idx(__u64 mask)
{
	for (unsigned i = 0; i < 63; i++) {
		if (mask & idx_to_mask(i))
			return i;
	}
	return -1;
}

static int test_parallel_reads(struct io_uring *ring, struct t_dev *dev, struct t_buf *buf)
{
	const int max_inflight = 16;
	__u64 mask = ((__u64)1 << max_inflight) - 1;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int nr_left = 1000;
	int inflight = 0;
	int i, ret;

	while (nr_left > 0 || inflight) {
		int to_submit = max_inflight - inflight;
		unsigned int head, count = 0;

		if (to_submit > nr_left)
			to_submit = nr_left;

		for (i = 0; i < to_submit; i++) {
			int idx = find_free_idx(mask);
			size_t off = dev->block_size * idx;

			if (idx == -1 || idx >= max_inflight) {
				fprintf(stderr, "Invalid free idx\n");
				return -1;
			}

			sqe = io_uring_get_sqe(ring);
			io_uring_prep_read_fixed(sqe, dev->fd, (void *)off,
						dev->block_size, off, 0);
			sqe->user_data = idx;
			mask &= ~idx_to_mask(idx);
		}
		if (to_submit) {
			ret = io_uring_submit(ring);
			if (ret != to_submit) {
				fprintf(stderr, "sqe submit failed: %d\n", ret);
				return -1;
			}
			inflight += to_submit;
			nr_left -= to_submit;
		}

		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			return -1;
		}

		io_uring_for_each_cqe(ring, head, cqe) {
			unsigned idx;
			size_t off;

			if (ret < 0) {
				fprintf(stderr, "wait completion %d\n", ret);
				return -1;
			}
			if (cqe->res != dev->block_size) {
				fprintf(stderr, "invalid result %i %i\n", cqe->res,
					(int)dev->block_size);
				return -1;
			}

			idx = cqe->user_data;
			if (mask & idx_to_mask(idx)) {
				fprintf(stderr, "invalid index\n");
				return -1;
			}

			mask |= idx_to_mask(idx);
			off = idx * dev->block_size;

			ret = verify_data(buf, off, off, dev->block_size);
			if (ret) {
				fprintf(stderr, "invalid data\n");
				return -1;
			}
			count++;
		}
		inflight -= count;
		io_uring_cq_advance(ring, count);
	}

	return 0;
}

static int test_read(struct io_uring *ring, struct t_dev *dev, struct t_buf *buf,
			  size_t f_off, size_t buf_off, size_t size)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_read_fixed(sqe, dev->fd, (void *)buf_off, size, f_off, 0);
	sqe->user_data = 42;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return -1;
	}
	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		return -1;
	}
	if (cqe->res != size) {
		fprintf(stderr, "invalid result %i %i\n", cqe->res, (int)size);
		return -1;
	}
	io_uring_cqe_seen(ring, cqe);

	return verify_data(buf, buf_off, f_off, size);
}

static int test_writes(struct io_uring *ring, struct t_dev *dev, struct t_buf *buf)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	const int nr_reqs = 16;
	size_t off = 0;
	int ret;

	ret = fill_device(dev, FILL_ZERO);
	if (ret) {
		fprintf(stderr, "fill_device failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	assert(dev->size % (nr_reqs * dev->block_size) == 0);

	while (off < dev->size) {
		for (int i = 0; i < nr_reqs; i++) {
			size_t io_size = dev->block_size;
			size_t buf_off = i * io_size;
			size_t f_off = off + buf_off;

			fill_buffer_pattern(buf->ptr + buf_off, io_size, f_off);
			sqe = io_uring_get_sqe(ring);
			io_uring_prep_write_fixed(sqe, dev->fd, (void *)buf_off,
						io_size, f_off, 0);
		}

		ret = io_uring_submit(ring);
		if (ret != nr_reqs) {
			fprintf(stderr, "sqe submit failed: %d\n", ret);
			return -1;
		}

		for (int i = 0; i < nr_reqs; i++) {
			ret = io_uring_wait_cqe(ring, &cqe);
			if (ret < 0) {
				fprintf(stderr, "wait completion %d\n", ret);
				return -1;
			}
			if (cqe->res != dev->block_size) {
				fprintf(stderr, "invalid result %i\n", cqe->res);
				return -1;
			}
			io_uring_cqe_seen(ring, cqe);
		}

		off += nr_reqs * dev->block_size;
	}

	return 0;
}

static int test_reads(struct io_uring *ring, struct t_dev *dev, struct t_buf *buf)
{
	size_t f_offs[] = { 0, 1, 2, 7 };
	size_t buf_offs[] = { 0, 1, 2, 7 };
	size_t io_sizes[] = { 1, 2, 3, 15, 7, 16, 32, 31 };
	int ret;

	ret = test_read(ring, dev, buf, 0, 0, dev->block_size);
	if (ret) {
		fprintf(stderr, "test_read() single failed\n");
		return ret;
	}

	for (int foff_idx = 0; foff_idx < ARRAY_SIZE(f_offs); foff_idx++) {
		for (int buf_idx = 0; buf_idx < ARRAY_SIZE(buf_offs); buf_idx++) {
			for (int size_idx = 0; size_idx < ARRAY_SIZE(io_sizes); size_idx++) {
				size_t f_off = f_offs[foff_idx] * dev->block_size;
				size_t buf_off = buf_offs[buf_idx] * dev->block_size;
				size_t size = io_sizes[size_idx] * dev->block_size;

				assert(buf_off + size <= buf->size);

				ret = test_read(ring, dev, buf, f_off, buf_off, size);
				if (ret) {
					fprintf(stderr, "test_read() failed ret=%i, foff=%li, off=%li, io=%li\n",
						ret, (long)f_off, (long)buf_off,
						(long)size);
					return ret;
				}
			}
		}
	}

	ret = test_parallel_reads(ring, dev, buf);
	if (ret) {
		fprintf(stderr, "test_parallel_reads() failed\n");
		return ret;
	}

	return 0;
}

static int test_device(const char *dev_name, bool defer_taskrun)
{
	struct io_uring_rsrc_update2 up;
	struct io_uring_regbuf_desc rd;
	struct io_uring ring;
	size_t max_io_size;
	struct t_dev dev;
	struct t_buf dmabuf;
	unsigned flags = 0;
	int ret;

	ret = open_device(&dev, dev_name);
	if (ret)
		return ret;
	dev.size = 1 << 20;

	ret = fill_device(&dev, FILL_PATTERN);
	if (ret) {
		fprintf(stderr, "fill_device failed %i\n", ret);
		return T_EXIT_FAIL;
	}

	max_io_size = 128 * dev.block_size;
	ret = create_udmabuf(&dmabuf, max_io_size);
	if (ret) {
		fprintf(stderr, "create_udmabuf failed\n");
		return ret;
	}

	ret = test_invalid_registration(&dev, &dmabuf);
	if (ret) {
		fprintf(stderr, "test_invalid_registration failed %i\n", ret);
		return ret;
	}

	if (defer_taskrun) {
		flags |= IORING_SETUP_COOP_TASKRUN;
		flags |= IORING_SETUP_SINGLE_ISSUER;
		flags |= IORING_SETUP_DEFER_TASKRUN;
	}

	ret = io_uring_queue_init(64, &ring, flags);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return -1;
	}

	ret = io_uring_register_buffers_sparse(&ring, 1);
	if (ret) {
		fprintf(stderr, "sparse buf table reg failed %i\n", ret);
		return ret;
	}

	memset(&up, 0, sizeof(up));
	up.data = uring_ptr_to_u64(&rd);
	up.nr = 1;
	up.resv = IORING_RSRC_UPDATE_EXTENDED;

	memset(&rd, 0, sizeof(rd));
	rd.target_fd = dev.fd;
	rd.dmabuf_fd = dmabuf.dmabuf_fd;
	rd.type = IO_REGBUF_TYPE_DMABUF;
	ret = register_buf(&ring, &up);
	if (ret) {
		fprintf(stderr, "Registration failed %i\n", ret);
		return ret;
	}

	ret = test_reads(&ring, &dev, &dmabuf);
	if (ret) {
		fprintf(stderr, "test_reads #1 failed %i\n", ret);
		return ret;
	}

	ret = test_writes(&ring, &dev, &dmabuf);
	if (ret) {
		fprintf(stderr, "test_writes failed %i\n", ret);
		return ret;
	}
	ret = read_verify(&dev);
	if (ret)
		return ret;

	ret = test_reads(&ring, &dev, &dmabuf);
	if (ret) {
		fprintf(stderr, "test_reads #2 failed %i\n", ret);
		return ret;
	}

	io_uring_queue_exit(&ring);
	close_udmabuf(&dmabuf);
	close_device(&dev);
	return 0;
}

int main(int argc, char *argv[])
{
	const char *dev_name = NULL;
	int ret;

	if (argc != 2) {
		fprintf(stderr, "Device not provided, skip\n");
		return T_EXIT_SKIP;
	}
	dev_name = argv[1];

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		fprintf(stderr, "Can't get page size\n");
		return T_EXIT_FAIL;
	}

	udmabuf_devfd = open("/dev/udmabuf", O_RDWR);
	if (udmabuf_devfd < 0) {
		printf("dmabuf is not available, skip\n");
		return T_EXIT_SKIP;
	}

	ret = test_device(dev_name, false);
	if (ret) {
		if (ret != T_EXIT_SKIP)
			fprintf(stderr, "test_device() failed\n");
		return ret;
	}

	ret = test_device(dev_name, true);
	if (ret) {
		if (ret != T_EXIT_SKIP)
			fprintf(stderr, "test_device() DEFER_TASKRUN failed\n");
		return ret;
	}

	close(udmabuf_devfd);
	return T_EXIT_PASS;
}
