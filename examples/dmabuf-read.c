#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/mman.h>
#include <linux/mman.h>
#include <sys/ioctl.h>
#include <linux/memfd.h>
#include <linux/dma-buf.h>
#include <linux/udmabuf.h>

#include "liburing.h"
#include "helpers.h"

struct buf_udmabuf {
	void *ptr;
	size_t size;
	int dmabuf_fd;
	int memfd;
};

static void create_udmabuf(struct buf_udmabuf *b, size_t size)
{
	struct udmabuf_create create;
	int memfd, dmabuf_fd;
	void *p;
	int ret, devfd;

	devfd = open("/dev/udmabuf", O_RDWR);
	if (devfd < 0)
		t_error(1, devfd, "Failed to open udmabuf dev");

	memfd = memfd_create("udmabuf-test", MFD_ALLOW_SEALING);
	if (memfd < 0)
		t_error(1, memfd, "Failed to open udmabuf dev");

	ret = fcntl(memfd, F_ADD_SEALS, F_SEAL_SHRINK);
	if (ret < 0)
		t_error(1, 0, "Failed to set seals");

	ret = ftruncate(memfd, size);
	if (ret == -1)
		t_error(1, 0, "Failed to resize udmabuf");

	memset(&create, 0, sizeof(create));
	create.memfd = memfd;
	create.offset = 0;
	create.size = size;
	dmabuf_fd = ioctl(devfd, UDMABUF_CREATE, &create);
	if (dmabuf_fd < 0)
		t_error(1, dmabuf_fd, "Failed to create udmabuf");

	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
			dmabuf_fd, 0);
	if (p == MAP_FAILED)
		t_error(1, 0, "Failed to mmap udmabuf");

	close(devfd);
	b->size = size;
	b->dmabuf_fd = dmabuf_fd;
	b->memfd = memfd;
	b->ptr = p;
}

struct io_uring_reg_buffer {
	__aligned_u64		iov_uaddr;
	__s32			target_fd;
	__s32			dmabuf_fd;
};

enum io_uring_rsrc_reg_flags {
       IORING_RSRC_F_EXTENDED_UPDATE           = 1,
};

int do_register(struct io_uring *ring, unsigned int opcode,
			      const void *arg, unsigned int nr_args);


int main(int argc, char *argv[])
{
	struct buf_udmabuf udmabuf;
	char *buf;
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int ret, fd;
	long i;
	long io_size, io_offset;
	long buf_size = 8 * 4096;
	long file_offset = 512;

	if (argc != 3) {
		fprintf(stderr, "invalid params\n");
		exit(1);
	}

	io_offset = strtoul(argv[1], NULL, 0);
	io_size = strtoul(argv[2], NULL, 0);
	printf("offset %i, size %i\n", (int)io_offset, (int)io_size);

	buf = t_aligned_alloc(4096, io_size);
	if (!buf)
		t_error(1, 0, "alloc failed");
	memset(buf, 0xfe, io_size);

	if (0) {
		for (i = 0; i < io_size; i++)
			buf[i] = (1 + i / 512);

		fd = open("/dev/nvme0n1", O_DIRECT | O_RDWR);
		if (fd < 0)
			t_error(1, 0, "open failed");

		ret = pwrite(fd, buf, io_size, 0);
		if (ret != io_size)
			t_error(1, 0, "pread fail %i", ret);


		exit(1);
		return 0;
	}

	// target file
	fd = open("/dev/nvme0n1", O_DIRECT | O_RDONLY);
	if (fd < 0)
		t_error(1, 0, "open failed");

	// read data for validation
	ret = pread(fd, buf, io_size, file_offset);
	if (ret != io_size)
		t_error(1, 0, "pread fail %i", ret);

	ret = io_uring_queue_init(8, &ring, 0);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	create_udmabuf(&udmabuf, buf_size);

	ret = io_uring_register_buffers_sparse(&ring, 1);
	if (ret)
		t_error(1, 0, "sparse failed\n");

	// registers the entire dmabuf
	struct iovec iov = { .iov_base = NULL, .iov_len = 0, };
	struct io_uring_reg_buffer rb = {};
	rb.iov_uaddr = (unsigned long)&iov;
	rb.target_fd = fd;
	rb.dmabuf_fd = udmabuf.dmabuf_fd;
	struct io_uring_rsrc_update2 up = {
		.data = (unsigned long)&rb,
		.nr = 1,
		.resv = IORING_RSRC_F_EXTENDED_UPDATE,
	};

	ret = do_register(&ring, IORING_REGISTER_BUFFERS_UPDATE, &up, sizeof(up));
	if (ret != 1)
		t_error(0, 1, "reg failed\n");

	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_read_fixed(sqe, fd, (void *)io_offset, io_size, file_offset, 0);
	sqe->user_data = 42;

	ret = io_uring_submit(&ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		return 1;
	}
	ret = io_uring_wait_cqe(&ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		return 1;
	}

	fprintf(stderr, "CQE data %li(%lx), res %i, flags %i(%x)\n",
		(long)cqe->user_data, (long)cqe->user_data,
		cqe->res,
		cqe->flags, cqe->flags);
	
	if (cqe->res != io_size) {
		fprintf(stderr, "invalid result\n");
		return 1;
	}
	io_uring_cqe_seen(&ring, cqe);

	for (i = 0; i < io_size; i++) {
		int a = buf[i];
		int b = ((char*)udmabuf.ptr)[i + io_offset];

		if (a != b) {
			fprintf(stderr, "mismatch %lu: %u %u\n", i, a, b);
			break;
		}
	}

	io_uring_queue_exit(&ring);
	return 0;
}

