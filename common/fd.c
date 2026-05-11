/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 (GPL 2), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 * Contact Information:
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "mem.h"
#include "macro.h"
#include "fd.h"

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

ssize_t
fd_write(int fd, const char *buf, ssize_t len)
{
	size_t remain = len;

	while (remain > 0) {
		int ret;

		ret = write(fd, buf, remain);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				TRACE_ERRNO("Writing to fd %d: Blocked, retrying...", fd);
				continue;
			} else if (errno == EINTR) {
				TRACE("Reading from fd %d: Interrupted, retrying...", fd);
				continue;
			}

			ERROR_ERRNO("Failed to write to fd %d", fd);
			return ret;
		}

		remain -= ret;
		buf += ret;
		TRACE("Writing to fd %d: Wrote %d bytes, %zu bytes remaining.", fd, ret, remain);

		if (ret == 0)
			break;
	}

	if (0 != fsync(fd)) {
		TRACE("Could not sync fd %d", fd);
	}

	return len - remain;
}

int
fd_read(int fd, char *buf, size_t len)
{
	size_t remain = len;

	while (remain > 0) {
		int ret;

		ret = read(fd, buf, remain);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				TRACE("Reading from fd %d: Blocked, retrying...", fd);
				continue;
			} else if (errno == EINTR) {
				TRACE("Reading from fd %d: Interrupted, retrying...", fd);
				continue;
			}

			return ret;
		}

		remain -= ret;
		buf += ret;
		TRACE("Reading from fd %d: Read %d bytes, %zu bytes remaining.", fd, ret, remain);

		if (ret == 0)
			break;
	}

	return len - remain;
}

ssize_t
fd_read_blockwise(int fd, void *buf, size_t len, size_t block_size, size_t alignment)
{
	ASSERT(buf);
	ASSERT(fd > 0);
	ASSERT(block_size > 0);
	ASSERT(alignment > 0);

	void *fragment_buf = NULL;
	void *p = NULL;
	ssize_t ret = -1;

	size_t fragment_len = len % block_size;
	size_t blocks_len = len - fragment_len;

	if ((size_t)buf & (alignment - 1)) {
		int r = posix_memalign(&p, alignment, len);
		if (r) {
			ERROR("posix_memalign returned %d", r);
			return -1;
		}
	} else {
		p = buf;
	}

	if (fd_read(fd, p, blocks_len) != (int)blocks_len) {
		goto out;
	}

	if (fragment_len) {
		int r = posix_memalign(&fragment_buf, alignment, block_size);
		if (r) {
			ERROR("posix_memalign returned %d", r);
			goto out;
		}
		if (fd_read(fd, fragment_buf, block_size) < (int)fragment_len) {
			goto out;
		}

		memcpy((char *)p + blocks_len, fragment_buf, fragment_len);
	}
	ret = len;
out:
	mem_free(fragment_buf);
	if (p != buf) {
		if (ret != -1) {
			memcpy(buf, p, len);
		}
		mem_free(p);
	}
	return ret;
}

int
fd_make_non_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (-1 == flags) {
		WARN_ERRNO("Failed to get flags for fd %d.", fd);
		return flags;
	}

	flags |= O_NONBLOCK;
	int res = fcntl(fd, F_SETFL, flags);
	if (-1 == res) {
		WARN_ERRNO("Failed to set flags for socket %d.", fd);
	}

	return res;
}

int
fd_is_closed(int fd)
{
	errno = 0;
	return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}
