/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#include "fd.h"

#include "common/macro.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int
fd_write(int fd, const char *buf, size_t len)
{
	size_t remain = len;

	while (remain > 0) {
		int ret;

		ret = write(fd, buf, remain);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				TRACE_ERRNO("Writing to fd %d: Blocked, retrying...", fd);
				continue;
			}
			return ret;
		}

		remain -= ret;
		buf += ret;
		TRACE("Writing to fd %d: Wrote %d bytes, %lu bytes remaining.", fd, ret, remain);

		if (ret == 0)
			break;
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
			}
			return ret;
		}

		remain -= ret;
		buf += ret;
		TRACE("Reading from fd %d: Read %d bytes, %lu bytes remaining.", fd, ret, remain);

		if (ret == 0)
			break;
	}

	return len - remain;
}

int
fd_make_non_blocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (-1 == flags)
	{
		WARN_ERRNO("Failed to get flags for fd %d.", fd);
		return flags;
	}

	flags |= O_NONBLOCK;
	int res = fcntl(fd, F_SETFL, flags);
	if (-1 == res)
	{
		WARN_ERRNO("Failed to set flags for socket %d.", fd);
	}

	return res;
}
