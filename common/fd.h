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

/**
 * @file fd.h
 *
 * Provides utility functions for file descriptors,
 * such as reading from and writing to them.
 */

#ifndef FD_H
#define FD_H

#include <stddef.h>

/**
 * Writes the given buffer of the given length to the given file descriptor,
 * looping over write() as necessary.
 *
 * @param fd the file descriptor to write to
 * @param buf pointer to the buffer
 * @param len length of the buffer
 */
int
fd_write(const int fd, const char *buf, size_t len);

/*
 * Reads the specified amount of bytes from the given file descriptor to the given buffer,
 * looping over read() as necessary.
 *
 * @param fd the file descriptor to read from
 * @param buf pointer to the buffer
 * @param number of bytes to read (must fit into given buffer!)
 */
int
fd_read(int fd, char *buf, size_t len);

/*
 * Reads blockwise from the given file descriptor to the given buffer, calling fd_read
 * internally.
 *
 * @param fd The file descriptor to read from
 * @param buf The buffer to read into
 * @param Number of bytes to read
 * @param block_size Size of the blocks to read
 * @param alignment Alignment to read with
 *
 * @return number of bytes read on success, otherwise -1
 */
ssize_t
fd_read_blockwise(int fd, void *buf, size_t len, size_t block_size, size_t alignment);

/**
 * Makes the given file descriptor non-blocking by setting the O_NONBLOCK flag.
 *
 * @param fd the file descriptor
 * @return 0 on success, -1 on error
 */
int
fd_make_non_blocking(int fd);

/**
 * Checks if the given fd is closed
 *
 * @param fd the file discriptor
 * @return 1 if fd is closed, 0 if fd is open and ready to use
 */
int
fd_is_closed(int fd);

#endif // FD_H
