/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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
 * @file file.bounds_test.c
 *
 * Standalone bounds-safety enforcement tests for file.c.
 *
 * Must be compiled with the swiftlang Clang fork and -fbounds-safety.
 * Uses fork() to test that out-of-bounds access traps at runtime.
 * Dynamic (malloc'd) buffer sizes force runtime checks — the compiler
 * cannot catch these statically.
 *
 * Build:
 *   make bounds_test CC=/path/to/bs-clang
 */

#include "bounds_test.h"
#include "file.h"
#include "mem.h"

#ifdef BOUNDS_SAFETY_ENABLED

/* Prevent the compiler from constant-folding sizes. */
static volatile size_t dynamic_4 = 4;
static volatile size_t dynamic_16 = 16;

/* Sink to prevent optimising away the call. */
static volatile int sink;

/*
 * Each violation allocates a buffer of real size N, then calls a file
 * function claiming size > N.  The runtime bounds check at the call
 * site should trap.
 */

static void
violate_file_write(void)
{
	char tmppath[] = "/tmp/file_bounds_test_XXXXXX";
	int fd = mkstemp(tmppath);
	if (fd < 0)
		_exit(2);
	close(fd);

	size_t real = dynamic_4;
	char *buf = (char *)mem_alloc0(real);
	memcpy(buf, "test", 4);
	/* buf has 4 bytes, but we claim len=16 → trap */
	sink = file_write(__unsafe_null_terminated_from_indexable(tmppath), buf, dynamic_16);

	unlink(tmppath);
}

static void
violate_file_read(void)
{
	/* Create a temp file with some content. */
	char tmppath[] = "/tmp/file_bounds_test_XXXXXX";
	int fd = mkstemp(tmppath);
	if (fd < 0)
		_exit(2);
	write(fd, "0123456789abcdef", 16);
	close(fd);

	size_t real = dynamic_4;
	char *buf = (char *)mem_alloc0(real);
	/* buf has 4 bytes, but we claim len=16 → trap */
	sink = file_read(__unsafe_null_terminated_from_indexable(tmppath), buf, dynamic_16);

	unlink(tmppath);
}

static struct bounds_test_case cases[] = { { "file_write OOB buf", violate_file_write },
					   { "file_read OOB buf", violate_file_read },
					   { NULL, NULL } };

#endif /* BOUNDS_SAFETY_ENABLED */

BOUNDS_TEST_MAIN("file.bounds_test", cases)
