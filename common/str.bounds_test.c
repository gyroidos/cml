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
 * @file str.bounds_test.c
 *
 * Standalone bounds-safety enforcement tests for str.c.
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
#include "str.h"
#include "mem.h"

#ifdef BOUNDS_SAFETY_ENABLED

/*
 * str_t is an opaque (incomplete) type here.  Upstream -fbounds-safety defaults
 * local pointers to __bidi_indexable, which requires a known pointee size.
 * Use __single explicitly to stay compatible with both upstream and our local
 * compiler patch that infers __single automatically for incomplete types.
 */
#define STR_LOCAL __single

/* Prevent the compiler from constant-folding sizes. */
static volatile size_t dynamic_4 = 4;
static volatile size_t dynamic_16 = 16;

/* Sink to prevent optimising away the call. */
static volatile int sink;

/*
 * Each violation allocates a buffer of real size N, then calls a str
 * function claiming size > N.  The runtime bounds check at the call
 * site should trap.
 */

static void
violate_str_append_len(void)
{
	str_t *STR_LOCAL s = str_new("");
	size_t real = dynamic_4;
	char *buf = (char *)mem_alloc0(real);
	memset(buf, 'A', real);
	/* buf has 4 bytes, but we claim len=16 -> trap */
	str_append_len(s, buf, dynamic_16);
	sink = (int)str_length(s);
	str_free(s, true);
}

static void
violate_str_assign_len(void)
{
	str_t *STR_LOCAL s = str_new("hello");
	size_t real = dynamic_4;
	char *buf = (char *)mem_alloc0(real);
	memset(buf, 'B', real);
	/* buf has 4 bytes, but we claim len=16 -> trap */
	str_assign_len(s, buf, dynamic_16);
	sink = (int)str_length(s);
	str_free(s, true);
}

static void
violate_str_insert_len(void)
{
	str_t *STR_LOCAL s = str_new("hello");
	size_t real = dynamic_4;
	char *buf = (char *)mem_alloc0(real);
	memset(buf, 'C', real);
	/* buf has 4 bytes, but we claim len=16 -> trap */
	str_insert_len(s, 0, buf, dynamic_16);
	sink = (int)str_length(s);
	str_free(s, true);
}

static void
violate_str_hexdump_new(void)
{
	size_t real = dynamic_4;
	unsigned char *buf = (unsigned char *)mem_alloc0(real);
	memset(buf, 0xAA, real);
	/* buf has 4 bytes, but we claim len=16 -> trap */
	str_t *STR_LOCAL s = str_hexdump_new(buf, dynamic_16);
	sink = (int)str_length(s);
	str_free(s, true);
}

static struct bounds_test_case cases[] = { { "str_append_len OOB buf", violate_str_append_len },
					   { "str_assign_len OOB buf", violate_str_assign_len },
					   { "str_insert_len OOB buf", violate_str_insert_len },
					   { "str_hexdump_new OOB buf", violate_str_hexdump_new },
					   { NULL, NULL } };

#endif /* BOUNDS_SAFETY_ENABLED */

BOUNDS_TEST_MAIN("str.bounds_test", cases)
