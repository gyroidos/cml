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
 * @file hex.bounds_test.c
 *
 * Standalone bounds-safety enforcement tests for hex.c.
 *
 * Must be compiled with the swiftlang Clang fork and -fbounds-safety.
 * Uses fork() to test that out-of-bounds access traps at runtime.
 * Dynamic (malloc'd) buffer sizes force runtime checks — the compiler
 * cannot catch these statically.
 *
 * Build:
 *   $BS_CLANG $CFLAGS -fbounds-safety -c hex.bounds_test.c
 *   $BS_CLANG -o hex.bounds_test hex.bounds_test.o hex.o mem.o logf.o ...
 *   ./hex.bounds_test
 */

#include "bounds_test.h"
#include "hex.h"
#include "mem.h"

#ifdef BOUNDS_SAFETY_ENABLED

/* Prevent the compiler from constant-folding sizes. */
static volatile size_t dynamic_2 = 2;
static volatile size_t dynamic_4 = 4;

/* Sink to prevent optimising away the call. */
static volatile int sink;

/*
 * Each violation allocates a buffer of real size N, forges bounds of size N,
 * then calls a hex function claiming size > N.  The runtime bounds check at
 * the call site should trap.
 */

static void
violate_hex_to_bin_output(void)
{
	size_t real = dynamic_2;
	uint8_t *out = (uint8_t *)mem_alloc0(real);
	/* out has 2 bytes, but we claim outlen=4 → trap */
	sink = convert_hex_to_bin("deadbeef", 8, out, dynamic_4);
}

static void
violate_hex_to_bin_input(void)
{
	size_t real = dynamic_4;
	char *in = (char *)mem_alloc0(real);
	memcpy(in, "dead", 4);
	uint8_t *out = (uint8_t *)mem_alloc0(real);
	/* in has 4 bytes, but we claim inlen=8 → trap */
	sink = convert_hex_to_bin(in, 8, out, dynamic_4);
}

static void
violate_bin_to_hex_output(void)
{
	uint8_t in_data[4] = { 0xde, 0xad, 0xbe, 0xef };
	size_t real = dynamic_2;
	uint8_t *out = (uint8_t *)mem_alloc0(real);
	/* out has 2 bytes, but we claim outlen=9 → trap */
	sink = convert_bin_to_hex(in_data, 4, out, 9);
}

static void
violate_bin_to_hex_input(void)
{
	size_t real = dynamic_2;
	uint8_t *in = (uint8_t *)mem_alloc0(real);
	in[0] = 0xde;
	in[1] = 0xad;
	uint8_t *out = (uint8_t *)mem_alloc0(9);
	/* in has 2 bytes, but we claim inlen=4 → trap */
	sink = convert_bin_to_hex(in, dynamic_4, out, 9);
}

static void
violate_bin_to_hex_new_input(void)
{
	size_t real = dynamic_2;
	uint8_t *bin = (uint8_t *)mem_alloc0(real);
	bin[0] = 0xde;
	bin[1] = 0xad;
	/* bin has 2 bytes, but we claim length=4 → trap */
	sink = (intptr_t)convert_bin_to_hex_new(bin, dynamic_4);
}

static struct bounds_test_case cases[] = { { "hex_to_bin OOB output", violate_hex_to_bin_output },
					   { "hex_to_bin OOB input", violate_hex_to_bin_input },
					   { "bin_to_hex OOB output", violate_bin_to_hex_output },
					   { "bin_to_hex OOB input", violate_bin_to_hex_input },
					   { "bin_to_hex_new OOB input",
					     violate_bin_to_hex_new_input },
					   { NULL, NULL } };

#endif /* BOUNDS_SAFETY_ENABLED */

BOUNDS_TEST_MAIN("hex.bounds_test", cases)
