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
 * @file protobuf-text.bounds_test.c
 *
 * Standalone bounds-safety enforcement tests for protobuf-text.c.
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
#include "protobuf-text.h"
#include "mem.h"

#ifdef BOUNDS_SAFETY_ENABLED

/* Prevent the compiler from constant-folding sizes. */
static volatile size_t dynamic_4 = 4;
static volatile size_t dynamic_16 = 16;

/* Sink to prevent optimising away the call. Written-only on purpose (the
 * volatile store is the side effect); marked unused for -Wunused-but-set-global
 * under newer Clang. */
static volatile void *sink __attribute__((unused));

/*
 * Each violation allocates a buffer of real size N, then calls a
 * protobuf_text function claiming size > N.  The runtime bounds check
 * at the call site should trap before the function body runs.
 *
 * We pass a bogus descriptor pointer since the trap fires before the
 * function is entered.
 */

static void
violate_protobuf_message_new_from_buf(void)
{
	size_t real = dynamic_4;
	uint8_t *buf = (uint8_t *)mem_alloc0(real);
	memset(buf, 'A', real);
	/* buf has 4 bytes, but we claim buflen=16 -> trap */
	sink = protobuf_message_new_from_buf(
		buf, dynamic_16,
		__unsafe_forge_single(const ProtobufCMessageDescriptor *, (void *)0x1));
}

static struct bounds_test_case cases[] = { { "protobuf_message_new_from_buf OOB buf",
					     violate_protobuf_message_new_from_buf },
					   { NULL, NULL } };

#endif /* BOUNDS_SAFETY_ENABLED */

BOUNDS_TEST_MAIN("protobuf-text.bounds_test", cases)
