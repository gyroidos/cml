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

/** @file mem.test.c
 *
 *  (Dummy) Unit Test for mem.c
 *  mem.c serves only as a wrapper, including aborts, for memory operations.
 *  Because of this, no exhaustive tests are elaborated.
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "logf.h"
#include "mem.h"
#include "macro.h"


/**
  * Sample test structure for the Unit Test
  */
typedef struct test_strct {
	int x;
	char *y;
	double z;
} test_strct;


/**
  * Helper function to test mem_vprintf
  *
  * @param n number of variable arguments
  * @return char-pointer to the vprintf output
  */
static char *test_vprintf(int n, ...);

/**
  * All functions from mem.c are basically tested in this function.
  */
int
main(int argc, char **argv)
{
	test_strct *tst1;
	test_strct *tst2;

	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: mem.test.c");

	tst1 = mem_new(test_strct, 1);

	tst1->x = 1;

	DEBUG("Check if mem_new allocates correctly");
	DEBUG("tst1.x %d", tst1->x);
	ASSERT(tst1->x == 1);

	tst2 = mem_new0(test_strct, 1);

	DEBUG("Check if mem_new0 NULLs correctly");
	DEBUG("tst2.x %d, tst2.y %s, tst2.z %f", tst2->x, tst2->y, tst2->z);
	ASSERT(tst2->x == 0 && tst2->y == NULL && tst2->z == 0);

	tst2->z = 2.0;
	tst2 = mem_renew(test_strct, tst2, 2);

	DEBUG("Check if mem_renew preserves former allocated struct");
	DEBUG("tst2.x %d, tst2.y %s, tst2.z %f", tst2->x, tst2->y, tst2->z);
	ASSERT(tst2->x == 0 && tst2->y == NULL && tst2->z == 2.0);

	tst2[1].x = 1;
	tst2[0].y = "TEST";
	tst2[1].y = mem_strdup(tst2->y);

	DEBUG("Check if mem_strdup duplicates correctly");
	DEBUG("tst2[0].y %s, tst2[1].y %s", tst2[0].y, tst2[1].y);
	ASSERT(!strcmp(tst2[0].y, "TEST") && !strcmp(tst2[1].y, tst2[0].y));

	tst2[0].y = mem_strndup(tst2[1].y, 10);
	tst2[1].y = mem_strndup(tst2[0].y, 2);

	DEBUG("Check if mem_strndup cuts/ends properly");
	DEBUG("tst2[0].y %s, tst2[1].y %s", tst2[0].y, tst2[1].y);
	ASSERT(!strcmp(tst2[0].y, "TEST") && !strcmp(tst2[1].y, "TE"));

	tst1->y = mem_printf("TEST %d and %d", 1, 2);

	DEBUG("Check mem_printf functionality");
	DEBUG("tst1->y %s", tst1->y);
	ASSERT(!strcmp(tst1->y, "TEST 1 and 2"));

	tst1->y = test_vprintf(2, 4.0, 5.0);

	DEBUG("Test mem_vprintf functionality");
	DEBUG("tst1->y %s", tst1->y);
	ASSERT(!strcmp(tst1->y, "TEST 4.000000 and 5.000000"));

	mem_free(tst1->y);
	mem_free(tst1);
	mem_free(tst2[0].y);
	mem_free(tst2[1].y);
	mem_free(tst2);

	return 0;
}

static char *test_vprintf(int n, ...)
{
	va_list vl;
	va_start(vl, n);
	int i;
	return mem_vprintf("TEST %f and %f", vl);
}
