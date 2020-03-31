/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#include "munit.h"

#include "logf.h"
#include "mem.h"
#include "macro.h"

// Dummy struct to test the different allocation primitives
struct complex_t {
	char buf[16];
	int int_field;
	unsigned long long int long_field;
	bool flag;
	double precision_number;
};

static void *
setup(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// Before every test, register a logger so that the logging functionality can run.
	logf_register(&logf_test_write, stderr);
	return NULL;
}

static void
tear_down(UNUSED void *fixture)
{
	// No clean-up needed for now
}

static MunitResult
test_freed_pointers_are_set_to_null(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// this defends against use after free, etc
	int *x = mem_alloc(sizeof(int));
	munit_assert_not_null(x);
	mem_free(x);
	munit_assert_null(x);

	struct complex_t *ptr = (struct complex_t *)mem_alloc(sizeof(struct complex_t));
	munit_assert_not_null(ptr);
	mem_free(ptr);
	munit_assert_null(ptr);
	return MUNIT_OK;
}

static MunitTest tests[] = {
	{
		"/freed-pointers-are-protected-against-use-after-free", /* name */
		test_freed_pointers_are_set_to_null,			/* test */
		setup,							/* setup */
		tear_down,						/* tear_down */
		MUNIT_TEST_OPTION_NONE,					/* options */
		NULL							/* parameters */
	},
	// Mark the end of the array with an entry where the test function is NULL
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

MunitSuite mem_suite = {
	"/mem",			/* name */
	tests,			/* tests */
	NULL,			/* suites */
	1,			/* iterations */
	MUNIT_SUITE_OPTION_NONE /* options */
};
