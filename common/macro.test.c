/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */
#include <limits.h>

#include "munit.h"

#include "logf.h"
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

__attribute__((noinline)) static uint32_t
id(uint32_t x)
{
	// just a dummy identity function to make sure
	// that the macros handle functions correctly
	return x;
}

static MunitResult
test_integer_overflow_macros_perform_correct_ops(UNUSED const MunitParameter params[],
						 UNUSED void *data)
{
	// addition macro correctly does addition
	int res = ADD_WITH_OVERFLOW_CHECK(5 * 1000, 700 + 89);
	munit_assert_int(res, ==, 5789);

	int b = 4500;
	res = ADD_WITH_OVERFLOW_CHECK(-4000 - 1000 + 2 * 250, b);
	munit_assert_int(res, ==, 0);

	uint64_t c = ADD_WITH_OVERFLOW_CHECK(res, b);
	munit_assert_uint64(c, ==, 4500);

	int d = ADD_WITH_OVERFLOW_CHECK(id(7070), -70);
	munit_assert_int(d, ==, 7000);

	// subtraction macro correctly does subtraction
	uint32_t e = SUB_WITH_OVERFLOW_CHECK(id(900), -50);
	munit_assert_uint32(e, ==, 950);

	uint32_t f = SUB_WITH_OVERFLOW_CHECK(id(7000), id(7000));
	munit_assert_uint32(f, ==, 0);

	int g = SUB_WITH_OVERFLOW_CHECK(ADD_WITH_OVERFLOW_CHECK(0, 50),
					ADD_WITH_OVERFLOW_CHECK(50 * 50, 10 * 2 * 5));
	munit_assert_int(g, ==, -2550);

	// multiplication macro correctly does multiplication
	int h = MUL_WITH_OVERFLOW_CHECK(70, -10);
	munit_assert_int(h, ==, -700);

	uint64_t i = MUL_WITH_OVERFLOW_CHECK(h, ADD_WITH_OVERFLOW_CHECK(20, 30));
	munit_assert_uint64(i, ==, -35000);

	// final randomized test
	for (size_t i = 0; i < 1000; i++) {
		int x = munit_rand_int_range(-(1 << 14), (1 << 14));
		int y = munit_rand_int_range(-(1 << 14), (1 << 14));

		int add = ADD_WITH_OVERFLOW_CHECK(x, y);
		int sub = SUB_WITH_OVERFLOW_CHECK(x, y);
		int mul = MUL_WITH_OVERFLOW_CHECK(x, y);

		munit_assert_int(add, ==, (x + y));
		munit_assert_int(sub, ==, (x - y));
		munit_assert_int(mul, ==, (x * y));
	}
	return MUNIT_OK;
}

static MunitResult
test_addition_macro_catches_overflow(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int res = ADD_WITH_OVERFLOW_CHECK(INT_MAX - 10, 0xdead);

	// should not be reached
	(void)res; // silence warnings for unusued variable
	return MUNIT_FAIL;
}

static MunitResult
test_subtraction_macro_catches_overflow(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int res = SUB_WITH_OVERFLOW_CHECK(INT_MIN, 0xbeef);

	// should not be reached
	(void)res; // silence warnings for unusued variable
	return MUNIT_FAIL;
}

static MunitResult
test_multiplication_macro_catches_overflow(UNUSED const MunitParameter params[], UNUSED void *data)
{
	int res = MUL_WITH_OVERFLOW_CHECK((1 << 20), (1 << 20));

	// should not be reached
	(void)res; // silence warnings for unusued variable
	return MUNIT_FAIL;
}

static MunitTest tests[] = {
	{
		"/integer overflow checking macros do correctly +,-.*", /* name */
		test_integer_overflow_macros_perform_correct_ops,	/* test */
		setup,							/* setup */
		tear_down,						/* tear_down */
		MUNIT_TEST_OPTION_NONE,					/* options */
		NULL							/* parameters */
	},
	{
		"/addition macro catches overflow",			 /* name */
		test_addition_macro_catches_overflow,			 /* test */
		setup,							 /* setup */
		tear_down,						 /* tear_down */
		MUNIT_TEST_OPTION_NONE | MUNIT_TEST_OPTION_RECV_SIGABRT, /* options */
		NULL							 /* parameters */
	},
	{
		"/subtraction macro catches overflow",			 /* name */
		test_subtraction_macro_catches_overflow,		 /* test */
		setup,							 /* setup */
		tear_down,						 /* tear_down */
		MUNIT_TEST_OPTION_NONE | MUNIT_TEST_OPTION_RECV_SIGABRT, /* options */
		NULL							 /* parameters */
	},
	{
		"/multiplication macro catches overflow",		 /* name */
		test_multiplication_macro_catches_overflow,		 /* test */
		setup,							 /* setup */
		tear_down,						 /* tear_down */
		MUNIT_TEST_OPTION_NONE | MUNIT_TEST_OPTION_RECV_SIGABRT, /* options */
		NULL							 /* parameters */
	},
	// Mark the end of the array with an entry where the test function is NULL
	{ NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

MunitSuite macro_suite = {
	"/macro",		/* name */
	tests,			/* tests */
	NULL,			/* suites */
	1,			/* iterations */
	MUNIT_SUITE_OPTION_NONE /* options */
};
