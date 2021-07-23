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
test_can_allocate_primitives_and_structs(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// we can alloc memory and modify it
	int *ptr_int = mem_alloc(sizeof(int));
	munit_assert_not_null(ptr_int);

	*ptr_int = 0xc0ffe;
	munit_assert_int(*ptr_int, ==, 0xc0ffe);
	mem_free0(ptr_int);

	// we can calloc memory and modify it
	ptr_int = mem_alloc0(sizeof(int));
	munit_assert_not_null(ptr_int);
	munit_assert_int(*ptr_int, ==, 0);

	*ptr_int = 0xb0b0;
	munit_assert_int(*ptr_int, ==, 0xb0b0);
	mem_free0(ptr_int);

	// we can alloc new objects and modify it
	struct complex_t *ptr_struct = mem_new(struct complex_t, 1);
	munit_assert_not_null(ptr_struct);

	ptr_struct->flag = true;
	ptr_struct->int_field = 0xdead;
	ptr_struct->long_field = 0xbeef;
	ptr_struct->buf[10] = 'V';
	munit_assert_true(ptr_struct->flag);
	munit_assert_char(ptr_struct->buf[10], ==, 'V');
	munit_assert_int(ptr_struct->int_field, ==, 0xdead);
	munit_assert_ullong(ptr_struct->long_field, ==, 0xbeef);
	mem_free0(ptr_struct);

	// we can calloc new objects and modify them
	ptr_struct = mem_new0(struct complex_t, 1);
	munit_assert_not_null(ptr_struct);

	munit_assert_false(ptr_struct->flag);
	munit_assert_int(ptr_struct->int_field, ==, 0);
	munit_assert_ullong(ptr_struct->long_field, ==, 0);
	munit_assert_double_equal(ptr_struct->precision_number, 0, 9);
	for (size_t i = 0; i < sizeof(ptr_struct->buf); i++)
		munit_assert_char(ptr_struct->buf[i], ==, 0);
	mem_free0(ptr_struct);

	return MUNIT_OK;
}

static MunitResult
test_can_realloc_primitives_and_structs(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// we can realloc primitives and the old content is preserved
	int *ptr_int = mem_alloc(sizeof(int));
	*ptr_int = 0x666;
	ptr_int = mem_realloc(ptr_int, 1024 * sizeof(int));
	munit_assert_not_null(ptr_int);
	munit_assert_int(*ptr_int, ==, 0x666);

	// we can realloc structs and the old content is preserved
	struct complex_t *ptr_struct = mem_new(struct complex_t, 1);
	ptr_struct->buf[15] = 'Z';
	ptr_struct = mem_renew(struct complex_t, ptr_struct, 1024);
	munit_assert_not_null(ptr_struct);
	munit_assert_char(ptr_struct->buf[15], ==, 'Z');

	mem_free0(ptr_int);
	mem_free0(ptr_struct);

	return MUNIT_OK;
}

static MunitResult
test_strdup_strndup(UNUSED const MunitParameter params[], UNUSED void *data)
{
	const char *a = "hehe, someone is actually reading!\n\t\r";

	// strdup duplicates a string
	char *b = mem_strdup(a);
	munit_assert_not_null(b);
	munit_assert_string_equal(a, b);

	// b is in a different memory chunk than a and can be modified
	b[8] = '\0';
	munit_assert_string_not_equal(a, b);
	mem_free0(b);

	// strndup copies full string
	char *c = mem_strndup(a, strlen(a));
	munit_assert_not_null(c);
	munit_assert_string_equal(a, c);
	mem_free0(c);

	// strndup cuts
	c = mem_strndup(a, 7);
	munit_assert_not_null(c);
	munit_assert_string_not_equal(a, c);
	munit_assert_string_equal("hehe, s", c);
	mem_free0(c);

	// strndup does not overflow
	c = mem_strndup(a, 1024);
	munit_assert_not_null(c);
	munit_assert_string_equal(a, c);
	mem_free0(c);

	return MUNIT_OK;
}

#define TEST_MEM_MEMCPY_BUF_SIZE 257
static MunitResult
test_mem_memcpy(UNUSED const MunitParameter params[], UNUSED void *data)
{
	unsigned char *a = mem_alloc(TEST_MEM_MEMCPY_BUF_SIZE);
	munit_rand_memory(TEST_MEM_MEMCPY_BUF_SIZE, a);

	// memcpy duplicates memory
	unsigned char *b = mem_memcpy(a, TEST_MEM_MEMCPY_BUF_SIZE);
	munit_assert_not_null(b);
	munit_assert_memory_equal(TEST_MEM_MEMCPY_BUF_SIZE, a, b);

	// b is in a different memory chunk than a and can be modified
	b[8] = ~b[8];
	munit_assert_memory_not_equal(TEST_MEM_MEMCPY_BUF_SIZE, a, b);
	mem_free0(b);

	// memcpy copies entire memory
	unsigned char *c = mem_memcpy(a, TEST_MEM_MEMCPY_BUF_SIZE);
	munit_assert_not_null(c);
	munit_assert_memory_equal(TEST_MEM_MEMCPY_BUF_SIZE, a, c);
	mem_free0(c);

	// memcpy cuts
	c = mem_memcpy(a, (TEST_MEM_MEMCPY_BUF_SIZE / 2) + 1);
	munit_assert_not_null(c);
	munit_assert_memory_not_equal(TEST_MEM_MEMCPY_BUF_SIZE, a, c);
	munit_assert_memory_equal(129, a, c);
	mem_free0(c);

	return MUNIT_OK;
}

static MunitResult
test_printf_dynamic_buffer(UNUSED const MunitParameter params[], UNUSED void *data)
{
	struct complex_t *ptr = mem_new0(struct complex_t, 1);

	ptr->int_field = 6060;
	memcpy(ptr->buf, "trustme.", sizeof("trustme."));
	ptr->long_field = 70550;

	// mem_printf allocates heap memory for the buffer and applies the format
	char *buf = mem_printf("Hey there, %s\n You got %d/%llu", ptr->buf, ptr->int_field,
			       ptr->long_field);
	munit_assert_not_null(buf);
	munit_assert_string_equal(buf, "Hey there, trustme.\n You got 6060/70550");

	//TODO: test against format string attacks. The %n modifier should be killed.

	mem_free0(buf);
	mem_free0(ptr);

	return MUNIT_OK;
}

static MunitResult
test_freed_pointers_are_set_to_null(UNUSED const MunitParameter params[], UNUSED void *data)
{
	// this defends against use after free, etc

	// for primitives
	int *x = mem_alloc(sizeof(int));
	munit_assert_not_null(x);
	mem_free0(x);
	munit_assert_null(x);

	// for structs
	struct complex_t *ptr = (struct complex_t *)mem_alloc(sizeof(struct complex_t));
	munit_assert_not_null(ptr);
	mem_free0(ptr);
	munit_assert_null(ptr);

	return MUNIT_OK;
}

static MunitResult
test_integer_overflow_in_mem_new_is_detected(UNUSED const MunitParameter params[],
					     UNUSED void *data)
{
	// this allocation size overflows. The test should be killed by the protection
	// guards using SIGABRT. We signal to the test harness about that below,
	// by passing the MUNIT_TEST_OPTION_RECV_SIGABRT option.
	size_t MAX = (~(size_t)(0));
	struct complex_t *ptr = mem_new(struct complex_t, MAX >> 1);

	// shouldn't be reached
	mem_free0(ptr);
	return MUNIT_FAIL;
}

static MunitResult
test_integer_overflow_in_mem_new0_is_detected(UNUSED const MunitParameter params[],
					      UNUSED void *data)
{
	// this allocation size overflows. The test should be killed by the protection
	// guards using SIGABRT. We signal to the test harness about that below,
	// by passing the MUNIT_TEST_OPTION_RECV_SIGABRT option.
	size_t MAX = (~(size_t)(0));
	struct complex_t *ptr = mem_new0(struct complex_t, MAX >> 1);

	// shouldn't be reached
	mem_free0(ptr);
	return MUNIT_FAIL;
}

static MunitResult
test_integer_overflow_in_mem_renew_is_detected(UNUSED const MunitParameter params[],
					       UNUSED void *data)
{
	// this allocation size overflows. The test should be killed by the protection
	// guards using SIGABRT. We signal to the test harness about that below,
	// by passing the MUNIT_TEST_OPTION_RECV_SIGABRT option.
	size_t MAX = (~(size_t)(0));
	struct complex_t *ptr = mem_new(struct complex_t, 30);
	ptr = mem_renew(struct complex_t, ptr, MAX >> 1);

	// shouldn't be reached
	mem_free0(ptr);
	return MUNIT_FAIL;
}

static MunitTest tests[] = {
	{
		"/allocate primitives and structs",	  /* name */
		test_can_allocate_primitives_and_structs, /* test */
		setup,					  /* setup */
		tear_down,				  /* tear_down */
		MUNIT_TEST_OPTION_NONE,			  /* options */
		NULL					  /* parameters */
	},
	{
		"/reallocate primitives and structs",	 /* name */
		test_can_realloc_primitives_and_structs, /* test */
		setup,					 /* setup */
		tear_down,				 /* tear_down */
		MUNIT_TEST_OPTION_NONE,			 /* options */
		NULL					 /* parameters */
	},
	{
		"/freed pointers are protected against use after free", /* name */
		test_freed_pointers_are_set_to_null,			/* test */
		setup,							/* setup */
		tear_down,						/* tear_down */
		MUNIT_TEST_OPTION_NONE,					/* options */
		NULL							/* parameters */
	},
	{
		"/integer overflow in allocation size of mem_new is detected", /* name */
		test_integer_overflow_in_mem_new_is_detected,		       /* test */
		setup,							       /* setup */
		tear_down,						       /* tear_down */
		MUNIT_TEST_OPTION_RECV_SIGABRT,				       /* options */
		NULL							       /* parameters */
	},
	{
		"/integer overflow in allocation size of mem_new0 is detected", /* name */
		test_integer_overflow_in_mem_new0_is_detected,			/* test */
		setup,								/* setup */
		tear_down,							/* tear_down */
		MUNIT_TEST_OPTION_RECV_SIGABRT,					/* options */
		NULL								/* parameters */
	},
	{
		"/integer overflow in allocation size of mem_renew is detected", /* name */
		test_integer_overflow_in_mem_renew_is_detected,			 /* test */
		setup,								 /* setup */
		tear_down,							 /* tear_down */
		MUNIT_TEST_OPTION_RECV_SIGABRT,					 /* options */
		NULL								 /* parameters */
	},
	{
		"/strdup and strndup",	/* name */
		test_strdup_strndup,	/* test */
		setup,			/* setup */
		tear_down,		/* tear_down */
		MUNIT_TEST_OPTION_NONE, /* options */
		NULL			/* parameters */
	},
	{
		"/memcpy",		/* name */
		test_mem_memcpy,	/* test */
		setup,			/* setup */
		tear_down,		/* tear_down */
		MUNIT_TEST_OPTION_NONE, /* options */
		NULL			/* parameters */
	},
	{
		"/printf to a dynamically allocated buffer", /* name */
		test_printf_dynamic_buffer,		     /* test */
		setup,					     /* setup */
		tear_down,				     /* tear_down */
		MUNIT_TEST_OPTION_NONE,			     /* options */
		NULL					     /* parameters */
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
