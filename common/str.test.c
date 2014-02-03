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

/* @file str.test.c
 * Unit Test form str.c
 * Puts the string library under test
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "logf.h"
#include "str.h"
#include "macro.h"


/** Unit Test str main function
  *
  */
int
main(int argc, char **argv)
{
	str_t *str;
	char *buf;

	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: str.test.c");

	buf = str_free(str_new_printf("/%s/%s%u", "dev", "tty", 0), false);
	DEBUG("Test str_new_printf and str_free: %s", buf);
	ASSERT(!strcmp(buf, "/dev/tty0"));
	free(buf);

	str = str_new_printf("/%s", "tty");
	str_append_printf(str, "%u", 0);
	str_insert(str, 0, "/dev");
	DEBUG("Test str_append_printf and str_insert: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "/dev/tty0"));
	str_free(str, true);

	str = str_new("1234");
	DEBUG("Test str_new: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "1234"));

	str_assign(str, "test");
	DEBUG("Test str_assign: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "test"));

	str_append(str, "TEST");
	DEBUG("Test str_append: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "testTEST"));

	str_assign_len(str, "12345678", 6);
	DEBUG("Test str_assign_len: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "123456"));

	str_append_printf(str, "%u", 7890);
	DEBUG("Test str_append_printf:%s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "1234567890"));

	str_assign_printf(str, "%u", 23);
	DEBUG("Test str_assign_printf: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "23"));
	str_free(str, true);

	str = str_new_printf("%u%x", 88, 0xaa);
	DEBUG("Test str_new_printf: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "88aa"));

	buf = str_free(str, false);
	DEBUG("Test str_free: %s", buf);
	ASSERT(!strcmp(buf, "88aa"));
	free(buf);

	str = str_new_len(1);
	DEBUG("Test str_new_len and str_length: %d", str_length(str));
	ASSERT(str_length(str) == 0);

	str_insert_len(str, 0, "TEST", 3);
	DEBUG("Test str_insert_len: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "TES"));

	str_append_len(str, "TE IMMER", 5);
	DEBUG("Test str_append_len: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "TESTE IM"));

	str_truncate(str, 100);
	DEBUG("Test str_truncate high number: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "TESTE IM"));

	str_truncate(str, 2);
	DEBUG("Test str_truncate low number: %s", str_buffer(str));
	ASSERT(!strcmp(str_buffer(str), "TE"));

	str = str_new(NULL);
	DEBUG("Test str_new and str_length: %d", str_length(str));
	ASSERT(str_length(str) == 0 && *str_buffer(str)=='\0' );

	str = str_new_len(0);
	DEBUG("Test str_new_len and str_length: %d", str_length(str));
	ASSERT(str_length(str) == 0);

	str = str_new_printf("");
	DEBUG("Test str_new_printf and str_length: %d", str_length(str));
	ASSERT(str_length(str) == 0);

	buf = str_free(str_new_printf("%s%d%u", "dev", 1, 0), false);

	str_assign_len(str, buf, strlen(buf));
	DEBUG("Test str_assign_len and str_length: %d, %d", strlen(buf), str_length(str));
	ASSERT(strlen(buf) == str_length(str));

	str_insert(str, strlen(buf), "H");
	DEBUG("Test str_insert: str: %s, len %d", str_buffer(str), str_length(str));
	ASSERT(str_length(str) == 6 && !strcmp(str_buffer(str), "dev10H"));

	return 0;
}
