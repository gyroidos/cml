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

/** @file list.test.c
  *
  * List Unit Test file
  */
#include <stdio.h>

#include "list.h"
#include "macro.h"
#include "logf.h"

/** Just a helper function, which prints a list
  *
  * @param list the list to be printed
  */
void
list_print(list_t *list)
{
	for (unsigned int i = 0; i < list_length(list); i++)
		DEBUG("list[%d] = %d\n", i, *((int *)list_nth_data(list, i)));
}

/** Unit Test main function for list implementation
  *
  */
int
main(void)
{
	list_t *list, *elem;

	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: list.test.c\n");

	int a = 1;
	list = list_append(NULL, &a);

	DEBUG("Test list functions. Check if a is first element in list");
	ASSERT(list_find(list, &a) != NULL);
	ASSERT(list_length(list) == 1);
	ASSERT(list_contains(list, list_tail(list)) == true);
	ASSERT(list_nth_data(list, 0) == &a);

	int b = 2;
	list = list_append(list, &b);

	DEBUG("Test list functions. Check if b is second element in list");
	ASSERT(list_find(list, &b) != NULL);
	ASSERT(list_length(list) == 2);
	ASSERT(list_contains(list, list_tail(list)) == true);
	ASSERT(list_nth_data(list, 0) == &a);
	ASSERT(list_nth_data(list, 1) == &b);

	int c = 3;
	list = list_append(list, &c);

	DEBUG("Test list functions. Check if c is third element in list");
	ASSERT(list_find(list, &c) != NULL);
	ASSERT(list_length(list) == 3);
	ASSERT(list_contains(list, list_tail(list)) == true);
	ASSERT(list_nth_data(list, 0) == &a);
	ASSERT(list_nth_data(list, 1) == &b);
	ASSERT(list_nth_data(list, 2) == &c);

	int d = 4;
	list = list_prepend(list, &d);

	DEBUG("Test list functions. Check if d is first  element in list");
	ASSERT(list_find(list, &d) != NULL);
	ASSERT(list_length(list) == 4);
	ASSERT(list_contains(list, list_nth(list, 0)) == true);
	ASSERT(list_nth_data(list, 1) == &a);
	ASSERT(list_nth_data(list, 2) == &b);
	ASSERT(list_nth_data(list, 3) == &c);
	ASSERT(list_nth_data(list, 0) == &d);

	int e = 5;
	list = list_prepend(list, &e);

	DEBUG("Test list functions. Check if e is first element in list");
	ASSERT(list_find(list, &e) != NULL);
	ASSERT(list_length(list) == 5);
	ASSERT(list_contains(list, list_nth(list, 0)) == true);
	ASSERT(list_nth_data(list, 2) == &a);
	ASSERT(list_nth_data(list, 3) == &b);
	ASSERT(list_nth_data(list, 4) == &c);
	ASSERT(list_nth_data(list, 1) == &d);
	ASSERT(list_nth_data(list, 0) == &e);

	list_print(list);

	DEBUG("Check if existing data can be successfully removed");
	ASSERT(list_contains(list, list_find(list, &e)) == true);
	list = list_remove(list, &e);
	ASSERT(list_find(list, &e) == NULL);
	ASSERT(list_length(list) == 4);

	list_print(list);
	list = list_prepend(list, &e);

	int false_test = -1;

	DEBUG("Verify that non-existing data does not adversely affect the list");
	ASSERT(list_contains(list, list_find(list, &false_test)) == false);
	list = list_remove(list, &false_test);
	ASSERT(list != NULL);
	ASSERT(list_find(list, &false_test) == NULL);
	ASSERT(list_length(list) == 5);

	list_print(list);

	DEBUG("Check if elem no 1 (d) can be resolved with correct data");
	elem = list_nth(list, 1);
	ASSERT(elem->data == &d);
	ASSERT(list_contains(list, elem) == true);
	ASSERT(list_contains(list, NULL) == false);
	ASSERT(list_contains(list, list_find(list, &c)) == true);

	int f = 5;

	DEBUG("Check if different pointer with same payload is erroneously ctd.");
	ASSERT(list_find(list, &f) == NULL);

	DEBUG("Check for correct element removal");
	list = list_unlink(list, elem);

	ASSERT(list != NULL);
	ASSERT(list_contains(list, elem) == false);
	ASSERT(list_length(list) == 4);
	ASSERT(list_nth_data(list, 0) == &e);
	ASSERT(list_nth_data(list, 1) == &a);
	ASSERT((*((int *)list_tail(list)->data)) == c);

	list_print(list);

	DEBUG("deleting first element");
	list = list_unlink(list, list_nth(list, 0));

	ASSERT(list != NULL);

	DEBUG("deleting last element");
	list = list_unlink(list, list_nth(list, list_length(list) - 1));

	ASSERT(list != NULL);
	ASSERT(list_length(list) == 2);
	ASSERT(list_nth_data(list, 0) == &a);
	ASSERT(list_nth_data(list, 1) == &b);

	list_print(list);

	DEBUG("deleting specific element  by searching for payload");
	list = list_remove(list, &b);

	ASSERT(list_length(list) == 1);
	ASSERT(list_nth_data(list, 0) == &a);
	ASSERT(list_find(list, &a) != NULL);
	ASSERT(list_find(list, &b) == NULL);
	ASSERT((*((int *)list_tail(list)->data)) == a);
	ASSERT(list == list_tail(list));

	list_print(list);

	DEBUG("delete last element of the list");
	list = list_remove(list, &a);
	ASSERT(list_length(list) == 0);
	ASSERT(list_find(list, &a) == NULL);
	ASSERT(list_tail(list) == NULL);

	DEBUG("check if deleting list does not cause crash");
	list_delete(list);

	return 0;
}
