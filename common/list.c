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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "list.h"
#include "macro.h"
#include "mem.h"

list_t *
list_append(list_t *list, void *data)
{
	list_t *e = mem_new(list_t, 1);
	e->data = data;

	list_t *tail = list_tail(list);
	e->prev = tail;
	e->next = NULL;

	if (tail)
		tail->next = e;

	return tail ? list : e; // return head of list
}

list_t *
list_join(list_t *list, list_t *list_append)
{
	IF_NULL_RETVAL(list, list_append);
	IF_NULL_RETVAL(list_append, list);

	list_t *l_tail = list_tail(list);
	l_tail->next = list_append;

	return list;
}

bool
list_contains(const list_t *list, const list_t *elem)
{
	IF_NULL_RETVAL(elem, false);

	for (const list_t *e = list; e; e = e->next) {
		TRACE("Searching list element %p in list %p", (void *)elem, (void *)list);
		if (e == elem)
			return true;
	}
	return false;
}

void
list_delete(list_t *list)
{
	while (list)
		list = list_unlink(list, list);
}

list_t *
list_unlink(list_t *list, list_t *elem)
{
	IF_NULL_RETVAL(elem, list);
	IF_FALSE_RETVAL(list_contains(list, elem), list); // this also handles the case that list is NULL

	list_t *head = list;

	if (elem->prev)
		elem->prev->next = elem->next;
	else
		head = elem->next; // elem was the head
	if (elem->next)
		elem->next->prev = elem->prev;
	mem_free(elem);

	return head;
}

list_t *
list_remove(list_t *list, void *data)
{
	return list_unlink(list, list_find(list, data));
}

list_t *
list_find(list_t *list, void *data)
{
	TRACE("Searching data %p in list %p", (void *)data, (void *)list);

	for (list_t *e = list; e; e = e->next) {
		TRACE("Scanning element %p having data %p", (void *)e, (void *)e->data);
		if (e->data == data) {
			TRACE("Found data in element %p", (void *)e);
			return e;
		}
	}

	TRACE("Did not find data in list");
	return NULL;
}

unsigned int
list_length(const list_t *list)
{
	unsigned int len = 0;

	for (const list_t *e = list; e; e = e->next)
		len++;

	return len;
}

list_t *
list_nth(list_t *list, unsigned int n)
{
	IF_NULL_RETVAL(list, NULL);

	list_t *elem = list;
	for (unsigned int i = n; i > 0; i--) {
		if (elem)
			elem = elem->next;
		else
			return NULL;
	}

	return elem;
}

void *
list_nth_data(list_t *list, unsigned int n)
{
	list_t *e = list_nth(list, n);
	return e ? e->data : NULL;
}

list_t *
list_prepend(list_t *list, void *data)
{
	list_t *e = mem_new(list_t, 1);
	e->data = data;

	e->prev = NULL;
	e->next = list;

	if (list)
		list->prev = e;

	return e; // return head of list
}

list_t *
list_tail(list_t *list)
{
	for (list_t *e = list; e; e = e->next) {
		if (e->next == NULL)
			return e;
	}
	return NULL;
}

list_t *
list_replace(list_t *list, list_t *elem, void *data)
{
	IF_NULL_RETVAL(elem, list);
	IF_FALSE_RETVAL(list_contains(list, elem), list); // this also handles the case that list is NULL

	list_t *head = list;
	list_t *e = mem_new(list_t, 1);

	e->data = data;
	e->prev = elem->prev;
	e->next = elem->next;

	if (elem->prev)
		elem->prev->next = e;
	else
		head = e; // elem was the head

	if (elem->next)
		elem->next->prev = e;

	mem_free(elem);

	return head;
}

void
list_foreach(list_t *list, void(func)(void *))
{
	ASSERT(list);
	ASSERT(func);

	list_t *current = list;
	list_t *elem = NULL;

	TRACE("Applying callback to list at %p", (void *)list);

	do {
		if (current) {
			TRACE("Applying callback to element %p, data: %p", (void *)current, (void *)current->data);
			elem = current;
			current = current->next;
			func(elem->data);
		} else {
			ERROR("NULL pointer during list traversal");
		}
	} while (current && current != list);
}
