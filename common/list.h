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

/**
 * @file list.h
 *
 * Implements a doubly linked list. A pointer to the head of the list
 * must be maintained by the caller of the list API. This pointer should
 * be passed to the API functions in order to access or manipulate the list
 * elements. The head pointer may be NULL when calling list_append or
 * list_prepend in order to create a new list.
 */

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

typedef struct list list_t;
struct list {
	void *data;
	list_t *next;
	list_t *prev;
};

/**
 * Allocates memory for a new list element and puts it at the end of the list
 * so that it becomes the new list tail.
 *
 * @param list The head of the list; may be NULL.
 * @param data Payload of the new list element; may be NULL.
 * @return The head of the list.
 */
list_t *
list_append(list_t *list, void *data)
#if defined(__GNUC__)
	__attribute__((warn_unused_result))
#endif
;

/**
 * Joins two lists by appending list_append to list. If one of
 * the lists is NULL, the head of the respectiv other list is returned.
 *
 * @param list The head of list; may be NULL.
 * @param list The head of the list to be appended; may be NULL.
 * @return The head of new joind list.
 */
list_t *
list_join(list_t *list, list_t *list_append);

/**
 * Returns true if and only if the list contains the element.
 *
 * @param list The head of the list.
 * @param elem The element to search for.
 * @return true if list contains element, false otherwise.
 */
bool
list_contains(const list_t *list, const list_t *elem);

/**
 * Deletes the list "to the right".
 *
 * @param list The head of the list.
 * @return Head of the list (or NULL if the element was the only element
 *         of the list or the list was already NULL).
 */
void
list_delete(list_t *list);

/**
 * Deletes an element from the list.
 *
 * @param list The head of the list.
 * @param elem The element to delete.
 * @return The head of the list (or NULL if the element was the only element
 *         of the list or the list was already NULL).
 */
list_t *
list_unlink(list_t *list, list_t *elem)
#if defined(__GNUC__)
	__attribute__((warn_unused_result))
#endif
;

/**
 * Deletes the first element from the list that contains the supplied data
 * as payload.
 *
 * @param list The head of the list.
 * @param data The payload data to search for as deletion criteria.
 * @return The head of the list (or NULL if the element was the only element
 *         of the list or the list was already NULL).
 */
list_t *
list_remove(list_t *list, void *data)
#if defined(__GNUC__)
	__attribute__((warn_unused_result))
#endif
;

/**
 * Returns the first element from the list that contains the supplied data
 * as payload.
 *
 * @param list The head of the list.
 * @param data The payload data to search for.
 * @return The first element that matches data or NULL if no element matches.
 */
list_t *
list_find(list_t *list, void *data);

/**
 * Returns the number of elements contained in the list.
 *
 * @param list The head of the list.
 * @return Number of elements contained in the list.
 */
unsigned int
list_length(const list_t *list);

/**
 * Returns the n'th element of the list.
 *
 * @param list The head of the list.
 * @param n The index of the element, starting with 0.
 * @return The element with index n.
 */
list_t *
list_nth(list_t *list, unsigned int n);

/**
 * Returns the payload of the n'th element of the list.
 *
 * @param list The head of the list.
 * @param n The index of the element, starting with 0.
 * @return The payload of the element with index n or NULL if there is no n'th
 *         element, i.e., the list contains fewer elements or list is NULL.
 */
void *
list_nth_data(list_t *list, unsigned int n);

/**
 * Allocates memory for a new list element and puts it at the start of the list
 * so that it becomes the new list head.
 *
 * @param list The head of the list; may be NULL.
 * @param data Payload of the new list element; may be NULL.
 * @return Head to the list.
 */
list_t *
list_prepend(list_t *list, void *data)
#if defined(__GNUC__)
	__attribute__((warn_unused_result))
#endif
;

/**
 * Returns the last element of the list.
 *
 * @param list The head of the list.
 * @return The last element of the list.
 */
list_t *
list_tail(list_t *list);

/**
 * replace an  element in the list.
 *
 * @param list The head of the list.
 * @param elem The element to be replaced.
 * @param data the payload of the new element
 * @return The head of the list (or NULL if the element was the only element
 *         of the list or the list was already NULL).
 */
	list_t *
	list_replace(list_t *list, list_t *elem,void * data)
#if defined(__GNUC__)
	        __attribute__((warn_unused_result))
#endif
;
#endif /* LIST_H */
