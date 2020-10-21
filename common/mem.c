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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "mem.h"
#include "macro.h"

#define DEBUG_THRESHOLD(size)                                                                      \
	do {                                                                                       \
		if (size > (1024 * 1024))                                                          \
			DEBUG("Allocating a large memory area of %zu bytes", size);                \
	} while (0)

void *
mem_alloc(size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = malloc(size);
	ASSERT(p);
	return p;
}

void *
mem_alloc0(size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = calloc(1, size);
	ASSERT(p);
	return p;
}

void *
mem_realloc(void *mem, size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = realloc(mem, size);
	ASSERT(p);
	return p;
}

char *
mem_strdup(const char *str)
{
	ASSERT(str);
	char *p = strdup(str);
	ASSERT(p);
	return p;
}

char *
mem_strndup(const char *str, size_t len)
{
	ASSERT(str);
	DEBUG_THRESHOLD(len);
	char *p = strndup(str, len);
	ASSERT(p);
	return p;
}

unsigned char *
mem_memcpy(const unsigned char *mem, size_t size)
{
	ASSERT(mem);
	unsigned char *p = mem_alloc0(size);
	ASSERT(p);
	memcpy(p, mem, size);
	return p;
}

char *
mem_vprintf(const char *fmt, va_list ap)
{
	char *p = NULL;
	ASSERT(fmt);
	ASSERT(vasprintf(&p, fmt, ap) >= 0);
	return p;
}

char *
mem_printf(const char *fmt, ...)
{
	char *p = NULL;
	va_list ap;
	ASSERT(fmt);
	va_start(ap, fmt);
	ASSERT(vasprintf(&p, fmt, ap) >= 0);
	va_end(ap);
	return p;
}

void
mem_free_array(void **array, size_t size)
{
	if (array != NULL) {
		size_t i = 0;
		while (i < size) {
			if (array[i] != NULL) {
				DEBUG("[MEM] Freeing element %zu", i);
				mem_free(array[i]);
			}

			i++;
		}

		DEBUG("[MEM] Freeing array");
		mem_free(array);
	}
}

bool
mem_ends_with(const void *buf, size_t buf_len, const void *end, size_t end_len)
{
	IF_NULL_RETVAL(buf, false);
	IF_NULL_RETVAL(end, false);

	if (buf_len < end_len)
		return false;

	if (memcmp((const char *)buf + (buf_len - end_len), end, end_len))
		return false;

	return true;
}

bool
mem_starts_with(const void *buf, size_t buf_len, const void *start, size_t start_len)
{
	IF_NULL_RETVAL(buf, false);
	IF_NULL_RETVAL(start, false);

	if (buf_len < start_len)
		return false;

	if (memcmp(buf, start, start_len)) {
		return false;
	}
	return true;
}
