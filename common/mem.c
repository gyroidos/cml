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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "bounds_safety.h"
#include "mem.h"
#include "macro.h"

#define DEBUG_THRESHOLD(size)                                                                      \
	do {                                                                                       \
		if (size > (1024 * 1024))                                                          \
			DEBUG("Allocating a large memory area of %zu bytes", size);                \
	} while (0)

void *__sized_by(size)
mem_alloc(size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = malloc(size);
	ASSERT(p);
	return p;
}

void *__sized_by(size)
mem_alloc0(size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = calloc(1, size);
	ASSERT(p);
	return p;
}

void *__sized_by(size)
mem_realloc(void *mem, size_t size)
{
	DEBUG_THRESHOLD(size);
	void *p = realloc(mem, size);
	ASSERT(p);
	return p;
}

char *__null_terminated
mem_strdup(const char *__null_terminated str)
{
	ASSERT(str);
	char *__null_terminated p = __unsafe_forge_null_terminated(char *, strdup(str));
	ASSERT(p);
	return p;
}

char *__null_terminated
mem_strndup(const char *__counted_by(len) str, size_t len)
{
	ASSERT(str);
	DEBUG_THRESHOLD(len);
	char *__null_terminated p = __unsafe_forge_null_terminated(char *, strndup(str, len));
	ASSERT(p);
	return p;
}

unsigned char *__sized_by(size)
mem_memcpy(const unsigned char *__sized_by(size) mem, size_t size)
{
	ASSERT(mem);
	unsigned char *p = mem_alloc0(size);
	ASSERT(p);
	memcpy(p, mem, size);
	return p;
}

char *__null_terminated
mem_vprintf(const char *__null_terminated fmt, va_list ap)
{
	char *__unsafe_indexable p = NULL;
	ASSERT(fmt);
	ASSERT(vasprintf(&p, fmt, ap) >= 0);
	return __unsafe_forge_null_terminated(char *, p);
}

char *__null_terminated
mem_printf(const char *__null_terminated fmt, ...)
{
	char *__unsafe_indexable p = NULL;
	va_list ap;
	ASSERT(fmt);
	va_start(ap, fmt);
	ASSERT(vasprintf(&p, fmt, ap) >= 0);
	va_end(ap);
	return __unsafe_forge_null_terminated(char *, p);
}

void
mem_free(void *ptr)
{
	free(ptr);
}

void
mem_free_array(void *__single *__counted_by(size) array, size_t size)
{
	if (array != NULL) {
		size_t i = 0;
		while (i < size) {
			if (array[i] != NULL) {
				DEBUG("[MEM] Freeing element %zu", i);
				mem_free0(array[i]);
			}

			i++;
		}

		DEBUG("[MEM] Freeing array");
		mem_free(array);
	}
}
