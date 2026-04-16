/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "bounds_safety.h"
#include "str.h"
#include "mem.h"
#include "macro.h"

struct str {
	char *__sized_by(allocated_len) buf;
	ssize_t len;
	size_t allocated_len;
};

static void
str_expand(str_t *str, size_t len)
{
	IF_NULL_RETURN(str);

	if (str->len + len < str->allocated_len)
		return;

	size_t new_alloc = str->len + len + 1;
	str->buf = mem_realloc(str->buf, new_alloc);
	str->allocated_len = new_alloc;
}

static void
str_append_printf_internal(str_t *str, const char *fmt, va_list ap)
{
	char *__null_terminated buf;

	buf = mem_vprintf(fmt, ap);
	size_t len = strlen(buf);
	str_insert_len(str, -1, __unsafe_forge_bidi_indexable(const char *, buf, len), len);
	mem_free0(buf);
}

str_t *
str_new(const char *init)
{
	str_t *str;

	if (init == NULL || *init == '\0') {
		str = str_new_len(2);
	} else {
		size_t len;

		len = strlen(init);
		str = str_new_len(len + 2);
		str_append_len(str,
			       __unsafe_forge_bidi_indexable(const char *, init, len),
			       len);
	}
	return str;
}

str_t *
str_new_len(size_t len)
{
	str_t *str;

	str = mem_new(str_t, 1);

	str->allocated_len = 0;
	str->len = 0;
	str->buf = NULL;

	str_expand(str, MAX(len, 2));
	str->buf[0] = 0;

	return str;
}

str_t *
str_new_printf(const char *fmt, ...)
{
	str_t *str;
	va_list ap;

	str = str_new_len(2);
	va_start(ap, fmt);
	str_append_printf_internal(str, fmt, ap);
	va_end(ap);

	return str;
}

void
str_assign(str_t *str, const char *buf)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);
	IF_FALSE_RETURN(str->buf != buf);

	str_truncate(str, 0);
	size_t len = strlen(buf);
	str_insert_len(str, -1, __unsafe_forge_bidi_indexable(const char *, buf, len), len);
}

void
str_assign_len(str_t *str, const char *__counted_by(len) buf, size_t len)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);
	IF_FALSE_RETURN(str->buf != buf);

	str_truncate(str, 0);
	str_insert_len(str, -1, buf, len);
}

void
str_assign_printf(str_t *str, const char *fmt, ...)
{
	va_list ap;

	IF_NULL_RETURN(str);

	str_truncate(str, 0);
	va_start(ap, fmt);
	str_append_printf_internal(str, fmt, ap);
	va_end(ap);
}

void
str_append(str_t *str, const char *buf)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);

	size_t len = strlen(buf);
	str_insert_len(str, -1, __unsafe_forge_bidi_indexable(const char *, buf, len), len);
}

void
str_append_len(str_t *str, const char *__counted_by(len) buf, size_t len)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);

	str_insert_len(str, -1, buf, len);
}

void
str_append_printf(str_t *str, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	str_append_printf_internal(str, fmt, ap);
	va_end(ap);
}

void
str_insert(str_t *str, ssize_t pos, const char *buf)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);

	size_t len = strlen(buf);
	str_insert_len(str, pos, __unsafe_forge_bidi_indexable(const char *, buf, len), len);
}

void
str_insert_len(str_t *str, ssize_t pos, const char *__counted_by(len) buf, size_t len)
{
	IF_NULL_RETURN(str);
	IF_NULL_RETURN(buf);

	if (pos < 0)
		pos = str->len;
	else if (pos > str->len)
		return;

	str_expand(str, len);

	if (buf >= str->buf && buf <= str->buf + str->len) {
		size_t offset = buf - str->buf;
		size_t precount = 0;

		const char *src = str->buf + offset;

		if (pos < str->len)
			memmove(str->buf + pos + len, str->buf + pos, str->len - pos);

		if (offset < (size_t)pos) {
			precount = MIN(len, (size_t)pos - offset);
			memcpy(str->buf + pos, src, precount);
		}

		if (len > precount)
			memcpy(str->buf + pos + precount, src + precount + len,
			       len - precount);
	} else {
		if (pos < str->len)
			memmove(str->buf + pos + len, str->buf + pos, str->len - pos);

		memcpy(str->buf + pos, buf, len);
	}

	str->len += len;
	str->buf[str->len] = 0;
}

void
str_truncate(str_t *str, ssize_t len)
{
	IF_NULL_RETURN(str);

	str->len = MIN(len, str->len);
	str->buf[str->len] = 0;
}

const char *
str_buffer(str_t *str)
{
	IF_NULL_RETVAL(str, NULL);
	return __unsafe_null_terminated_from_indexable(str->buf);
}

size_t
str_length(str_t *str)
{
	IF_NULL_RETVAL(str, 0);
	return str->len;
}

char *__null_terminated
str_free(str_t *str, bool free_buf)
{
	char *__null_terminated buf;

	IF_NULL_RETVAL(str, NULL);

	if (free_buf) {
		free(str->buf);
		str->buf = NULL;
		str->allocated_len = 0;
		buf = NULL;
	} else {
		buf = __unsafe_null_terminated_from_indexable(str->buf);
	}

	mem_free0(str);

	return buf;
}

str_t *
str_hexdump_new(unsigned char *__counted_by(len) mem, size_t len)
{
	str_t *ret = str_new_len(len * 2 + 1);

	for (size_t i = 0; i < len; i++) {
		str_append_printf(ret, "%02x ", mem[i]);
	}

	return ret;
}
