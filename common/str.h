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
 * @file str.h
 *
 * Provides functionality for creating and manipulating strings.
 * These strings may be used as a safer and more comfortable
 * alternative to directly dealing with C's character arrays.
 */

#ifndef STR_H
#define STR_H

#include <unistd.h>
#include <stdbool.h>

typedef struct str str_t;

/**
 * Creates a new string.
 *
 * @param init The initial content of the string.
 * @return Pointer to the newly created string.
 */
str_t *
str_new(const char *init);

/**
 * Creates a new string of specified length.
 * The first character of the string is set to the null byte.
 *
 * @param len The length of the new string.
 * @return Pointer to the newly created string.
 */
str_t *
str_new_len(size_t len);

/**
 * Creates a new string with formatted content.
 *
 * @param fmt The initial content of the string as a printf(3)-like format string.
 * @return Pointer to the newly created string.
 */
str_t *
str_new_printf(const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 1, 2)))
#endif
;

/**
 * Assigns the content of the supplied buffer to a string.
 *
 * @param str The string which gets assigned the buffer content.
 * @param buf The buffer containing the content to assign to the string.
 */
void
str_assign(str_t *str, const char *buf);

/**
 * Assigns the content of the supplied buffer to a string with known length.
 * This function may be used instead of str_assign (possibly for performance reasons)
 * in case the length of the string is already known.
 *
 * @param str The string which gets assigned the buffer content.
 * @param buf The buffer containing the content to assign to the string.
 * @param len The length of the string.
 */
void
str_assign_len(str_t *str, const char *buf, ssize_t len);

/**
 * Assigns the content of the supplied format string to a string.
 *
 * @param str The string which gets assigned the formatted string.
 * @param fmt The to be assigned content of the string as a printf(3)-like format string.
 */
void
str_assign_printf(str_t *str, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
;

/**
 * Appends the content of the supplied buffer to a string.
 *
 * @param str The string where the supplied buffer gets appended to.
 * @param buf The buffer to append to the string.
 */
void
str_append(str_t *str, const char *buf);

/**
 * Appends the content of the supplied buffer to a string with known length.
 * This function may be used instead of str_append (possibly for performance reasons)
 * in case the length of the string is already known.
 *
 * @param str The string where the supplied buffer gets appended to.
 * @param buf The buffer to append to the string.
 * @param len The length of the string.
 */
void
str_append_len(str_t *str, const char *buf, ssize_t len);

/**
 * Appends the content of the supplied format string to a string.
 *
 * @param str The string where the formatted string gets appended to.
 * @param fmt The to be appended content of the string as a printf(3)-like format string.
 */
void
str_append_printf(str_t *str, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
;

/**
 * Inserts the contents of the supplied buffer to a string at the specified position.
 *
 * @param str The string where the supplied buffer gets inserted into.
 * @param pos The position of the string to insert the supplied buffer.
 *            The position may be an integer within the interval [0,strlen(str)]
 *            where 0 means "prepend to string" and strlen(str) means "append to string".
 *            A negative value may be used as shorthand for `strlen(str)', i.e., "append to string".
 *            A value greater than strlen(str) will result in the function just returning without altering the string at all.
 * @param buf The buffer to insert into the string.
 */
void
str_insert(str_t *str, ssize_t pos, const char *buf);

/**
 * Inserts the contents of the supplied buffer to a string at the specified position.
 * This function may be used instead of str_insert (possibly for performance reasons)
 * in case the length of the string is already known.
 *
 * @param str The string where the supplied buffer gets inserted into.
 * @param pos The position of the string to insert the supplied buffer.
 *            The position may be an integer within the interval [0,strlen(str)]
 *            where 0 means "prepend to string" and strlen(str) means "append to string".
 *            A negative value may be used as shorthand for `strlen(str)', i.e., "append to string".
 *            A value greater than strlen(str) will result in the function just returning without altering the string at all.
 * @param buf The buffer to insert into the string.
 * @param len The length of the string.
 */
void
str_insert_len(str_t *str, ssize_t pos, const char *buf, ssize_t len);

/**
 * Shortens a string to the specified length.
 * The length of the string remains unchanged if the specified length
 * is greater than the current length of the string.
 *
 * @param str The string to be shortened.
 * @param len The new length of the string.
 */
void
str_truncate(str_t *str, ssize_t len);

/**
 * Returns a pointer to the internal string buffer.
 *
 * @param str The string for which the internal buffer is requested.
 * @return A pointer to the (constant) internal string buffer.
 */
const char *
str_buffer(str_t *str);

/**
 * Returns the string length.
 *
 * @param str The string for which the string length is requested.
 * @return The length of the string.
 */
size_t
str_length(str_t *str);

/**
 * Frees the allocated string memory.
 *
 * @param str The string to be freed.
 * @param free_buf True: the internal string buffer should also be freed. False: the internal string buffer is not freed and a pointer to it is returned by the function.
 * @return If free_buf is false, a pointer to the internal string buffer is returned. Otherwise, NULL is returned.
 */
char *
str_free(str_t *str, bool free_buf);

#endif /* STR_H */
