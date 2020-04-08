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
 * @file mem.h
 *
 * Provides wrapper functions and macros for classic C memory allocation
 * functions like malloc(3), strdup(3), or vasprintf(3) which abort
 * if the wrapped functions fail.
 */

#ifndef MEM_H
#define MEM_H

#include <stddef.h>
#include <stdarg.h>
#include <string.h>

/**
 * Allocates memory. The memory is not initialized.
 * This is a wrapper for malloc(3) which aborts if the allocation fails.
 *
 * @param size The number of bytes to allocate.
 * @return Pointer to the allocated memory.
 */
void *
mem_alloc(size_t size);

/**
 * Allocates memory. The memory is set to zero.
 * This is a wrapper for calloc(3) which aborts if the allocation fails.
 *
 * @param size The number of bytes to allocate.
 * @return Poiner to the allocated memory.
 */
void *
mem_alloc0(size_t size);

/**
 * Changes the size of the memory block pointed to by mem to size bytes.
 * This is a wrapper for realloc(3) which aborts if the allocation fails.
 *
 * @param mem The memory block to be resized.
 * @param size The new size of the memory block.
 * @return Pointer to the newly allocated memory.
 */
void *
mem_realloc(void *mem, size_t size);

/**
 * Duplicates a string. Allocates sufficient memory.
 * This is a wrapper for strdup(3) which aborts if the duplication fails.
 *
 * @param str The string to duplicate.
 * @return Pointer to the new string.
 */
char *
mem_strdup(const char *str);

/**
 * Duplicates a string, but copies at most len bytes. Allocates sufficient memory.
 * This is a wrapper for strndup(3) which aborts if the duplication fails.
 *
 * @param str The string to duplicate.
 * @param len The maximum length of the new string.
 * @return Pointer to the new string.
 */
char *
mem_strndup(const char *str, size_t len);

/**
 * Duplicates an array of unsigned char, but copies at most size bytes.
 * Allocates sufficient memory.
 * This is a wrapper for memcpy(3).
 *
 * @param mem The memory to duplicate.
 * @param size The size of the memory.
 * @return Pointer to the new array.
 */
unsigned char *
mem_memcpy(const unsigned char *mem, size_t size);

/**
 * Prints to a string allocated by this function.
 * This is a wrapper for vasprintf(3) which aborts if the function fails.
 *
 * @param fmt The format string.
 * @param ap va_list
 * @return Pointer to the allocated formatted string.
 */
char *
mem_vprintf(const char *fmt, va_list ap);

/**
 * Prints to a string allocated by this function.
 * This is a wrapper for vasprintf(3) which aborts if the function fails.
 *
 * @param fmt The format string.
 * @return Pointer to the allocated formatted string.
 */
char *
mem_printf(const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 1, 2)))
#endif
	;

/**
 * Frees the allocated memory.
 * This is a wrapper for free(3).
 * If we seccessfully free a pointer,
 * the wrapper sets it to NULL to prevent use-after-free,
 * double-free and similar exploitable issues.
 * @param mem Memory pointer to be freed.
 */
#define mem_free(ptr)                                                                              \
	do {                                                                                       \
		if (ptr) {                                                                         \
			free(ptr);                                                                 \
			ptr = NULL;                                                                \
		}                                                                                  \
	} while (0)

/**
 * Frees the allocated memory of each array element and the array itself.
 * @param array Array to be freed.
 * @param size Array size.
 */
void
mem_free_array(void **array, size_t size);

/**
 * Convenience wrapper macro for mem_alloc which calculates
 * the correct size to be allocated and casts accordingly.
 */
#define mem_new(struct_type, n_structs)                                                            \
	__extension__({                                                                            \
		size_t _total_len = 0;                                                             \
		size_t _lvalue = (size_t)sizeof(struct_type);                                      \
		size_t _rvalue = (size_t)(n_structs);                                              \
		if (__builtin_mul_overflow(_lvalue, _rvalue, &_total_len)) {                       \
			FATAL("Detected integer overflow in allocation size. \
                                Aborting to prevent heap overflow.");                              \
		}                                                                                  \
		(struct_type *)mem_alloc(_total_len);                                              \
	})

/**
 * Convenience wrapper macro for mem_alloc0 which calculates
 * the correct size to be allocated and casts accordingly.
 */
#define mem_new0(struct_type, n_structs)                                                           \
	__extension__({                                                                            \
		size_t _total_len = 0;                                                             \
		size_t _lvalue = (size_t)sizeof(struct_type);                                      \
		size_t _rvalue = (size_t)(n_structs);                                              \
		if (__builtin_mul_overflow(_lvalue, _rvalue, &_total_len)) {                       \
			FATAL("Detected integer overflow in allocation size. \
                                Aborting to prevent heap overflow.");                              \
		}                                                                                  \
		(struct_type *)mem_alloc0(_total_len);                                             \
	})
/**
 * Convenience wrapper macro for mem_realloc which calculates
 * the correct size to be allocated and casts accordingly.
 */
#define mem_renew(struct_type, mem, n_structs)                                                     \
	__extension__({                                                                            \
		size_t _total_len = 0;                                                             \
		size_t _lvalue = (size_t)sizeof(struct_type);                                      \
		size_t _rvalue = (size_t)(n_structs);                                              \
		if (__builtin_mul_overflow(_lvalue, _rvalue, &_total_len)) {                       \
			FATAL("Detected integer overflow in allocation size. \
                                Aborting to prevent heap overflow.");                              \
		}                                                                                  \
		(struct_type *)mem_realloc((mem), _total_len);                                     \
	})

#endif /* MEM_H */
