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
 * @file macro.h
 *
 * Macros for logging, assertions, compiler hints, and for
 * common mathematical functions like min, max, or abs.
 * Note that macros in this file do not have the file name as prefix,
 * what is true for all other modules. And there is only a header file,
 * there is no macro.c.
 */

#ifndef MACRO_H
#define MACRO_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "logf.h"

// logging
#define TRACE(...) logf_trace(__VA_ARGS__) //!< Trace logging (enabled only in debug builds).
#define DEBUG(...) logf_debug(__VA_ARGS__) //!< Debug logging (enabled only in debug builds).
#define INFO(...) logf_info(__VA_ARGS__)   //!< Normal logging (e.g. container start).
#define WARN(...) logf_warn(__VA_ARGS__)   //!< Recoverable error (warning).
#define ERROR(...)                                                                                 \
	logf_error(__VA_ARGS__) //!< Non-recoverable error (operation failed, but process stable).
#define FATAL(...)                                                                                 \
	do {                                                                                       \
		logf_fatal(__VA_ARGS__);                                                           \
		logf_fatal("%s", "Aborting...");                                                   \
		abort();                                                                           \
	} while (0) //!< Non-recoverable error, process will abort.

// logging with errno
#define TRACE_ERRNO(...) logf_trace_errno(__VA_ARGS__)
#define DEBUG_ERRNO(...) logf_debug_errno(__VA_ARGS__)
#define INFO_ERRNO(...) logf_info_errno(__VA_ARGS__)
#define WARN_ERRNO(...) logf_warn_errno(__VA_ARGS__)
#define ERROR_ERRNO(...) logf_error_errno(__VA_ARGS__)
#define FATAL_ERRNO(...)                                                                           \
	do {                                                                                       \
		logf_fatal_errno(__VA_ARGS__);                                                     \
		logf_fatal("%s", "Aborting...");                                                   \
		abort();                                                                           \
	} while (0)

#define ASSERT(expr)                                                                               \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			FATAL("Assertion `%s' failed", #expr);                                     \
		}                                                                                  \
	} while (0)
#define ASSERT_ERRNO(expr)                                                                         \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			FATAL_ERRNO("Assertion `%s' failed", #expr);                               \
		}                                                                                  \
	} while (0)

#define IF_NULL_RETURN(ptr) IF_NULL_RETURN_DEBUG(ptr)
#define IF_NULL_RETVAL(ptr, val) IF_NULL_RETVAL_DEBUG(ptr, val)
#define IF_NULL_GOTO(ptr, label) IF_NULL_GOTO_DEBUG(ptr, label)
#define IF_TRUE_RETURN(expr) IF_TRUE_RETURN_DEBUG(expr)
#define IF_TRUE_RETVAL(expr, val) IF_TRUE_RETVAL_DEBUG(expr, val)
#define IF_TRUE_GOTO(expr, label) IF_TRUE_GOTO_DEBUG(expr, label)
#define IF_FALSE_RETURN(expr) IF_FALSE_RETURN_DEBUG(expr)
#define IF_FALSE_RETVAL(expr, val) IF_FALSE_RETVAL_DEBUG(expr, val)
#define IF_FALSE_GOTO(expr, label) IF_FALSE_GOTO_DEBUG(expr, label)

#define IF_NULL_RETURN_TRACE(ptr)                                                                  \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE("Check failed: pointer `%s' is NULL", #ptr);                         \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_DEBUG(ptr)                                                                  \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG("Check failed: pointer `%s' is NULL", #ptr);                         \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_INFO(ptr)                                                                   \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO("Check failed: pointer `%s' is NULL", #ptr);                          \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_WARN(ptr)                                                                   \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN("Check failed: pointer `%s' is NULL", #ptr);                          \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_ERROR(ptr)                                                                  \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR("Check failed: pointer `%s' is NULL", #ptr);                         \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_NULL_RETVAL_TRACE(ptr, val)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE("Check failed: pointer `%s' is NULL", #ptr);                         \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_DEBUG(ptr, val)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG("Check failed: pointer `%s' is NULL", #ptr);                         \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_INFO(ptr, val)                                                              \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO("Check failed: pointer `%s' is NULL", #ptr);                          \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_WARN(ptr, val)                                                              \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN("Check failed: pointer `%s' is NULL", #ptr);                          \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_ERROR(ptr, val)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR("Check failed: pointer `%s' is NULL", #ptr);                         \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_NULL_GOTO_TRACE(ptr, label)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE("Check failed: pointer `%s' is NULL", #ptr);                         \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_DEBUG(ptr, label)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG("Check failed: pointer `%s' is NULL", #ptr);                         \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_INFO(ptr, label)                                                              \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO("Check failed: pointer `%s' is NULL", #ptr);                          \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_WARN(ptr, label)                                                              \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN("Check failed: pointer `%s' is NULL", #ptr);                          \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_ERROR(ptr, label)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR("Check failed: pointer `%s' is NULL", #ptr);                         \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define IF_TRUE_RETURN_TRACE(expr)                                                                 \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE("Check failed: expression `%s' is true", #expr);                     \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_DEBUG(expr)                                                                 \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG("Check failed: expression `%s' is true", #expr);                     \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_INFO(expr)                                                                  \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO("Check failed: expression `%s' is true", #expr);                      \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_WARN(expr)                                                                  \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN("Check failed: expression `%s' is true", #expr);                      \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_ERROR(expr)                                                                 \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR("Check failed: expression `%s' is true", #expr);                     \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_TRUE_RETVAL_TRACE(expr, val)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE("Check failed: expression `%s' is true", #expr);                     \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_DEBUG(expr, val)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG("Check failed: expression `%s' is true", #expr);                     \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_INFO(expr, val)                                                             \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO("Check failed: expression `%s' is true", #expr);                      \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_WARN(expr, val)                                                             \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN("Check failed: expression `%s' is true", #expr);                      \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_ERROR(expr, val)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR("Check failed: expression `%s' is true", #expr);                     \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_TRUE_GOTO_TRACE(expr, label)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE("Check failed: expression `%s' is true", #expr);                     \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_DEBUG(expr, label)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG("Check failed: expression `%s' is true", #expr);                     \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_INFO(expr, label)                                                             \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO("Check failed: expression `%s' is true", #expr);                      \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_WARN(expr, label)                                                             \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN("Check failed: expression `%s' is true", #expr);                      \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_ERROR(expr, label)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR("Check failed: expression `%s' is true", #expr);                     \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define IF_FALSE_RETURN_TRACE(expr)                                                                \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE("Check failed: expression `%s' is false", #expr);                    \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_DEBUG(expr)                                                                \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG("Check failed: expression `%s' is false", #expr);                    \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_INFO(expr)                                                                 \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO("Check failed: expression `%s' is false", #expr);                     \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_WARN(expr)                                                                 \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN("Check failed: expression `%s' is false", #expr);                     \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_ERROR(expr)                                                                \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR("Check failed: expression `%s' is false", #expr);                    \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_FALSE_RETVAL_TRACE(expr, val)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE("Check failed: expression `%s' is false", #expr);                    \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_DEBUG(expr, val)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG("Check failed: expression `%s' is false", #expr);                    \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_INFO(expr, val)                                                            \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO("Check failed: expression `%s' is false", #expr);                     \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_WARN(expr, val)                                                            \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN("Check failed: expression `%s' is false", #expr);                     \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_ERROR(expr, val)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR("Check failed: expression `%s' is false", #expr);                    \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_FALSE_GOTO_TRACE(expr, label)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE("Check failed: expression `%s' is false", #expr);                    \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_DEBUG(expr, label)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG("Check failed: expression `%s' is false", #expr);                    \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_INFO(expr, label)                                                            \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO("Check failed: expression `%s' is false", #expr);                     \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_WARN(expr, label)                                                            \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN("Check failed: expression `%s' is false", #expr);                     \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_ERROR(expr, label)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR("Check failed: expression `%s' is false", #expr);                    \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define IF_NULL_RETURN_TRACE_ERRNO(ptr)                                                            \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_DEBUG_ERRNO(ptr)                                                            \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_INFO_ERRNO(ptr)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_WARN_ERRNO(ptr)                                                             \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETURN_ERROR_ERRNO(ptr)                                                            \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_NULL_RETVAL_TRACE_ERRNO(ptr, val)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_DEBUG_ERRNO(ptr, val)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_INFO_ERRNO(ptr, val)                                                        \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_WARN_ERRNO(ptr, val)                                                        \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_NULL_RETVAL_ERROR_ERRNO(ptr, val)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_NULL_GOTO_TRACE_ERRNO(ptr, label)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			TRACE_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_DEBUG_ERRNO(ptr, label)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			DEBUG_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_INFO_ERRNO(ptr, label)                                                        \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			INFO_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_WARN_ERRNO(ptr, label)                                                        \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			WARN_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                    \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_NULL_GOTO_ERROR_ERRNO(ptr, label)                                                       \
	do {                                                                                       \
		if ((ptr) == NULL) {                                                               \
			ERROR_ERRNO("Check failed: pointer `%s' is NULL", #ptr);                   \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define IF_TRUE_RETURN_TRACE_ERRNO(expr)                                                           \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_DEBUG_ERRNO(expr)                                                           \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_INFO_ERRNO(expr)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO_ERRNO("Check failed: expression `%s' is true", #expr);                \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_WARN_ERRNO(expr)                                                            \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN_ERRNO("Check failed: expression `%s' is true", #expr);                \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETURN_ERROR_ERRNO(expr)                                                           \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_TRUE_RETVAL_TRACE_ERRNO(expr, val)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_DEBUG_ERRNO(expr, val)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_INFO_ERRNO(expr, val)                                                       \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO_ERRNO("Check failed: expression `%s' is true", #expr);                \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_WARN_ERRNO(expr, val)                                                       \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN_ERRNO("Check failed: expression `%s' is true", #expr);                \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_TRUE_RETVAL_ERROR_ERRNO(expr, val)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR_ERRNO("Check failed: expression `%s' is true", #expr);               \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_TRUE_GOTO_TRACE_ERRNO(expr, label)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			TRACE_ERRNO("Check failed: expression `%s' is true", #expr);               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_DEBUG_ERRNO(expr, label)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			DEBUG_ERRNO("Check failed: expression `%s' is true", #expr);               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_INFO_ERRNO(expr, label)                                                       \
	do {                                                                                       \
		if (expr) {                                                                        \
			INFO_ERRNO("Check failed: expression `%s' is true", #expr);                \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_WARN_ERRNO(expr, label)                                                       \
	do {                                                                                       \
		if (expr) {                                                                        \
			WARN_ERRNO("Check failed: expression `%s' is true", #expr);                \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_TRUE_GOTO_ERROR_ERRNO(expr, label)                                                      \
	do {                                                                                       \
		if (expr) {                                                                        \
			ERROR_ERRNO("Check failed: expression `%s' is true", #expr);               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define IF_FALSE_RETURN_TRACE_ERRNO(expr)                                                          \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_DEBUG_ERRNO(expr)                                                          \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_INFO_ERRNO(expr)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO_ERRNO("Check failed: expression `%s' is false", #expr);               \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_WARN_ERRNO(expr)                                                           \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN_ERRNO("Check failed: expression `%s' is false", #expr);               \
			return;                                                                    \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETURN_ERROR_ERRNO(expr)                                                          \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return;                                                                    \
		}                                                                                  \
	} while (0)

#define IF_FALSE_RETVAL_TRACE_ERRNO(expr, val)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_DEBUG_ERRNO(expr, val)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_INFO_ERRNO(expr, val)                                                      \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO_ERRNO("Check failed: expression `%s' is false", #expr);               \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_WARN_ERRNO(expr, val)                                                      \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN_ERRNO("Check failed: expression `%s' is false", #expr);               \
			return (val);                                                              \
		}                                                                                  \
	} while (0)
#define IF_FALSE_RETVAL_ERROR_ERRNO(expr, val)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR_ERRNO("Check failed: expression `%s' is false", #expr);              \
			return (val);                                                              \
		}                                                                                  \
	} while (0)

#define IF_FALSE_GOTO_TRACE_ERRNO(expr, label)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			TRACE_ERRNO("Check failed: expression `%s' is false", #expr);              \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_DEBUG_ERRNO(expr, label)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			DEBUG_ERRNO("Check failed: expression `%s' is false", #expr);              \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_INFO_ERRNO(expr, label)                                                      \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			INFO_ERRNO("Check failed: expression `%s' is false", #expr);               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_WARN_ERRNO(expr, label)                                                      \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			WARN_ERRNO("Check failed: expression `%s' is false", #expr);               \
			goto label;                                                                \
		}                                                                                  \
	} while (0)
#define IF_FALSE_GOTO_ERROR_ERRNO(expr, label)                                                     \
	do {                                                                                       \
		if (!(expr)) {                                                                     \
			ERROR_ERRNO("Check failed: expression `%s' is false", #expr);              \
			goto label;                                                                \
		}                                                                                  \
	} while (0)

#define HOURS_TO_MILLISECONDS(hours) ((hours)*60 * 60 * 1000)

/**
 * Get the number of elements of an array.
 */
#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))

/**
 * Indicates that a function parameter is not used in the function body.
 * This may be required in order to prevent compiler errors.
 * The macro is used in prefix notation, e.g., @code void f(UNUSED char *p) @endcode
 */
#define UNUSED __attribute__((unused))

/**
 * Helper macro to cast a function pointer to a void pointer.
 */
#ifdef __GNUC__
#define CAST(type) __extension__(type)
#define CAST_FUNCPTR_VOIDPTR __extension__(void *)
#else
#define CAST(type) (type)
#define CAST_FUNCPTR_VOIDPTR (void *)
#endif

// math helpers
#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#ifndef ABS
#define ABS(a) (((a) < 0) ? -(a) : (a))
#endif

/**
 * Do normal addition, i.e. +, but abort if
 * overflow is detected. This is helpful when we
 * calculate with untrusted parameters and the result
 * can (directly or indirectly) influence a security-sensitive
 * variable (e.g. the size of a buffer).
 *
 * Example:
 * int a = ADD_WITH_OVERFLOW_CHECK(10, 20); // results in 30
 * int b = ADD_WITH_OVERFLOW_CHECK(100, MAX_INT); // aborts
 **/
#ifndef ADD_WITH_OVERFLOW_CHECK
#define ADD_WITH_OVERFLOW_CHECK(x, y)                                                              \
	__extension__({                                                                            \
		typeof(x) _x = (x);                                                                \
		typeof(y) _y = (y);                                                                \
		typeof(x + y) _res;                                                                \
		if (__builtin_add_overflow(_x, _y, &_res)) {                                       \
			FATAL("Detected addition integer overflow.");                              \
		}                                                                                  \
		(_res);                                                                            \
	})
#endif

/**
 * Do normal subtraction, i.e. -, but abort if
 * overflow is detected. This is helpful when we
 * calculate with untrusted parameters and the result
 * can (directly or indirectly) influence a security-sensitive
 * variable (e.g. the size of a buffer).
 *
 * Example:
 * int a = SUB_WITH_OVERFLOW_CHECK(10, 20); // results in -10
 * int b = SUB_WITH_OVERFLOW_CHECK(MIN_INT, 1); // aborts
 **/
#ifndef SUB_WITH_OVERFLOW_CHECK
#define SUB_WITH_OVERFLOW_CHECK(x, y)                                                              \
	__extension__({                                                                            \
		typeof(x) _x = (x);                                                                \
		typeof(y) _y = (y);                                                                \
		typeof(x - y) _res;                                                                \
		if (__builtin_sub_overflow(_x, _y, &_res)) {                                       \
			FATAL("Detected subtraction integer overflow.");                           \
		}                                                                                  \
		(_res);                                                                            \
	})
#endif

/**
 * Do normal multiplication, i.e. *, but abort if
 * overflow is detected. This is helpful when we
 * calculate with untrusted parameters and the result
 * can (directly or indirectly) influence a security-sensitive
 * variable (e.g. the size of a buffer).
 *
 * Example:
 * int a = MUL_WITH_OVERFLOW_CHECK(10, 20); // results in 200
 * int b = MUL_WITH_OVERFLOW_CHECK(MIN_INT, 2); // aborts
 **/
#ifndef MUL_WITH_OVERFLOW_CHECK
#define MUL_WITH_OVERFLOW_CHECK(x, y)                                                              \
	__extension__({                                                                            \
		typeof(x) _x = (x);                                                                \
		typeof(y) _y = (y);                                                                \
		typeof(x * y) _res;                                                                \
		if (__builtin_mul_overflow(_x, _y, &_res)) {                                       \
			FATAL("Detected multiplication integer overflow.");                        \
		}                                                                                  \
		(_res);                                                                            \
	})
#endif

#endif /* MACRO_H */
