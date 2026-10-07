/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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

/**
 * @file bounds_safety.h
 *
 * Compatibility header for Clang's -fbounds-safety annotations.
 *
 * When compiled with the swiftlang Clang fork (which ships <ptrcheck.h>),
 * this header simply includes <ptrcheck.h>, which provides both real
 * annotations (under -fbounds-safety) and no-op fallbacks (without it).
 * On GCC or stock Clang where <ptrcheck.h> is absent, this header defines
 * all annotations as no-ops, preserving full build compatibility.
 *
 * Usage: include this header before using any bounds annotations in .h or .c
 * files. Annotate pointer parameters that have an associated size argument:
 *
 *   void foo(const char *__counted_by(len) buf, size_t len);
 */

#ifndef BOUNDS_SAFETY_H
#define BOUNDS_SAFETY_H

#if defined(__has_include) && __has_include(<ptrcheck.h>)
/* swiftlang Clang fork: <ptrcheck.h> provides real annotations when
   * -fbounds-safety is active and comprehensive no-ops when it is not. */
#include <ptrcheck.h>
#else
/* GCC or stock Clang without ptrcheck.h: annotations are no-ops.
   *
   * The __counted_by/__sized_by family is guarded with #ifndef: the Linux
   * UAPI header <linux/stddef.h> (kernel >= 6.11) also defines __counted_by
   * (as an empty no-op) for flexible-array members, so an unconditional
   * redefinition here trips -Wmacro-redefined under -Werror whenever a
   * translation unit pulls in a UAPI header before this one.  Cooperate the
   * same way the kernel header does and defer to any existing definition. */
#ifndef __counted_by
#define __counted_by(N)
#endif
#ifndef __sized_by
#define __sized_by(N)
#endif
#ifndef __counted_by_or_null
#define __counted_by_or_null(N)
#endif
#ifndef __sized_by_or_null
#define __sized_by_or_null(N)
#endif
#define __ended_by(E)
#define __single
#define __null_terminated
#define __unsafe_indexable
#define __terminated_by(T)
#define __unsafe_forge_single(T, P) ((T)(P))
#define __unsafe_forge_bidi_indexable(T, P, S) ((T)(P))
#define __unsafe_forge_null_terminated(T, P) ((T)(P))
#define __BOUNDS_SAFETY_IGNORE_REST(P, ...) (P)
#define __unsafe_terminated_by_from_indexable(T, ...)                                              \
	__BOUNDS_SAFETY_IGNORE_REST(__VA_ARGS__, ((void)0))
#define __unsafe_null_terminated_from_indexable(...)                                               \
	__unsafe_terminated_by_from_indexable(0, __VA_ARGS__)
#define __null_terminated_to_indexable(P) (P)
#define __unsafe_null_terminated_to_indexable(P) (P)
#define __ptrcheck_abi_assume_single()
#define __ptrcheck_abi_assume_unsafe_indexable()
#define __array_decay_discards_count_in_parameters
#endif

/* Set when full enforcement is active (bounds_test files gate on this). */
#ifdef __clang__
#if __has_feature(bounds_safety)
#define BOUNDS_SAFETY_ENABLED 1
#endif
#endif

#endif /* BOUNDS_SAFETY_H */
