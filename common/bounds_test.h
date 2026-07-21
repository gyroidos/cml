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
 * @file bounds_test.h
 *
 * Shared harness for the standalone -fbounds-safety enforcement tests
 * (the common/ *.bounds_test.c files).
 *
 * Each test file defines a set of violate_*() functions that deliberately call
 * a bounds-annotated function with a length larger than the real buffer, plus a
 * NULL-terminated cases[] array pairing each with a name.  The file then invokes
 * BOUNDS_TEST_MAIN() to generate its entry point.
 *
 * Without the swiftlang Clang fork (i.e. BOUNDS_SAFETY_ENABLED undefined),
 * BOUNDS_TEST_MAIN() expands to a stub main() that prints SKIP and returns 77
 * (autotools-style skip exit code); the file's violate_*()/cases[] should live
 * inside an #ifdef BOUNDS_SAFETY_ENABLED so they are not compiled there.
 *
 * With -fbounds-safety active, it expands to a runner that forks each violation
 * in a child and asserts the child was killed by a signal (the bounds trap).
 *
 * Typical usage:
 *   #include "bounds_test.h"
 *   #include "hex.h"
 *   #include "mem.h"
 *
 *   #ifdef BOUNDS_SAFETY_ENABLED
 *   static void violate_foo(void) { ... }
 *   static struct bounds_test_case cases[] = {
 *           { "foo OOB", violate_foo },
 *           { NULL, NULL }
 *   };
 *   #endif
 *
 *   BOUNDS_TEST_MAIN("hex.bounds_test", cases)
 */

#ifndef BOUNDS_TEST_H
#define BOUNDS_TEST_H

#include "bounds_safety.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef BOUNDS_SAFETY_ENABLED

/*
 * Built without -fbounds-safety: emit a stub that skips.  cases_array is
 * intentionally not referenced, so it need not exist in this build.
 */
#define BOUNDS_TEST_MAIN(module, cases_array)                                                      \
	int main(void)                                                                             \
	{                                                                                          \
		fprintf(stderr,                                                                    \
			"SKIP: " module " requires -fbounds-safety.\n"                             \
			"Build with: CC=/path/to/bs-clang BOUNDS_SAFETY=y make bounds_test\n");    \
		return 77; /* autotools-style skip exit code */                                    \
	}

#else

typedef void (*bounds_violation_fn)(void);

struct bounds_test_case {
	const char *name;
	bounds_violation_fn fn;
};

/*
 * Fork a child that calls fn().  Returns 1 if the child was killed by a
 * signal (bounds-safety trap), 0 if it exited normally, -1 on error.
 */
static int
expect_trap(bounds_violation_fn fn)
{
	fflush(stdout);
	fflush(stderr);
	pid_t pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		fn();
		_exit(0);
	}
	int status;
	if (waitpid(pid, &status, 0) < 0)
		return -1;
	return WIFSIGNALED(status) ? 1 : 0;
}

/*
 * Run every case: a case passes only if its violation trapped.  Returns 1 if
 * any case failed to trap (or errored), 0 if all trapped.  n counts the array
 * entries (including the { NULL, NULL } sentinel, on which iteration stops).
 */
static int __attribute__((unused))
bounds_test_run(struct bounds_test_case *__counted_by(n) cases, size_t n)
{
	int passed = 0;
	int failed = 0;

	for (size_t i = 0; i < n && cases[i].name; i++) {
		int r = expect_trap(cases[i].fn);
		if (r == 1) {
			printf("  PASS  %s (trapped)\n", cases[i].name);
			passed++;
		} else if (r == 0) {
			printf("  FAIL  %s (no trap — bounds not enforced)\n", cases[i].name);
			failed++;
		} else {
			printf("  ERROR %s (fork/wait failed)\n", cases[i].name);
			failed++;
		}
	}

	printf("\n%d passed, %d failed\n", passed, failed);
	return failed ? 1 : 0;
}

#define BOUNDS_TEST_MAIN(module, cases_array)                                                      \
	int main(void)                                                                             \
	{                                                                                          \
		(void)module;                                                                      \
		return bounds_test_run(cases_array,                                                \
				       sizeof(cases_array) / sizeof((cases_array)[0]));            \
	}

#endif /* BOUNDS_SAFETY_ENABLED */

#endif /* BOUNDS_TEST_H */
