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

#include "common/macro.h"
#include "common/dir.h"
#include "common/mem.h"

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/syscall.h>

int
setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}

static void
usage(char *pname)
{
	ERROR("Usage: %s container-pid cmd [arg...]\n", pname);
	exit(-1);
}

#define MAX_NS 10
int fd[MAX_NS] = { 0 };

static int
setns_cb(const char *path, const char *file, void *data)
{
	int *i = data;

	char *ns_file = mem_printf("%s%s", path, file);
	TRACE("Opening namespace file %s", ns_file);

	if (*i >= MAX_NS) {
		ERROR("Too many namespace files found in %s", path);
		goto error;
	}

	fd[*i] = open(ns_file, O_RDONLY);
	if (fd[*i] == -1) {
		ERROR_ERRNO("Could not open namespace file %s", ns_file);
		goto error;
	}

	*i = *i + 1;

	mem_free(ns_file);
	return 0;

error:
	mem_free(ns_file);
	abort();
}

int
main(int argc, char *argv[])
{
	logf_register(&logf_test_write, stderr);

	if (argc < 3)
		usage(argv[0]);

	pid_t pid = strtol(argv[1], NULL, 10);
	if (!pid) {
		ERROR("No valid PID given");
		usage(argv[0]);
	}

	char *folder = mem_printf("/proc/%d/ns/", pid);

	int i = 0;
	if (dir_foreach(folder, &setns_cb, &i)) {
		FATAL("Could not traverse PID dir in procfs, wrong PID?");
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) { /* Join that namespace */
			FATAL_ERRNO("Could not join namespace");
		}
	}

	TRACE("Successfully joined all namespaces, now forking...");

	pid = fork();
	if (pid == -1) {
		FATAL_ERRNO("fork failed");
	}

	if (pid != 0) { /* Parent */
		if (waitpid(-1, NULL, 0) == -1) /* Wait for child */
			FATAL_ERRNO("waitpid failed");
		exit(0);
	}

	INFO("Fork successful, now executing given command...");

	/* Child falls through to code below */
	execvp(argv[2], &argv[2]);
	ERROR_ERRNO("execvp failed");
}
