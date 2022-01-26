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

#include "scd.h"
#include "scd_shared.h"

#include "common/macro.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/sock.h"
#include "common/proc.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

// clang-format off
#define SCD_CONTROL_SOCKET SOCK_PATH(scd-control)
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

static pid_t scd_pid;

static pid_t
scd_fork_and_exec(void)
{
	TRACE("Starting scd..");

	int status;
	pid_t pid = fork();
	char *const param_list[] = { SCD_BINARY_NAME, NULL };

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", SCD_BINARY_NAME);
		return -1;
	case 0:
		execvp((const char *)param_list[0], param_list);
		FATAL_ERRNO("Could not execvp %s", SCD_BINARY_NAME);
		return -1;
	default:
		// Just check if the child is alive but do not wait
		if (waitpid(pid, &status, WNOHANG) != 0) {
			ERROR("Failed to start %s", SCD_BINARY_NAME);
			return -1;
		}
		return pid;
	}
	return -1;
}

int
scd_init(bool start_daemon)
{
	int sock = -1;

	// In hosted mode, the init scripts should take care of correct scd initialization and start-up
	if (start_daemon) {
		// if device.cert is not present, start scd to initialize device (provisioning mode)
		if (!file_exists(DEVICE_CERT_FILE)) {
			INFO("Starting scd in Provisioning / Installing Mode");
			// Start the SCD in provisioning mode
			const char *const args[] = { SCD_BINARY_NAME, NULL };
			IF_FALSE_RETVAL_TRACE(proc_fork_and_execvp(args) == 0, -1);
		}

		// Start SCD and wait for control interface
		scd_pid = scd_fork_and_exec();
		IF_TRUE_RETVAL_TRACE(scd_pid == -1, -1);
	} else {
		DEBUG("Skipping tpm2d launch as requested");
	}

	size_t retries = 0;
	do {
		NANOSLEEP(0, 500000000)
		sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
		retries++;
		TRACE("Retry %zu connecting to scd", retries);
	} while (sock < 0 && retries < 10);

	if (sock < 0) {
		ERROR("Failed to connect to scd");
		return -1;
	}

	// allow access from namespaced child before chroot and execv of init
	if (chmod(SCD_CONTROL_SOCKET, 00777))
		WARN("could not change access rights for scd control socket");

	return 0;
}

void
scd_cleanup(void)
{
	IF_TRUE_RETURN_TRACE(scd_pid == -1);
	DEBUG("Stopping %s process with pid=%d!", SCD_BINARY_NAME, scd_pid);
	kill(scd_pid, SIGTERM);
}
