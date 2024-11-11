/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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
 * @file c_seccomp/adjtimex.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for the adjtimex,
 * clock_adjtime and clock_settime system calls. We call this module 'init_module' analogous
 * to the manpage which lists adjtimex() and clock_adjtimex() syscalls under man adjtimex(2).
 * Further, we include the clock_settime in this file even if it has an own manpage. 
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"

#include <common/macro.h>
#include <common/mem.h>
#include <common/proc.h>

#include "seccomp.h"

#include <sys/syscall.h>
#include <sys/timex.h>

#include <linux/capability.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

int
c_seccomp_emulate_adjtime(c_seccomp_t *seccomp, struct seccomp_notif *req,
			  struct seccomp_notif_resp *resp)
{
	int ret_adjtime = 0;
	struct timex *timex = NULL;

	if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
		DEBUG("Blocking call to SYS_clock_adjtime by PID %d", req->pid);
		goto out;
	}

	DEBUG("Got clock_adjtime, clk_id: %lld, struct timex *: %p", req->data.args[0],
	      CAST_UINT_VOIDPTR req->data.args[1]);

	// Check cap of target pid in its namespace
	if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
		ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
		goto out;
	}

	if (CLOCK_REALTIME != req->data.args[0]) {
		DEBUG("Attempt of container %s to execute clock_settime on clock %llx blocked",
		      uuid_string(compartment_get_uuid(seccomp->compartment)), req->data.args[0]);
		goto out;
	}

	if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(seccomp, req->pid,
							     CAST_UINT_VOIDPTR req->data.args[1],
							     sizeof(struct timex)))) {
		ERROR_ERRNO("Failed to fetch struct timex");
		goto out;
	}

	DEBUG("Executing clock_adjtime on behalf of container");
	if (-1 == (ret_adjtime = clock_adjtime(CLOCK_REALTIME, timex))) {
		ERROR_ERRNO("Failed to execute clock_adjtime");
		goto out;
	}

	DEBUG("clock_adjtime returned %d", ret_adjtime);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_adjtime;

out:
	if (timex)
		mem_free(timex);

	return ret_adjtime;
}

int
c_seccomp_emulate_adjtimex(c_seccomp_t *seccomp, struct seccomp_notif *req,
			   struct seccomp_notif_resp *resp)
{
	int ret_adjtimex = 0;
	struct timex *timex = NULL;

	if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
		DEBUG("Blocking call to SYS_adjtimex by PID %d", req->pid);
		goto out;
	}

	DEBUG("Got adjtimex, struct timex *: %p", CAST_UINT_VOIDPTR req->data.args[0]);

	// Check cap of target pid in its namespace
	if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
		ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
		goto out;
	}

	if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(seccomp, req->pid,
							     CAST_UINT_VOIDPTR req->data.args[0],
							     sizeof(struct timex)))) {
		ERROR_ERRNO("Failed to fetch struct timex");
		goto out;
	}

	DEBUG("Executing adjtimex on behalf of container");
	if (-1 == (ret_adjtimex = adjtimex(timex))) {
		ERROR_ERRNO("Failed to execute adjtimex");
		goto out;
	}

	DEBUG("adjtimex returned %d", ret_adjtimex);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_adjtimex;

out:
	if (timex)
		mem_free(timex);

	return ret_adjtimex;
}

int
c_seccomp_emulate_settime(c_seccomp_t *seccomp, struct seccomp_notif *req,
			  struct seccomp_notif_resp *resp)
{
	int ret_settime = 0;
	struct timespec *timespec = NULL;

	if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
		DEBUG("Blocking call to SYS_clock_settime by PID %d", req->pid);
		goto out;
	}

	DEBUG("Got clock_settime, clockid: %lld, struct timespec *: %p", req->data.args[0],
	      CAST_UINT_VOIDPTR req->data.args[1]);

	// Check cap of target pid in its namespace
	if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
		ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
		goto out;
	}

	if (CLOCK_REALTIME != req->data.args[0]) {
		DEBUG("Attempt of container %s to execute clock_settime on clock %llx blocked",
		      uuid_string(compartment_get_uuid(seccomp->compartment)), req->data.args[0]);
		goto out;
	}

	if (!(timespec = (struct timespec *)c_seccomp_fetch_vm_new(
		      seccomp, req->pid, CAST_UINT_VOIDPTR req->data.args[1],
		      sizeof(struct timespec)))) {
		ERROR_ERRNO("Failed to fetch struct timespec");
		goto out;
	}

	DEBUG("Executing clock_settime on behalf of container");
	if (-1 == (ret_settime = clock_settime(CLOCK_REALTIME, timespec))) {
		ERROR_ERRNO("Failed to execute clock_settime");
		goto out;
	}

	DEBUG("clock_settime returned %d", ret_settime);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_settime;

out:
	if (timespec)
		mem_free(timespec);

	return ret_settime;
}
