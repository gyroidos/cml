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
 * @file c_seccomp/mknod.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for the mknod() and mknodat()
 * system calls.
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"

#include <common/macro.h>
#include <common/mem.h>
#include <common/proc.h>
#include <common/ns.h>

#include "seccomp.h"

#include <sched.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/stat.h>

#include <linux/capability.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

struct mknodat_fork_data {
	int dirfd;
	const char *pathname;
	const char *cwd;
	mode_t mode;
	dev_t dev;
};

static int
c_seccomp_do_mknodat_fork(const void *data)
{
	const struct mknodat_fork_data *params = data;
	ASSERT(params);

	if (params->cwd && chdir(params->cwd)) {
		ERROR_ERRNO("Failed to switch to working directory (%s) of target process",
			    params->cwd);
		return -1;
	}

	DEBUG("Executing mknodat %s in mountns of container", params->pathname);
	if (-1 == mknodat(params->dirfd, params->pathname, params->mode, params->dev)) {
		ERROR_ERRNO("Failed to execute mknodat");
		return -1;
	}

	return 0;
}

int
c_seccomp_emulate_mknodat(c_seccomp_t *seccomp, struct seccomp_notif *req,
			  struct seccomp_notif_resp *resp)
{
	int ret_mknodat = 0;
	const char *syscall_name = req->data.nr == SYS_mknodat ? "mknodat" : "mknod";
	int dirfd = -1;
	int arg_offset = 0;
	char *pathname = NULL;
	char *cwd = NULL;
	int cml_dirfd = -1;

	/*
	 * We emulate mknod() by mknodat() for code dedup:
	 *
	 * mknod() and mknodat() have the same arguments, except that
	 * mknodat has dirfd as first argument:
	 *   int mknod(const char *pathname, mode_t mode, dev_t dev);
	 *   int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
	 *
	 * We therefore use an offset +1 for the data.args array to
	 * retrieve syscall parameters from seccomp req in case of
	 * mknodat() and set dirfd to AT_FDCWD in case of mknod()
	 */
	if (req->data.nr == SYS_mknodat) {
		DEBUG("Got %s() from pid %d, fd: %lld, const char *pathname: %p, mode: %lld, dev: %lld",
		      syscall_name, req->pid, req->data.args[0], (void *)req->data.args[1],
		      req->data.args[2], req->data.args[3]);
		dirfd = req->data.args[arg_offset];
		arg_offset++;
	} else { // SYS_mknod
		DEBUG("Got %s() from pid %d, const char *pathname: %p, mode: %lld, dev: %lld",
		      syscall_name, req->pid, (void *)req->data.args[0], req->data.args[1],
		      req->data.args[2]);
		dirfd = AT_FDCWD;
	}

	mode_t mode = req->data.args[1 + arg_offset];
	dev_t dev = req->data.args[2 + arg_offset];

	/* Check cap of target pid in its namespace */
	if (!c_seccomp_capable(req->pid, CAP_MKNOD)) {
		ERROR("Missing CAP_MKNOD for process %d!", req->pid);
		goto out;
	}

	/* We only handle char and block devices, due to our seccomp filter */
	char dev_type = S_ISCHR(mode) ? 'c' : 'b';

	/* Check if dev is allowed (c_cgroups submodule) */
	if (!container_is_device_allowed(seccomp->container, dev_type, major(dev), minor(dev))) {
		ERROR("Missing cgroup permission for device (%c %d:%d) in process %d!", dev_type,
		      major(dev), minor(dev), req->pid);
		goto out;
	}

	int pathname_max_len = PATH_MAX;
	pathname = mem_alloc0(pathname_max_len);
	if (!(pathname = (char *)c_seccomp_fetch_vm_new(seccomp, req->pid,
							(void *)req->data.args[0 + arg_offset],
							pathname_max_len))) {
		ERROR_ERRNO("Failed to fetch pathname string");
		goto out;
	}

	cml_dirfd = AT_FDCWD;
	if (dirfd != AT_FDCWD) {
		int pidfd;
		if (-1 == (pidfd = pidfd_open(req->pid, 0))) {
			ERROR_ERRNO("Could not open pidfd for emulating %s()", syscall_name);
			goto out;
		}

		cml_dirfd = pidfd_getfd(pidfd, dirfd, 0);
		if (cml_dirfd < 0) {
			ERROR_ERRNO("Could not open dirfd in target process for emulating %s()",
				    syscall_name);
			goto out;
		}
	}

	cwd = proc_get_cwd_new(req->pid);

	DEBUG("Emulating %s by executing mknodat %s on behalf of container", syscall_name,
	      pathname);

	struct mknodat_fork_data mknodat_params = {
		.dirfd = cml_dirfd, .pathname = pathname, .cwd = cwd, .mode = mode, .dev = dev
	};
	if (-1 == (ret_mknodat = namespace_exec(req->pid, CLONE_NEWNS,
						container_get_uid(seccomp->container), CAP_MKNOD,
						c_seccomp_do_mknodat_fork, &mknodat_params))) {
		ERROR_ERRNO("Failed to execute mknodat");
		goto out;
	}

	DEBUG("mknodat returned %d", ret_mknodat);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_mknodat;

out:
	if (cwd)
		mem_free0(cwd);
	if (pathname)
		mem_free0(pathname);
	if ((AT_FDCWD != cml_dirfd) && (cml_dirfd >= 0))
		close(cml_dirfd);

	return ret_mknodat;
}
