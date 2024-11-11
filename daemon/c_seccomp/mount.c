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
 * @file c_seccomp/mount.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for the
 * mount() system call.
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"

#include <common/file.h>
#include <common/macro.h>
#include <common/mem.h>
#include <common/ns.h>

#include "seccomp.h"

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <sys/mount.h>

#include <linux/capability.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

struct mount_fork_data {
	const char *source;
	const char *target;
	const char *filesystem;
	unsigned long mountflags;
	const void *data;
};

static int
c_seccomp_do_mount_fork(const void *data)
{
	const struct mount_fork_data *params = data;
	ASSERT(params);

	DEBUG("Executing mount(source:%s, target:%s, fs:%s, flags:%lu, data:%s) in mountns of container",
	      params->source, params->target, params->filesystem, params->mountflags,
	      params->data ? (char *)params->data : "null");

	if (-1 == mount(params->source, params->target, params->filesystem, params->mountflags,
			params->data)) {
		ERROR_ERRNO("Failed to execute mount");
		return -1;
	}

	return 0;
}

int
c_seccomp_emulate_mount(c_seccomp_t *seccomp, struct seccomp_notif *req,
			struct seccomp_notif_resp *resp)
{
	int ret_mount = 0;
	char *source = NULL;
	char *target = NULL;
	char *filesystem = NULL;
	unsigned long mountflags = 0;
	void *data = NULL;

	/*
	 * in any case of error just continue the syscall in the kernel.
	 * We just want to strip out SB_I_NODEV from file systems which may carry
	 * device nodes, which are currently tmpfs, ramfs or overlayfs
	 */
	resp->error = 0;
	resp->val = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

	/* We only handle mount if filesystem is set */
	if (0 == req->data.args[2])
		goto out;

	TRACE("Got mount() from pid %d, const char *source: %p, const char *target: %p, "
	      "const char * filesystem: %p, mountflags: %lld, const void *data: %p",
	      req->pid, CAST_UINT_VOIDPTR req->data.args[0], CAST_UINT_VOIDPTR req->data.args[1],
	      CAST_UINT_VOIDPTR req->data.args[2], req->data.args[3],
	      CAST_UINT_VOIDPTR req->data.args[4]);

	mountflags = req->data.args[3];

	/* Check cap of target pid in its namespace */
	if (!c_seccomp_capable(req->pid, CAP_SYS_ADMIN)) {
		ERROR("Missing CAP_SYS_ADMIN for process %d!", req->pid);
		goto out;
	}

	int max_len = PATH_MAX;
	if (!(filesystem = (char *)c_seccomp_fetch_vm_new(
		      seccomp, req->pid, CAST_UINT_VOIDPTR req->data.args[2], max_len))) {
		ERROR_ERRNO("Failed to fetch filesystem string");
		goto out;
	}

	if (strcmp("tmpfs", filesystem) && strcmp("overlay", filesystem) &&
	    strcmp("ramfs", filesystem)) {
		TRACE("Unsuported filesystem, we only allow tmpfs | overlay | ramfs!");
		goto out;
	}

	if (req->data.args[0]) {
		if (!(source = (char *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, CAST_UINT_VOIDPTR req->data.args[0], max_len))) {
			ERROR_ERRNO("Failed to fetch source string");
			goto out;
		}
	}

	if (req->data.args[1]) {
		if (!(target = (char *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, CAST_UINT_VOIDPTR req->data.args[1], max_len))) {
			ERROR_ERRNO("Failed to fetch target string");
			goto out;
		}
	}

	/*
	 * some user space payload such as systemd privat devices, use proc related symlinks,
	 * e.g. /proc/self/fd/4, as path. We have to read the link and put the real path as
	 * target in those cases.
	 */
	if (strstr(target, "/proc")) {
		char buf[PATH_MAX] = { 0 };

		TRACE("Sanitize proc related path: %s", target);

		if (1 == sscanf(target, "/proc/self/%s", buf)) {
			mem_free0(target);
			target = mem_printf("/proc/%d/%s", req->pid, buf);

			TRACE("Sanitized new path: %s", target);

			if (file_is_link(target)) {
				if (readlink(target, buf, PATH_MAX) < 0)
					TRACE_ERRNO("Readlink of %s failed.", target);
				else {
					mem_free0(target);
					target = mem_strdup(buf);
				}
			}

			TRACE("Sanitized new path real target: %s", target);
		}
	}

	if (req->data.args[4]) {
		if (!(data = c_seccomp_fetch_vm_new(
			      seccomp, req->pid, CAST_UINT_VOIDPTR req->data.args[4], max_len))) {
			ERROR_ERRNO("Failed to fetch data string");
			goto out;
		}
	}

	DEBUG("Executing mount on behalf of container %s", container_get_name(seccomp->container));

	struct mount_fork_data mount_params = { .source = source,
						.target = target,
						.filesystem = filesystem,
						.mountflags = mountflags,
						.data = data };
	if (-1 == (ret_mount = namespace_exec(req->pid, CLONE_NEWNS,
					      container_get_uid(seccomp->container), CAP_SYS_ADMIN,
					      c_seccomp_do_mount_fork, &mount_params))) {
		ERROR_ERRNO("Failed to execute mount");
		goto out;
	}

	DEBUG("mount returned %d", ret_mount);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_mount;
	/* mount emulated by us, so clear SECCOMP_USER_NOTIF_FLAG_CONTINUE flag */
	resp->flags = 0;

out:
	if (source)
		mem_free0(source);
	if (target)
		mem_free0(target);
	if (filesystem)
		mem_free0(filesystem);
	if (data)
		mem_free0(data);

	return ret_mount;
}
