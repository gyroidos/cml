/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <linux/capability.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <stdbool.h>

#include <grp.h>

#include "macro.h"
#include "mem.h"
#include "dir.h"
#include "event.h"
#include "file.h"
#include "proc.h"

static int
capset(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);
}

static int
namespace_setuid_keep_cap(int uid, int cap)
{
	/*
	 * We change to the mapped root user (uid) in the container.
	 * Otherwise, if we just use system root with uid 0, we cannot write
	 * mounts mounted by the container itself, e.g. '/tmp'. This would
	 * result in an "errno (75: Value too large for defined data type)".
	 * To still allow privileged operations using system-wide capabilities,
	 * we need to preserve the coressponding 'cap'.
	 */
	IF_TRUE_RETVAL(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), -1);

	if (setgid(uid) < 0) {
		ERROR_ERRNO("Could not set gid to '%d' in target ns", uid);
		return -1;
	}

	if (setuid(uid) < 0) {
		ERROR_ERRNO("Could not change to mapped root '(%d)' in target ns", uid);
		return -1;
	}

	struct __user_cap_header_struct cap_header = { .version = _LINUX_CAPABILITY_VERSION_3,
						       .pid = 0 };
	struct __user_cap_data_struct cap_data[2];
	mem_memset0(&cap_data, sizeof(cap_data));

	cap_data[CAP_TO_INDEX(cap)].permitted |= CAP_TO_MASK(cap);
	cap_data[CAP_TO_INDEX(cap)].effective |= CAP_TO_MASK(cap);

	if (capset(&cap_header, cap_data)) {
		ERROR_ERRNO("Could not set cap (%d) effective!", cap);
		return -1;
	}

	return 0;
}

int
namespace_setuid0()
{
	TRACE("uid %d, euid %d", getuid(), geteuid());
	if (setuid(0) < 0) {
		ERROR_ERRNO("Could not become root 'setuid(0)' in new userns");
		return -1;
	}
	if (setgid(0) < 0) {
		ERROR_ERRNO("Could not set gid to '0' in new userns");
		return -1;
	}
	if (setgroups(0, NULL) < 0) {
		ERROR_ERRNO("Could not setgroups to '0' in new userns");
		return -1;
	}
	TRACE("uid %d, euid %d", getuid(), geteuid());
	return 0;
}

int
setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}

static bool
ns_is_self_userns_file(char *file)
{
	struct stat s, userns_s;
	IF_TRUE_RETVAL_TRACE(stat(file, &s) == -1, false);
	IF_TRUE_RETVAL_TRACE(stat("/proc/self/ns/user", &userns_s) == -1, false);

	return (s.st_dev == userns_s.st_dev) && (s.st_ino == userns_s.st_ino) ? true : false;
}

int
do_join_namespace(const char *namespace, const int pid)
{
	char *target_namespace_path = NULL;
	char *target_namespace_id = mem_alloc0(40);
	char *current_namespace_path = NULL;
	char *current_namespace_id = mem_alloc0(40);
	ssize_t len = -1;
	int ns_fd = -1;

	target_namespace_path = mem_printf("/proc/%d/ns/%s", pid, namespace);
	current_namespace_path = mem_printf("/proc/self/ns/%s", namespace);

	if (ns_is_self_userns_file(target_namespace_path)) {
		TRACE("Joining same namespace not necessary -> skip.");
		goto out;
	}

	len = readlink(target_namespace_path, target_namespace_id, 40);

	if (len < 0 || len > 39) {
		ERROR("Failed to read namespace identifier");
		goto error;
	}

	target_namespace_id[len] = 0;

	len = readlink(current_namespace_path, current_namespace_id, 40);

	if (len < 0 || len > 39) {
		WARN("Failed to read current identifier");
		len = 0;
	}

	current_namespace_id[len] = 0;

	DEBUG("Joining namespace with identifier %s, current namespace identifier is %s",
	      target_namespace_id, current_namespace_id);

	if (-1 == (ns_fd = open(target_namespace_path, O_RDONLY))) {
		TRACE_ERRNO("Could not open ns file %s!", target_namespace_path);
		goto error;
	}

	if (setns(ns_fd, 0) == -1) {
		TRACE_ERRNO("Could not join %s namespace of pid %d!", target_namespace_path, pid);
		close(ns_fd);
		goto error;
	}

	close(ns_fd);

out:
	mem_free0(target_namespace_path);
	mem_free0(target_namespace_id);
	mem_free0(current_namespace_path);
	mem_free0(current_namespace_id);

	return 0;

error:
	mem_free0(target_namespace_path);
	mem_free0(target_namespace_id);
	mem_free0(current_namespace_path);
	mem_free0(current_namespace_id);

	return -1;
}

int
namespace_exec(pid_t namespace_pid, const int namespaces, int uid, int cap,
	       int (*func)(const void *), const void *data)
{
	if (namespace_pid < 1) {
		ERROR("Invalid namespace PID given: %d", namespace_pid);
		return -1;
	}

	pid_t pid = fork();

	if (pid == -1) {
		ERROR_ERRNO("Could not fork for switching to namespaces of %d", namespace_pid);
		return -1;
	} else if (pid == 0) {
		event_reset(); // do not handle signals in child
		TRACE("Child to join namespaces forked");

		if (namespaces & CLONE_NEWCGROUP) {
			TRACE("Join cgroup namespace");
			if (do_join_namespace("cgroup", namespace_pid) == -1)
				_exit(-1);
		}
		if (namespaces & CLONE_NEWIPC) {
			TRACE("Join ipc namespace");
			if (do_join_namespace("ipc", namespace_pid) == -1)
				_exit(-1);
		}
		if (namespaces & CLONE_NEWNET) {
			TRACE("Join net namespace");
			if (do_join_namespace("net", namespace_pid) == -1)
				_exit(-1);
		}
		if (namespaces & CLONE_NEWUTS) {
			TRACE("Join uts namespace");
			if (do_join_namespace("uts", namespace_pid) == -1)
				_exit(-1);
		}
		if (namespaces & CLONE_NEWPID) {
			TRACE("Join pid namespace");
			if (do_join_namespace("pid", namespace_pid) == -1)
				_exit(-1);
		}
		if (namespaces & CLONE_NEWUSER) {
			TRACE("Join user namespace");
			if (do_join_namespace("user", namespace_pid) == -1)
				_exit(-1);
		}
		//after joining the mount namespace the container init process has pid 1 in procfs
		if (namespaces & CLONE_NEWNS) {
			TRACE("Join mnt namespace");
			if (do_join_namespace("mnt", namespace_pid) == -1)
				_exit(-1);
		}
		if ((namespaces & CLONE_NEWUSER) && uid == 0) {
			TRACE("Becoming root in target namespace");
			if (namespace_setuid0() == -1)
				_exit(-1);
		}
		if (!(namespaces & CLONE_NEWUSER) && cap) {
			TRACE("Preserve system wide cap in target namespace");
			if (namespace_setuid_keep_cap(uid, cap) == -1)
				_exit(-1);
		}

		TRACE("Executing namespaced function");

		int ret = func(data);

		TRACE("Namespaced function returned %d", ret);
		_exit(ret); // don't call atexit registered cleanup of main process
	} else {
		int status;

		DEBUG("Waiting for namespace child %i to exit", pid);
		if (proc_waitpid(pid, &status, 0) != pid) {
			if (!WIFEXITED(status))
				ERROR_ERRNO("Namespaced child %d did not exit cleanly", pid);
			else
				ERROR_ERRNO("Could not waitpid for '%d'", pid);
		} else {
			int estatus = WEXITSTATUS(status);
			int ret = -1;
			ret = WIFEXITED(estatus) ? 0 : -1;

			TRACE("Namespace exec child exited with status %d, returning %d", estatus,
			      ret);
			return ret;
		}
	}

	TRACE("An error occured in namespace_exec, returning -1");
	return -1;
}

#define MAX_NS 16
static int fd[MAX_NS] = { 0 };

struct ns_setns_cbdata {
	int *fd;
	bool join_userns;
};

static int
ns_setns_cb(const char *path, const char *file, void *data)
{
	struct ns_setns_cbdata *cbdata = data;
	ASSERT(cbdata);

	int *i = cbdata->fd;
	bool join_userns = cbdata->join_userns;

	IF_TRUE_RETVAL_TRACE(!join_userns && !strcmp(file, "user"), EXIT_SUCCESS);

	char *ns_file = mem_printf("%s%s", path, file);
	TRACE("Opening namespace file %s", ns_file);

	if (ns_is_self_userns_file(ns_file)) {
		TRACE("Joining same user namespace, not allowed and also not necessary -> skip.");
		mem_free0(ns_file);
		return EXIT_SUCCESS;
	}

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

	mem_free0(ns_file);
	return EXIT_SUCCESS;

error:
	TRACE("An error occurred. Exiting...");
	mem_free0(ns_file);
	exit(EXIT_FAILURE);
}

int
ns_join_all(pid_t pid, bool userns)
{
	char *pid_string = mem_printf("%d", pid);

	TRACE("Setting namespaces to match namespaces of pid %s", pid_string);

	// set namespaces
	char *folder = mem_printf("/proc/%d/ns/", pid);

	int i = 0;
	struct ns_setns_cbdata cbdata = { .fd = &i, .join_userns = userns };

	if (dir_foreach(folder, &ns_setns_cb, &cbdata)) {
		ERROR("Could not traverse PID dir in procfs, wrong PID?");
		goto error;
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) { /* Join that namespace */
			ERROR_ERRNO("Could not join namespace");
			close(fd[j]);
			goto error;
		}
		close(fd[j]);
	}

	TRACE("Successfully joined all namespaces");

	mem_free0(pid_string);
	mem_free0(folder);
	return 0;

error:
	TRACE("An error occurred. Exiting...");
	mem_free0(pid_string);
	mem_free0(folder);
	return -1;
}

int
ns_bind(char *ns, pid_t pid, char *ns_path)
{
	int ret = 0;
	char *ns_proc_path = NULL;
	IF_TRUE_RETVAL(file_touch(ns_path), -1);

	ns_proc_path = mem_printf("/proc/%d/ns/%s", pid, ns);

	if (mount(ns_proc_path, ns_path, NULL, MS_BIND, NULL) < 0) {
		ERROR_ERRNO("Could not bind mount ns file %s on %s", ns_proc_path, ns_path);
		ret = -1;
	}

	mem_free0(ns_proc_path);
	return ret;
}

int
ns_unbind(const char *ns_path)
{
	if (umount(ns_path) < 0) {
		ERROR_ERRNO("Could not unbind mount ns file %s", ns_path);
		return -1;
	}
	if (unlink(ns_path) < 0) {
		ERROR_ERRNO("Could not remove ns file %s", ns_path);
		return -1;
	}
	return 0;
}

int
ns_join_by_path(const char *ns_path)
{
	int fd = open(ns_path, O_RDONLY);
	if (fd == -1) {
		ERROR_ERRNO("Could not open namespace file %s", ns_path);
		return -1;
	}

	if (setns(fd, 0) == -1) {
		ERROR_ERRNO("Could not join namespace by path %s!", ns_path);
		close(fd);
		return -1;
	}

	close(fd);
	INFO("Sucessfully joined ns by path: '%s'.", ns_path);
	return 0;
}

bool
ns_cmp_pidns_by_pid(pid_t pid1, pid_t pid2)
{
	bool ret = false;
	struct stat s1, s2;

	char *ns_file1 = mem_printf("/proc/%d/ns/pid", pid1);
	char *ns_file2 = mem_printf("/proc/%d/ns/pid", pid2);

	IF_TRUE_GOTO_TRACE(stat(ns_file1, &s1) == -1, out);
	IF_TRUE_GOTO_TRACE(stat(ns_file2, &s2) == -1, out);

	ret = (s1.st_dev == s2.st_dev) && (s1.st_ino == s2.st_ino) ? true : false;
out:
	mem_free0(ns_file1);
	mem_free0(ns_file2);
	return ret;
}
