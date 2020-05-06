#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <sched.h>

#include <grp.h>

#include "macro.h"
#include "mem.h"

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

		goto error;
	}

	mem_free(target_namespace_path);
	mem_free(target_namespace_id);
	mem_free(current_namespace_path);
	mem_free(current_namespace_id);

	return 0;

error:
	mem_free(target_namespace_path);
	mem_free(target_namespace_id);
	mem_free(current_namespace_path);
	mem_free(current_namespace_id);

	return -1;
}

int
namespace_exec(pid_t namespace_pid, const int namespaces, bool become_root,
	       int (*func)(const void **), const void **data)
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
		TRACE("Child to join namespaces forked");

		if (namespaces & CLONE_NEWCGROUP) {
			TRACE("Join cgroup namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("cgroup", namespace_pid), -1);
		}
		if (namespaces & CLONE_NEWIPC) {
			TRACE("Join ipc namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("ipc", namespace_pid), -1);
		}
		if (namespaces & CLONE_NEWNET) {
			TRACE("Join net namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("net", namespace_pid), -1);
		}
		if (namespaces & CLONE_NEWUTS) {
			TRACE("Join uts namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("uts", namespace_pid), -1);
		}
		if (namespaces & CLONE_NEWPID) {
			TRACE("Join pid namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("pid", namespace_pid), -1);
		}
		if (namespaces & CLONE_NEWUSER) {
			TRACE("Join user namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("user", namespace_pid), -1);
		}
		//after joining the mount namespace the container init process has pid 1 in procfs
		if (namespaces & CLONE_NEWNS) {
			TRACE("Join mnt namespace");
			IF_TRUE_RETVAL_ERROR(do_join_namespace("mnt", namespace_pid), -1);
		}
		if (become_root) {
			TRACE("Becoming root in target namespace");
			IF_TRUE_RETVAL(namespace_setuid0(), -1);
		}

		TRACE("Executing namespaced function");

		int ret = func(data);

		TRACE("Namespaced function returned %d", ret);
		exit(ret);
	} else {
		int status;

		DEBUG("Waiting for namespace child %i to exit", pid);
		if (waitpid(pid, &status, 0) != pid) {
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
