#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "macro.h"
#include "mem.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

/**
 * This function forks a new child in the given target namespaces and executes the given function
 */
int
namespace_exec(pid_t ns_pid, const char *const *namespaces, const size_t ns_len,
	       int (*func)(const void **), const void **data)
{
	TRACE("Executing function in namespace with pid %d", ns_pid);

	if (ns_pid < 1) {
		ERROR("Invalid namespace PID given: %d", ns_pid);
		return -1;
	}

	int status;

	TRACE("Forking child to join namespaces");

	pid_t pid = fork();

	if (pid == -1) {
		ERROR_ERRNO("Could not fork for switching to namespaces of %d", ns_pid);
		return -1;
	} else if (pid == 0) {
		TRACE("Child to join namespaces forked");

		for (size_t i = 0; i < ns_len; i++) {
			char *ns_path = mem_printf("/proc/%d/ns/%s", ns_pid, namespaces[i]);
			int ns_fd = open(ns_path, O_RDONLY);

			TRACE("Joining namespace %s", ns_path);

			if (ns_fd == -1) {
				TRACE_ERRNO("Could not open ns file %s!", ns_path);
				return -1;
			}

			if (setns(ns_fd, 0) == -1) {
				TRACE_ERRNO("Could not join %s namespace of pid %d!", ns_path,
					    ns_pid);
				return -1;
			}

			//TODO handle userns

			mem_free(ns_path);
		}

		int ret = func(data);

		TRACE("Namespaced function returned %d", ret);
		exit(ret);
	} else {
		ERROR("Waiting for namespace child to exit");
		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%d'", pid);
		} else if (!WIFEXITED(status)) {
			ERROR("Namespaced child %d terminated abnormally", pid);
		} else {
			int estatus = WEXITSTATUS(status);
			int ret = -1;
			ret = WEXITSTATUS(estatus) ? -1 : 0;

			TRACE("Namespace exec child exited with status %d, returning %d", estatus,
			      ret);
			return ret;
		}
	}

	TRACE("An error occured in namespace_exec, returning -1");
	return -1;
}
