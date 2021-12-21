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

#define MOD_NAME "c_cap"

#include "common/macro.h"
#include "common/mem.h"
#include "common/ns.h"
#include "common/event.h"
#include "common/proc.h"
#include "common/file.h"
#include "container.h"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#define C_CAP_DROP(cap)                                                                            \
	do {                                                                                       \
		DEBUG("Dropping capability %s:%d for %s", #cap, cap,                               \
		      container_get_description(container));                                       \
		if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {                                    \
			ERROR_ERRNO("Could not drop capability %s:%d for %s", #cap, cap,           \
				    container_get_description(container));                         \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

typedef struct c_cap {
	container_t *container;
} c_cap_t;

static void *
c_cap_new(container_t *container)
{
	ASSERT(container);

	c_cap_t *cap = mem_new0(c_cap_t, 1);
	cap->container = container;

	return cap;
}

static void
c_cap_free(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);
	mem_free0(cap);
}

static int
c_cap_set_current_process(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);

	// C_CAP_DROP macro needs variable container
	container_t *container = cap->container;

	///* 1 */ C_CAP_DROP(CAP_DAC_OVERRIDE); /* does NOT work properly */
	///* 2 */ C_CAP_DROP(CAP_DAC_READ_SEARCH);
	///* 3 */ C_CAP_DROP(CAP_FOWNER); /* does NOT work */
	///* 4 */ C_CAP_DROP(CAP_FSETID);
	///* 6 */ C_CAP_DROP(CAP_SETGID); /* does NOT work */
	///* 7 */ C_CAP_DROP(CAP_SETUID); /* does NOT work */

	/* 9 */ C_CAP_DROP(CAP_LINUX_IMMUTABLE);
	/* 14 */ C_CAP_DROP(CAP_IPC_LOCK);
	/* 15 */ C_CAP_DROP(CAP_IPC_OWNER);
	/* 16 */ C_CAP_DROP(CAP_SYS_MODULE);
	///* 17 */ C_CAP_DROP(CAP_SYS_RAWIO); /* does NOT work */
#ifndef DEBUG_BUILD
	/* 19 */ C_CAP_DROP(CAP_SYS_PTRACE);
#endif
	/* 20 */ C_CAP_DROP(CAP_SYS_PACCT);
	///* 22 */ C_CAP_DROP(CAP_SYS_BOOT);

	///* 23 */ C_CAP_DROP(CAP_SYS_NICE); /* Is needed for some usecases*/
	///* 24 */ C_CAP_DROP(CAP_SYS_RESOURCE); /* does NOT work */
	/* 28 */ C_CAP_DROP(CAP_LEASE);

	///* 29 */ C_CAP_DROP(CAP_AUDIT_WRITE); /* needed for console/X11 login */
	/* 30 */ C_CAP_DROP(CAP_AUDIT_CONTROL);

	/* 31 */ C_CAP_DROP(CAP_SETFCAP);

	/* 32 */ C_CAP_DROP(CAP_MAC_OVERRIDE);
	/* 33 */ C_CAP_DROP(CAP_MAC_ADMIN);

	/* 34 */ C_CAP_DROP(CAP_SYSLOG);
	///* 35 */ C_CAP_DROP(CAP_WAKE_ALARM); /* needed by alarm driver */

	if (container_has_userns(container))
		return 0;

	/* 21 */ C_CAP_DROP(CAP_SYS_ADMIN);

	/* Use the following for dropping caps only in unprivileged containers */
	if (!container_is_privileged(container) &&
	    container_get_state(container) != CONTAINER_STATE_SETUP) {
		/* 18 */ C_CAP_DROP(CAP_SYS_CHROOT);
		/* 25 */ C_CAP_DROP(CAP_SYS_TIME);
		/* 26 */ C_CAP_DROP(CAP_SYS_TTY_CONFIG);
	}

	return 0;
}

int
capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(SYS_capset, hdrp, datap);
}

static int
c_cap_do_exec_cap_systime(c_cap_t *cap, char *const *argv)
{
	ASSERT(cap);

	// C_CAP_DROP macro needs variable container
	container_t *container = cap->container;

	int uid = container_get_uid(container);

	int last_cap = proc_cap_last_cap() < 0 ? CAP_LAST_CAP : proc_cap_last_cap();
	TRACE("Last CAP %d", last_cap);
	for (int cap = 0; cap < last_cap; cap++) {
		// ntpd needs to bind a socket to
		if (cap == CAP_SYS_TIME || cap == CAP_NET_BIND_SERVICE || cap == CAP_SETUID)
			continue;
		C_CAP_DROP(cap);
	}

	// keep caps during uid switch
	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
		ERROR_ERRNO("Could not set KEEPCAPS");
		_exit(EXIT_FAILURE);
	}
	// switch to uid and gid of mapped userns root user
	if (setgid(uid) < 0) {
		ERROR_ERRNO("Could not set gid to '%d' in root userns", uid);
		_exit(EXIT_FAILURE);
	}
	if (setuid(uid) < 0) {
		ERROR_ERRNO("Could not become user '%d' in root userns", uid);
		_exit(EXIT_FAILURE);
	}

	struct __user_cap_header_struct hdr = { 0 };
	hdr.version = _LINUX_CAPABILITY_VERSION_3;
	hdr.pid = 0;

	struct __user_cap_data_struct data[2] = { 0 };
	data[CAP_TO_INDEX(CAP_SYS_TIME)].effective |= CAP_TO_MASK(CAP_SYS_TIME);
	data[CAP_TO_INDEX(CAP_SYS_TIME)].permitted |= CAP_TO_MASK(CAP_SYS_TIME);
	data[CAP_TO_INDEX(CAP_SYS_TIME)].inheritable |= CAP_TO_MASK(CAP_SYS_TIME);

	data[CAP_TO_INDEX(CAP_NET_BIND_SERVICE)].effective |= CAP_TO_MASK(CAP_NET_BIND_SERVICE);
	data[CAP_TO_INDEX(CAP_NET_BIND_SERVICE)].permitted |= CAP_TO_MASK(CAP_NET_BIND_SERVICE);
	data[CAP_TO_INDEX(CAP_NET_BIND_SERVICE)].inheritable |= CAP_TO_MASK(CAP_NET_BIND_SERVICE);

	if (capset(&hdr, &data[0]) < 0) {
		ERROR_ERRNO("capset failed!");
		_exit(EXIT_FAILURE);
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_TIME, 0, 0) < 0) {
		ERROR_ERRNO("Could not preserve CAP_SYS_TIME");
		_exit(EXIT_FAILURE);
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0) < 0) {
		ERROR_ERRNO("Could not preserve CAP_NET_BIND_SERVICE");
		_exit(EXIT_FAILURE);
	}

	if (strstr(argv[0], "ntpd")) {
		char *env_ntp[] = { "LD_PRELOAD=/usr/lib/libuid_wrapper.so", "UID_WRAPPER=1",
				    "UID_WRAPPER_ROOT=1", NULL };
		if (!file_exists("/usr/lib/libc.so")) {
			struct utsname uts_name;
			if (uname(&uts_name))
				WARN_ERRNO("Can't get utsname!");
			char *multiarch_dir = mem_printf("/lib/%s-linux-gnu", uts_name.machine);
			int fd = open(multiarch_dir, O_DIRECTORY);
			if (fd > 0 && symlinkat("libc.so.6", fd, "libc.so"))
				WARN_ERRNO("symlink of %s to libc.so failed!", multiarch_dir);
			else if (file_exists("/lib/libc.so.6") &&
				 symlink("/lib/libc.so.6", "/usr/lib/libc.so"))
				WARN_ERRNO("symlink to libc.so failed!");
			mem_free0(multiarch_dir);
			close(fd);
		}
		execve(argv[0], argv, env_ntp);
		ERROR_ERRNO("exec with uid_wrapper of '%s' failed!", argv[0]);
	} else {
		execvp(argv[0], argv);
		ERROR_ERRNO("exec '%s' failed!", argv[0]);
	}
	return -1;
}

static void
c_cap_exec_cap_systime_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	pid_t *pid = data;
	int status = 0;

	DEBUG("exec_cap_systime SIGCHLD handler called for PID %d", *pid);
	if (waitpid(*pid, &status, WNOHANG) > 0) {
		TRACE("Reaped exec_cap_systime process: %d", *pid);
		event_remove_signal(sig);
		event_signal_free(sig);
		mem_free0(pid);
	} else {
		TRACE("Failed to reap exec_cap_systime process");
	}
}

static int
c_cap_exec_cap_systime(void *capp, char *const *argv)
{
	c_cap_t *cap = capp;
	ASSERT(cap);

	IF_FALSE_RETVAL(container_is_privileged(cap->container), -1);

	int i = 1;
	char *cmd = mem_strdup(argv[0]);
	while (argv[i]) {
		cmd = mem_printf("%s %s", cmd, argv[i]);
		++i;
	}
	INFO("Going to exec '%s' with CAP_SYS_TIME!", cmd);

	int pid = fork();
	if (pid == 0) {
		if (strstr(argv[0], "ntpd")) {
			char *uid_wrapper_lib = mem_printf("%s/usr/lib/libuid_wrapper.so",
							   container_get_rootdir(cap->container));
			if (-1 ==
			    file_copy("/usr/lib/libuid_wrapper.so.0", uid_wrapper_lib, -1, 512, 0))
				ERROR("Could not copy LD_PRELOAD lib '%s' for ntpd",
				      uid_wrapper_lib);
			if (chmod(uid_wrapper_lib, 0755))
				WARN_ERRNO("Could not set %s executeable", uid_wrapper_lib);
			mem_free0(uid_wrapper_lib);
		}
		// join container namespace but maintain root user ns
		if (ns_join_all(container_get_pid(cap->container), false) < 0) {
			ERROR("Could not join namesapces");
			_exit(EXIT_FAILURE);
		}

		// double fork for to join pidns
		int pid_2 = fork();
		if (pid_2 == 0) {
			c_cap_do_exec_cap_systime(cap, argv);
			_exit(EXIT_FAILURE);
		} else if (pid < 0) {
			ERROR("double fork faild!");
			_exit(EXIT_FAILURE);
		} else {
			// exit parent to handover child to init of container
			_exit(0);
		}
	} else if (pid < 0) {
		ERROR_ERRNO("Failed to exec %s with CAP_SYS_TIME!", argv[0]);
		return -1;
	}

	// sucessfully double forked child in target pidns
	pid_t *_pid = mem_new(pid_t, 1);
	*_pid = pid;
	// register reaper for intermediate process
	event_signal_t *sigchld =
		event_signal_new(SIGCHLD, c_cap_exec_cap_systime_sigchld_cb, _pid);
	event_add_signal(sigchld);
	return 0;
}

static int
c_cap_start_child(void *capp)
{
	c_cap_t *cap = capp;
	ASSERT(cap);

	if (c_cap_set_current_process(cap))
		return -CONTAINER_ERROR;

	return 0;
}

static container_module_t c_cap_module = {
	.name = MOD_NAME,
	.container_new = c_cap_new,
	.container_free = c_cap_free,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_cap_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_cap_init(void)
{
	// register this module in container.c
	container_register_module(&c_cap_module);

	// register relevant handlers implemented by this module
	container_register_set_cap_current_process_handler(MOD_NAME, c_cap_set_current_process);
	container_register_exec_cap_systime_handler(MOD_NAME, c_cap_exec_cap_systime);
}
