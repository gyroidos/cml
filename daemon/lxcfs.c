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

#include "lxcfs.h"
#include "hardware.h"
#include "mount.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/file.h"

#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#define LXCFS_RT_PATH "/var/lib/lxcfs"
#define LXCFS_PID_FILE "/run/lxcfs.cmld.pid"

static const char *lxcfs_bin_path = NULL;
static const char *lxcfs_rt_path = NULL;
static pid_t lxcfs_daemon_pid = 0;

#define PROC_FSES "/proc/filesystems"
static const char *
lxcfs_get_bin_path_if_supported(void)
{
	char *fses = file_read_new(PROC_FSES, 2048);
	bool ret = strstr(fses, "fuse") ? true : false;

	mem_free0(fses);

	IF_FALSE_RETVAL_TRACE(ret, NULL);

	const char *binary[] = { "/bin/lxcfs",	    "/sbin/lxcfs",	    "/usr/bin/lxcfs",
				 "/usr/sbin/lxcfs", "/usr/local/bin/lxcfs", "/usr/local/bin/lxcfs" };

	for (size_t i = 0; i < sizeof(binary) / sizeof(const char *); ++i) {
		if (file_exists(binary[i]))
			return binary[i];
	}
	return NULL;
}

static void
lxcfs_daemon_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	pid_t *lxcfs_pid = data;
	pid_t pid;
	int status = 0;

	TRACE("lxcfs SIGCHLD handler called for PID %d", *lxcfs_pid);
	if ((pid = waitpid(*lxcfs_pid, &status, WNOHANG)) > 0) {
		TRACE("Reaped lxcfs process: %d", pid);
		/* remove the sigchld callback for the lxcfs daemon from the event loop */
		event_remove_signal(sig);
		event_signal_free(sig);
	} else {
		TRACE("Failed to reap lxcfs process");
	}
}

static void
lxcfs_daemon_stop(void)
{
	if (lxcfs_daemon_pid > 0) {
		DEBUG("Stopping lxcfs process with pid=%d!", lxcfs_daemon_pid);
		kill(lxcfs_daemon_pid, SIGTERM);
	}
}

static int
lxcfs_daemon_start(const char *rt_path)
{
	const char *const lxcfs_argv[] = { lxcfs_bin_path, "-f",    "-l", "-p",
					   LXCFS_PID_FILE, rt_path, NULL };
	INFO("lxcfs is supported, starting lxcfs daemon '%s' ...", lxcfs_argv[0]);

	IF_TRUE_RETVAL((lxcfs_daemon_pid = fork()) == -1, -1);

	if (lxcfs_daemon_pid == 0) {
		if (file_exists(LXCFS_PID_FILE)) {
			char *pid_buf = file_read_new(LXCFS_PID_FILE, 128);
			int lxcfs_daemon_prev_pid;
			if (sscanf(pid_buf, "%d", &lxcfs_daemon_prev_pid) == 1) {
				INFO("Killing previous instance of lxcfs!");
				kill(lxcfs_daemon_prev_pid, SIGTERM);
			}
			mem_free0(pid_buf);
			for (int i = 0; file_exists(LXCFS_PID_FILE); ++i) {
				sleep(1);
				if (i > 4) {
					kill(lxcfs_daemon_prev_pid, SIGKILL);
					break;
				}
			}
		}
		execvp(lxcfs_bin_path, (char *const *)lxcfs_argv);
		WARN_ERRNO("Could not exec '%s'!", lxcfs_argv[0]);
		_exit(-1);
	} else {
		INFO("lxcfs daemon start done");
		event_signal_t *sigchld =
			event_signal_new(SIGCHLD, lxcfs_daemon_sigchld_cb, &lxcfs_daemon_pid);
		event_add_signal(sigchld);
	}

	return 0;
}

bool
lxcfs_is_supported(void)
{
	return (lxcfs_bin_path) ? true : false;
}

static int
lxcfs_proc_dir_foreach_cb(const char *path, const char *file, void *data)
{
	char *target_path = data;
	ASSERT(target_path);

	if (0 == strcmp(file, "mounts")) {
		TRACE("Skipping 'mounts'");
		return 0;
	}

	char *dst = mem_printf("%s/%s", target_path, file);
	char *src = mem_printf("%s/%s", path, file);

	int ret;
	if ((ret = mount(src, dst, NULL, MS_BIND, NULL)) < 0)
		ERROR_ERRNO("failed to overlay %s with %s from lxcfs!", dst, src);
	else
		TRACE("Applied overlay on %s with %s from lxcfs!", dst, src);

	mem_free0(dst);
	mem_free0(src);
	return ret;
}

int
lxcfs_mount_proc_overlay(char *target)
{
	int ret = 0;
	if (!lxcfs_is_supported())
		return ret;

	char *lxcfs_proc = mem_printf("%s/proc", lxcfs_rt_path);
	if (dir_foreach(lxcfs_proc, &lxcfs_proc_dir_foreach_cb, target) < 0) {
		ERROR("Could not mount proc overlay %s -> %s", lxcfs_proc, target);
		ret = -1;
	}
	mem_free0(lxcfs_proc);
	return ret;
}

int
lxcfs_init(void)
{
	lxcfs_rt_path = LXCFS_RT_PATH;
	lxcfs_bin_path = lxcfs_get_bin_path_if_supported();

	if (lxcfs_bin_path) {
		int ret = mount_cgroups(hardware_get_active_cgroups_subsystems());
		if (ret) {
			WARN("Cannont mount CGroups, thus no need to start lxcfs!");
			return -1;
		}
		return lxcfs_daemon_start(lxcfs_rt_path);
	}
	return -1;
}

void
lxcfs_cleanup(void)
{
	lxcfs_daemon_stop();
}
