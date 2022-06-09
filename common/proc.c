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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "macro.h"
#include "proc.h"
#include "mem.h"
#include "file.h"
#include "dir.h"

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>

struct proc_killall {
	pid_t ppid;
	const char *name;
	int sig;
};

struct proc_find {
	pid_t ppid;
	const char *name;
	pid_t match;
};

struct proc_status {
	char name[16];
	char state;
	pid_t pid;
	pid_t ppid;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	uid_t fuid;
	gid_t rgid;
	gid_t egid;
	gid_t sgid;
	gid_t fgid;
};

proc_status_t *
proc_status_new(pid_t pid)
{
	proc_status_t *status;
	char *file, *buf, *tmp;
	int n;

	file = mem_printf("/proc/%d/status", pid);
	buf = file_read_new(file, 4096);
	mem_free0(file);

	IF_NULL_RETVAL(buf, NULL);

	status = mem_new0(proc_status_t, 1);

	n = sscanf(buf, "Name:\t%15c", status->name);
	IF_FALSE_GOTO(n == 1, error);
	tmp = strchr(status->name, '\n');
	if (tmp)
		tmp[0] = '\0';
	TRACE("Parsed name for %d: %s", pid, status->name);

	tmp = strstr(buf, "\nState:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nState:\t%c\n", &status->state);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed state for %d: %c", pid, status->state);

	tmp = strstr(buf, "\nPid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nPid:\t%d\n", &status->pid);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed pid for %d: %d", pid, status->pid);

	tmp = strstr(buf, "\nPPid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nPPid:\t%d\n", &status->ppid);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed ppid for %d: %d", pid, status->ppid);

	tmp = strstr(buf, "\nUid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nUid:\t%u\t%u\t%u\t%u\n", &status->ruid, &status->euid, &status->suid,
		   &status->fuid);
	IF_FALSE_GOTO(n == 4, error);
	TRACE("Parsed uid for %d: %u %u %u %u", pid, status->ruid, status->euid, status->suid,
	      status->fuid);

	tmp = strstr(buf, "\nGid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nGid:\t%u\t%u\t%u\t%u\n", &status->rgid, &status->egid, &status->sgid,
		   &status->fgid);
	IF_FALSE_GOTO(n == 4, error);
	TRACE("Parsed gid for %d: %u %u %u %u", pid, status->rgid, status->egid, status->sgid,
	      status->fgid);

	mem_free0(buf);
	return status;
error:
	mem_free0(status);
	mem_free0(buf);
	return NULL;
}

void
proc_status_free(proc_status_t *status)
{
	mem_free0(status);
}

const char *
proc_status_get_name(const proc_status_t *status)
{
	ASSERT(status);
	return status->name;
}

pid_t
proc_status_get_ppid(const proc_status_t *status)
{
	ASSERT(status);
	return status->ppid;
}

static int
proc_killall_cb(UNUSED const char *path, const char *file, void *data)
{
	struct proc_killall *pk = data;

	char *tmp = NULL;
	pid_t pid = strtol(file, &tmp, 10);
	if (!tmp || tmp[0] != '\0') // filename is not a number
		return 0;

	proc_status_t *status = proc_status_new(pid);
	IF_NULL_RETVAL(status, 0);

	pid_t ppid = proc_status_get_ppid(status);
	const char *name = proc_status_get_name(status);

	if ((pk->ppid < 0 || pk->ppid == ppid) && !strcmp(name, pk->name)) {
		DEBUG("Killing process %s with pid %d", pk->name, pid);
		kill(pid, pk->sig);
	}

	proc_status_free(status);
	return 0;
}

int
proc_killall(pid_t ppid, const char *name, int sig)
{
	struct proc_killall data = { ppid, name, sig };

	DEBUG("Trying to kill %s with ppid %d", name, ppid);
	if (dir_foreach("/proc", &proc_killall_cb, &data) < 0) {
		WARN("Could not traverse /proc");
		return -1;
	}

	return 0;
}

static int
proc_find_cb(UNUSED const char *path, const char *file, void *data)
{
	struct proc_find *pf = data;

	char *tmp = NULL;
	pid_t pid = strtol(file, &tmp, 10);
	if (!tmp || tmp[0] != '\0') // filename is not a number
		return 0;

	proc_status_t *status = proc_status_new(pid);
	IF_NULL_RETVAL_TRACE(status, 0);

	pid_t ppid = proc_status_get_ppid(status);
	const char *name = proc_status_get_name(status);

	if ((pf->ppid == ppid) && !strcmp(name, pf->name)) {
		TRACE("Found pid %d with ppid %d and name %s", pid, ppid, pf->name);
		pf->match = pid;
		//return -1; // TODO maybe adapt dir_foreach to allow aborting the directory traversing without indicating an error
	}

	proc_status_free(status);
	return 0;
}

pid_t
proc_find(pid_t ppid, const char *name)
{
	struct proc_find data = { ppid, name, 0 };

	if (dir_foreach("/proc", &proc_find_cb, &data) < 0) {
		WARN("Could not traverse /proc");
		return -1;
	}

	return data.match;
}

int
proc_fork_and_execvp(const char *const *argv)
{
	int status;
	pid_t pid = fork();

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", argv[0]);
		return -1;
	case 0:
		execvp(argv[0], (char *const *)argv);
		FATAL_ERRNO("Could not execvp %s", argv[0]);
		return -1;
	default:
		while (waitpid(pid, &status, WNOHANG) != pid) {
			continue;
		}
		if (!WIFEXITED(status)) {
			ERROR("Child '%s' terminated abnormally", argv[0]);
		} else {
			TRACE("%s terminated normally", argv[0]);
			return WEXITSTATUS(status) ? -1 : 0;
		}
	}
	return -1;
}

int
proc_cap_last_cap(void)
{
	int cap;
	const char *file_cap_last_cap = "/proc/sys/kernel/cap_last_cap";

	char *str_cap_last_cap = file_read_new(file_cap_last_cap, 24);
	if (sscanf(str_cap_last_cap, "%d", &cap) <= 0) {
		ERROR_ERRNO("Can't read cap from '%s'", file_cap_last_cap);
		cap = -1;
	}

	mem_free0(str_cap_last_cap);
	return cap;
}

int
proc_stat_btime(unsigned long long *boottime_sec)
{
	FILE *proc;
	char line_buf[2048];

	IF_NULL_RETVAL((proc = fopen("/proc/stat", "r")), -1);

	while (fgets(line_buf, 2048, proc)) {
		if (sscanf(line_buf, "btime %llu", boottime_sec) != 1)
			continue;
		fclose(proc);
		return 0;
	}
	if (errno) {
		ERROR_ERRNO("fscanf");
		fclose(proc);
		return -errno;
	}
	ERROR_ERRNO("failed to parse /proc/stat");
	fclose(proc);
	return -1;
}
