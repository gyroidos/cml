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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "macro.h"
#include "proc.h"
#include "mem.h"
#include "file.h"
#include "dir.h"

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <unistd.h>
#include <stdint.h>
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
	uint64_t cap_prm;
	uint64_t cap_eff;
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

	tmp = strstr(tmp, "\nPid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nPid:\t%d\n", &status->pid);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed pid for %d: %d", pid, status->pid);

	tmp = strstr(tmp, "\nPPid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nPPid:\t%d\n", &status->ppid);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed ppid for %d: %d", pid, status->ppid);

	tmp = strstr(tmp, "\nUid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nUid:\t%u\t%u\t%u\t%u\n", &status->ruid, &status->euid, &status->suid,
		   &status->fuid);
	IF_FALSE_GOTO(n == 4, error);
	TRACE("Parsed uid for %d: %u %u %u %u", pid, status->ruid, status->euid, status->suid,
	      status->fuid);

	tmp = strstr(tmp, "\nGid:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nGid:\t%u\t%u\t%u\t%u\n", &status->rgid, &status->egid, &status->sgid,
		   &status->fgid);
	IF_FALSE_GOTO(n == 4, error);
	TRACE("Parsed gid for %d: %u %u %u %u", pid, status->rgid, status->egid, status->sgid,
	      status->fgid);

	tmp = strstr(tmp, "\nCapPrm:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nCapPrm:\t%" SCNx64 "\n", &status->cap_prm);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed CapPrm for %d: %016" PRIx64, pid, status->cap_prm);

	tmp = strstr(tmp, "\nCapEff:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nCapEff:\t%016" SCNx64 "\n", &status->cap_eff);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed CapEff for %d: %016" PRIx64, pid, status->cap_eff);

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

uint64_t
proc_status_get_cap_prm(const proc_status_t *status)
{
	ASSERT(status);
	return status->cap_prm;
}

uint64_t
proc_status_get_cap_eff(const proc_status_t *status)
{
	ASSERT(status);
	return status->cap_eff;
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
		while (waitpid(pid, &status, 0) != pid && errno == EINTR) {
			TRACE_ERRNO("waitpid interrupted for child '%s' "
				    "wait again",
				    argv[0]);
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

char *
proc_get_cgroups_path_new(pid_t pid)
{
	char line_buf[2048];
	FILE *proc = NULL;
	char *cgroup_path = NULL;
	bool read_one_line = false;

	char *path = mem_printf("/proc/%d/cgroup", pid);

	if (NULL == (proc = fopen(path, "r"))) {
		mem_free0(path);
		return NULL;
	}

	while (fgets(line_buf, 2048, proc)) {
		if (read_one_line) {
			// more than one line means no unified v2 only setup
			cgroup_path = mem_strdup("");
			break;
		}
		read_one_line = true;

		if (strlen(line_buf) > 3 && !strncmp(line_buf, "0::", 3)) {
			cgroup_path = mem_strdup(line_buf + 3);
			// fgets does not remove '\n'
			cgroup_path[strcspn(cgroup_path, "\n")] = '\0';
			break;
		}
	}

	fclose(proc);
	mem_free0(path);
	return cgroup_path;
}

struct proc_meminfo {
	ssize_t mem_total;
	ssize_t mem_free;
	ssize_t mem_available;
};

proc_meminfo_t *
proc_meminfo_new()
{
	proc_meminfo_t *meminfo;
	char *buf, *tmp;
	int n;

	buf = file_read_new("/proc/meminfo", 4096);
	IF_NULL_RETVAL(buf, NULL);

	meminfo = mem_new0(proc_meminfo_t, 1);

	n = sscanf(buf, "MemTotal:\t%zd kB", &meminfo->mem_total);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed MemTotal: %zd kB", meminfo->mem_total);

	tmp = strstr(buf, "\nMemFree:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nMemFree:\t%zd kB", &meminfo->mem_free);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed MemFree: %zd kB", meminfo->mem_free);

	tmp = strstr(buf, "\nMemAvailable:");
	IF_NULL_GOTO(tmp, error);
	n = sscanf(tmp, "\nMemAvailable:\t%zd kB", &meminfo->mem_available);
	IF_FALSE_GOTO(n == 1, error);
	TRACE("Parsed MemAvailable: %zd kB", meminfo->mem_available);

	mem_free0(buf);
	return meminfo;
error:
	mem_free0(meminfo);
	mem_free0(buf);
	return NULL;
}

void
proc_meminfo_free(proc_meminfo_t *meminfo)
{
	IF_NULL_RETURN(meminfo);
	mem_free0(meminfo);
}

ssize_t
proc_get_mem_total(const proc_meminfo_t *meminfo)
{
	IF_NULL_RETVAL(meminfo, -1);
	return MUL_WITH_OVERFLOW_CHECK(meminfo->mem_total, 1024);
}

ssize_t
proc_get_mem_free(const proc_meminfo_t *meminfo)
{
	IF_NULL_RETVAL(meminfo, -1);
	return MUL_WITH_OVERFLOW_CHECK(meminfo->mem_free, 1024);
}

ssize_t
proc_get_mem_available(const proc_meminfo_t *meminfo)
{
	IF_NULL_RETVAL(meminfo, -1);
	return MUL_WITH_OVERFLOW_CHECK(meminfo->mem_available, 1024);
}

int
proc_waitpid(pid_t pid, int *status, int options)
{
	pid_t ret;
	while ((ret = waitpid(pid, status, options)) == -1 && errno == EINTR) {
		TRACE_ERRNO("waitpid interrupted for child '%d', wait again", pid);
	}
	return ret;
}

char *
proc_get_filename_of_fd_new(pid_t pid, int fd)
{
	char *ret;

	char *file_path = mem_alloc0(PATH_MAX);
	char *path = mem_printf("/proc/%d/fd/%d", pid, fd);

	ssize_t len = readlink(path, file_path, PATH_MAX);
	if (len < 0 || len > PATH_MAX - 1)
		ERROR_ERRNO("readlink on %s returned %zd", path, len);

	ret = (len < 0 || len > PATH_MAX - 1) ? NULL : mem_strdup(file_path);

	mem_free0(file_path);
	mem_free0(path);
	return ret;
}

char *
proc_get_cwd_new(pid_t pid)
{
	char *ret;

	char *file_path = mem_alloc0(PATH_MAX);
	char *path = mem_printf("/proc/%d/cwd", pid);

	ssize_t len = readlink(path, file_path, PATH_MAX);
	if (len < 0 || len > PATH_MAX - 1)
		ERROR_ERRNO("readlink on %s returned %zd", path, len);

	ret = (len < 0 || len > PATH_MAX - 1) ? NULL : mem_strdup(file_path);

	mem_free0(file_path);
	mem_free0(path);
	return ret;
}
