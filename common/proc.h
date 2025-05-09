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

#ifndef PROC_H
#define PROC_H

#include <unistd.h>
#include <stdint.h>

typedef struct proc_status proc_status_t;

proc_status_t *
proc_status_new(pid_t pid);

void
proc_status_free(proc_status_t *status);

const char *
proc_status_get_name(const proc_status_t *status);

pid_t
proc_status_get_ppid(const proc_status_t *status);

uint64_t
proc_status_get_cap_prm(const proc_status_t *status);

uint64_t
proc_status_get_cap_eff(const proc_status_t *status);

/**
 * Kills a process/service with a given name. If ppid is bigger
 * than 0 only process with this parent pid are killed.
 * @param ppid The pid of the parent process, might be negativ.
 * @param name The process name which should be killed.
 * @param sig The signal number, e.g. SIGKILL.
 */
int
proc_killall(pid_t ppid, const char *name, int sig);

/**
 * Returns the pid of the process matching name and ppid.
 * @param ppid The pid of the parent process.
 * @param name The process name to find.
 * @return pid of matched process, 0 if no match, -1 on error.
 */
pid_t
proc_find(pid_t ppid, const char *name);

int
proc_fork_and_execvp(const char *const *argv);

/**
 * Returns the last cap from the running kernel
 * @return last cap of running kernel, -1 on error;
 */
int
proc_cap_last_cap(void);

/**
 * Returns the btime field from /proc/stat in buffer boottime_sec
 * @param boottime_sec pointer to buffer for result
 * @return 0 on success, -1 on error
 */
int
proc_stat_btime(unsigned long long *boottime_sec);

/**
 * Returns the unified v2 cgroup in which the current pid is running
 * by parsing /proc/<pid>/cgroup.
 * @param pid The pid of the process to be checked
 * @return subfolder in mounted cgroup hirachy, "" on v1 systems, NULL on error
 */
char *
proc_get_cgroups_path_new(pid_t pid);

typedef struct proc_meminfo proc_meminfo_t;

/**
 * Parses /proc/meminfo into an internal struct
 * @return pointer to the newly allocated struct, NULL on error
 */
proc_meminfo_t *
proc_meminfo_new();

/**
 * Frees the meminfo internal struct
 * @param meminfo pointer to struct which should be freed
 */
void
proc_meminfo_free(proc_meminfo_t *meminfo);

/**
 * Returns the mem_total in bytes retrieved from /proc/meminfo
 * @param meminfo struct containing the parsed output of /proc/meminfo
 * @return mem_total in bytes on success, -1 on error
 */
ssize_t
proc_get_mem_total(const proc_meminfo_t *meminfo);

/**
 * Returns the mem_free in bytes retrieved from /proc/meminfo
 * @param meminfo struct containing the parsed output of /proc/meminfo
 * @return mem_total in bytes on success, -1 on error
 */
ssize_t
proc_get_mem_free(const proc_meminfo_t *meminfo);

/**
 * Returns the mem_available in bytes retrieved from /proc/meminfo
 * @param meminfo struct containing the parsed output of /proc/meminfo
 * @return mem_total in bytes on success, -1 on error
 */
ssize_t
proc_get_mem_available(const proc_meminfo_t *meminfo);

int
proc_waitpid(pid_t pid, int *status, int options);

/**
 * Returns the name of the file which was used when the file descriptor
 * fd was opened.
 * @param pid The pid of the process which opened the fd
 * @param fd The file descriptor
 * @return path of the file when fd was opened, NULL on error
 */
char *
proc_get_filename_of_fd_new(pid_t pid, int fd);

/**
 * Returns the current working dir of a process
 * @param pid The pid of the process
 * @return path of the cwd of the process with pid pid, NULL on error
 */
char *
proc_get_cwd_new(pid_t pid);

#endif /* PROC_H */
