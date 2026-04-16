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
 * @file c_seccomp/sysinfo.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for
 * the sysinfo() syscall. Values are used either directly derived from cgroups
 * files or in case of loads[], we use the proc provided values, which are
 * emulated by lxcfs if available.
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"

#include <common/file.h>
#include <common/macro.h>
#include <common/mem.h>
#include <common/ns.h>

#include "seccomp.h"

#include <limits.h>
#include <linux/sysinfo.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <unistd.h>

#define CGROUPS_FOLDER "/sys/fs/cgroup"
// cgroup subtree where cmld is running in (provided by c_cgroups_v2.c)
extern char *c_cgroups_subtree;

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

/*
 *  According to man sysinfo(2) the sysinfo struct looks like this:
 *
 *      struct sysinfo {
 *           long uptime;             // Seconds since boot
 *           unsigned long loads[3];  // 1, 5, and 15 minute load averages
 *           unsigned long totalram;  // Total usable main memory size
 *           unsigned long freeram;   // Available memory size
 *           unsigned long sharedram; // Amount of shared memory
 *           unsigned long bufferram; // Memory used by buffers
 *           unsigned long totalswap; // Total swap space size
 *           unsigned long freeswap;  // Swap space still available
 *           unsigned short procs;    // Number of current processes
 *           unsigned long totalhigh; // Total high memory size
 *           unsigned long freehigh;  // Available high memory size
 *           unsigned int mem_unit;   // Memory unit size in bytes
 *           char _f[20-2*sizeof(long)-sizeof(int)]; // Padding to 64 bytes
 *      };
 */

#define SI_LOAD_SHIFT 16
#define MEM_UNLIMITED 0

int
sysinfo(struct sysinfo *info)
{
	return syscall(__NR_sysinfo, info);
}

struct cg_mem_stat {
	/*
	 * for sysinfo the only relevant info from memory.stat file is shmem
	 * which mapps to sharedram
	 */
	unsigned long shmem;
};

static int
c_seccomp_cgroup_get_mem_stat(struct cg_mem_stat *mem_stat, const char *cg_path)
{
	int ret = -1;
	int n = 0;
	char *cg_file = NULL;
	char *buf = NULL;
	char *tmp = NULL;

	cg_file = mem_printf("%s/%s", cg_path, "memory.stat");
	IF_NULL_RETVAL(cg_file, -1);

	buf = file_read_new(cg_file, sysconf(_SC_PAGE_SIZE));
	IF_NULL_GOTO(buf, err);

	TRACE("buf: '%s'", buf);

	tmp = strstr(buf, "\nshmem");
	IF_NULL_GOTO(tmp, err);
	n = sscanf(tmp, "\nshmem %lu\n", &mem_stat->shmem);
	IF_FALSE_GOTO(n == 1, err);
	TRACE("Parsed shmem for %d: %lu", getpid(), mem_stat->shmem);

	ret = 0;
err:
	mem_free0(cg_file);
	if (buf)
		mem_free0(buf);
	return ret;
}

static bool
wd_is_root_cg(void)
{
	int ret;

	char *cwd = get_current_dir_name();
	if (!cwd)
		return false;

	ret = !strcmp(cwd, CGROUPS_FOLDER);

	mem_free0(cwd);
	return ret;
}

static int
c_seccomp_cgroup_get_max(const char *file_prefix, unsigned long *mem_max, const char *cg_path)
{
	ASSERT(cg_path);
	ASSERT(file_prefix);
	ASSERT(mem_max);

	int ret = -1;
	int n = 0;
	char *buf = NULL;
	char *cwd = NULL;
	unsigned long mem_max_current = MEM_UNLIMITED;
	char *cg_file = mem_printf("%s.max", file_prefix);

	// save current working directory
	cwd = get_current_dir_name();

	IF_TRUE_GOTO(chdir(cg_path), err);

	*mem_max = ULONG_MAX;
	while (!wd_is_root_cg() && (buf = file_read_new(cg_file, sysconf(_SC_PAGE_SIZE)))) {
		TRACE("buf: '%s'", buf);

		if (!strcmp("max\n", buf)) {
			// no limit set, skip
		} else {
			n = sscanf(buf, "%lu\n", &mem_max_current);
			IF_FALSE_GOTO(n == 1, err);
			*mem_max = MIN(*mem_max, mem_max_current);
		}

		mem_free0(buf);
		// chdir to .. should always succeed, however just to be sure
		IF_TRUE_GOTO(chdir(".."), err);
	}

	if (*mem_max == ULONG_MAX)
		*mem_max = MEM_UNLIMITED;

	TRACE("Parsed memory.max for %d: %lu", getpid(), *mem_max);
	ret = 0;
err:
	mem_free0(cg_file);
	if (cwd) {
		// restore current working directory
		if (chdir(cwd))
			WARN("Could not change back to former cwd %s", cwd);
		mem_free0(cwd);
	}
	return ret;
}

static int
c_seccomp_cgroup_get_mem_max(unsigned long *mem_max, const char *cg_path)
{
	return c_seccomp_cgroup_get_max("memory", mem_max, cg_path);
}

static int
c_seccomp_cgroup_get_swap_max(unsigned long *swap_max, const char *cg_path)
{
	return c_seccomp_cgroup_get_max("memory.swap", swap_max, cg_path);
}

static int
c_seccomp_cgroup_get_current(const char *file_prefix, unsigned long *mem_current,
			     const char *cg_path)
{
	ASSERT(cg_path);
	ASSERT(file_prefix);
	ASSERT(mem_current);

	int ret = -1;
	int n = 0;
	char *buf = NULL;
	char *cg_file = mem_printf("%s/%s.current", cg_path, file_prefix);

	buf = file_read_new(cg_file, sysconf(_SC_PAGE_SIZE));
	IF_NULL_GOTO(buf, err);

	TRACE("buf: '%s'", buf);

	n = sscanf(buf, "%lu\n", mem_current);
	IF_FALSE_GOTO(n == 1, err);
	TRACE("Parsed memory.current for %d: %lu", getpid(), *mem_current);

	ret = 0;
err:
	mem_free0(cg_file);
	if (buf)
		mem_free0(buf);
	return ret;
}

static int
c_seccomp_cgroup_get_mem_current(unsigned long *mem_current, const char *cg_path)
{
	return c_seccomp_cgroup_get_current("memory", mem_current, cg_path);
}

static int
c_seccomp_cgroup_get_swap_current(unsigned long *swap_max, const char *cg_path)
{
	return c_seccomp_cgroup_get_current("memory.swap", swap_max, cg_path);
}

static int
c_seccomp_cgroup_get_pids_current(unsigned short *pid_current, const char *cg_path)
{
	ASSERT(cg_path);
	ASSERT(pid_current);

	int ret = -1;
	int n = 0;
	char *buf = NULL;
	char *cg_file = mem_printf("%s/pids.current", cg_path);

	buf = file_read_new(cg_file, sysconf(_SC_PAGE_SIZE));
	IF_NULL_GOTO(buf, err);

	TRACE("buf: '%s'", buf);

	n = sscanf(buf, "%hu\n", pid_current);
	IF_FALSE_GOTO(n == 1, err);
	TRACE("Parsed pids.current for %d: %hu", getpid(), *pid_current);

	ret = 0;
err:
	mem_free0(cg_file);
	if (buf)
		mem_free0(buf);
	return ret;
}

static void
c_seccomp_print_sysinfo(struct sysinfo *info)
{
	TRACE("uptime;    \t %ld", info->uptime); // Seconds since boot
	TRACE("loads[3];  \t [%ld, %ld, %ld]", info->loads[0], info->loads[1], info->loads[2]);
	// 1, 5, and 15 minute load averages
	TRACE("totalram;  \t %ld", info->totalram);  // Total usable main memory size
	TRACE("freeram;   \t %ld", info->freeram);   // Available memory size
	TRACE("sharedram; \t %ld", info->sharedram); // Amount of shared memory
	TRACE("bufferram; \t %ld", info->bufferram); // Memory used by buffers
	TRACE("totalswap; \t %ld", info->totalswap); // Total swap space size
	TRACE("freeswap;  \t %ld", info->freeswap);  // Swap space still available
	TRACE("procs;     \t %hu", info->procs);     // Number of current processes
	TRACE("totalhigh; \t %ld", info->totalhigh); // Total high memory size
	TRACE("freehigh;  \t %ld", info->freehigh);  // Available high memory size
	TRACE("mem_unit;  \t %d", info->mem_unit);   // Memory unit size in bytes
}

struct sysinfo_fork_data {
	c_seccomp_t *seccomp;
	struct sysinfo *info;
	pid_t target_pid;
	void *target_datap;
};

static int
c_seccomp_do_sysinfo_fork(const void *data)
{
	const struct sysinfo_fork_data *sysinfo_params = data;
	ASSERT(sysinfo_params);

	// initialize struct sysinfo with host values
	TRACE("Executing sysinfo in namespaces of container");
	if (-1 == sysinfo(sysinfo_params->info)) {
		ERROR_ERRNO("Failed to execute sysinfo");
		return -1;
	}

	TRACE("sysinfo struct ns-only!");
	c_seccomp_print_sysinfo(sysinfo_params->info);

	const uuid_t *uuid = compartment_get_uuid(sysinfo_params->seccomp->compartment);
	char *cg_path = mem_printf("%s/%s", c_cgroups_subtree, uuid_string(uuid));

	// cg values are in bytes, thus scale values by mem_unit
	unsigned int mem_unit = sysinfo_params->info->mem_unit;

	// overwrite totalram and freeram if memory limits are set
	unsigned long mem_max = 0;
	if (-1 == c_seccomp_cgroup_get_mem_max(&mem_max, cg_path)) {
		WARN("Failed to get memory.max from cgroup");
	} else if (mem_max != MEM_UNLIMITED) {
		// if cgroup is unlimited mem_max is set to 0 (MEM_UNLIMITED)
		sysinfo_params->info->totalram = mem_max / mem_unit;

		// overwrite freeram
		unsigned long mem_current = 0;
		if (-1 == c_seccomp_cgroup_get_mem_current(&mem_current, cg_path)) {
			WARN("Failed to get memory.current from cgroup");
		} else {
			sysinfo_params->info->freeram = (mem_max - mem_current) / mem_unit;
		}
	}

	// overwrite sharedram
	struct cg_mem_stat mem_stat = { 0 };
	if (-1 == c_seccomp_cgroup_get_mem_stat(&mem_stat, cg_path)) {
		WARN("Failed to get mem_stat from cgroup");
	} else {
		sysinfo_params->info->sharedram = mem_stat.shmem / mem_unit;
	}
	// equivalent for bufferram does not exist in cgroups v2 memory.stat
	sysinfo_params->info->bufferram = 0ULL;

	// overwrite totalswap and freeswap if swap limits are set
	unsigned long swap_max = 0;
	if (-1 == c_seccomp_cgroup_get_swap_max(&swap_max, cg_path)) {
		WARN("Failed to get memory.swap.max from cgroup");
	} else if (swap_max != MEM_UNLIMITED) {
		// if cgroup is unlimited swap_max is set to 0 (MEM_UNLIMITED)
		sysinfo_params->info->totalswap = swap_max / mem_unit;

		// overwrite freeswap
		unsigned long swap_current = 0;
		if (-1 == c_seccomp_cgroup_get_swap_current(&swap_current, cg_path)) {
			WARN("Failed to get memory.swap.current from cgroup");
		} else {
			sysinfo_params->info->freeswap = (swap_max - swap_current) / mem_unit;
		}
	}

	// overwrite procs
	unsigned short pids_current = 0;
	if (-1 == c_seccomp_cgroup_get_pids_current(&pids_current, cg_path)) {
		WARN("Failed to get pids.current from cgroup");
	} else {
		sysinfo_params->info->procs = pids_current;
	}

	if (ns_join_by_pid(compartment_get_pid(sysinfo_params->seccomp->compartment), CLONE_NEWNS))
		WARN("Failed to join mountns for lxcfs provided values");

	// overwrite loads from procfs (if lxcfs is enabled, we get the container values)
	unsigned long load[6] = { 0 };

	char *loadavg = file_read_new("/proc/loadavg", sysconf(_SC_PAGE_SIZE));
	if (6 != sscanf(loadavg, "%lu.%lu %lu.%lu %lu.%lu", &load[0], &load[1], &load[2], &load[3],
			&load[4], &load[5])) {
		WARN("Could not parse '/proc/loadavg' in namespace of container!");
	} else {
		TRACE("parsed /proc/loadavg '%s' %lu-%lu, %lu-%lu, %lu-%lu", loadavg, load[0],
		      load[1], load[2], load[3], load[4], load[5]);

		sysinfo_params->info->loads[0] =
			(load[0] << SI_LOAD_SHIFT) + ((load[1] << SI_LOAD_SHIFT) / 100);
		sysinfo_params->info->loads[1] =
			(load[2] << SI_LOAD_SHIFT) + ((load[3] << SI_LOAD_SHIFT) / 100);
		sysinfo_params->info->loads[2] =
			(load[4] << SI_LOAD_SHIFT) + ((load[5] << SI_LOAD_SHIFT) / 100);
	}
	mem_free0(loadavg);

	TRACE("sysinfo struct emulated!");
	c_seccomp_print_sysinfo(sysinfo_params->info);

	mem_free0(cg_path);

	if (-1 == c_seccomp_send_vm(sysinfo_params->seccomp, sysinfo_params->target_pid,
				    (void *)sysinfo_params->info, sysinfo_params->target_datap,
				    sizeof(struct sysinfo))) {
		ERROR_ERRNO("Failed to send struct sysinfo");
		return -1;
	}

	return 0;
}

int
c_seccomp_emulate_sysinfo(c_seccomp_t *seccomp, struct seccomp_notif *req,
			  struct seccomp_notif_resp *resp)
{
	int ret_sysinfo = 0;
	struct sysinfo *info;

	TRACE("Got sysinfo, struct sysinfo *: %p", CAST_UINT_VOIDPTR req->data.args[0]);
	info = mem_new0(struct sysinfo, 1);

	TRACE("Executing sysinfo on behalf of container");
	/*
	 * Join all namespaces but pidns; thus, the helper process won't show up inside
	 * the container and except cgroupns+mountns; thus, cgroup traversal can be made to
	 * cgroup system root to check max values of parents.
	 * Uptime will then already be correctly handled by time namespace
	 */
	struct sysinfo_fork_data sysinfo_params = { .seccomp = seccomp,
						    .info = info,
						    .target_pid = req->pid,
						    .target_datap =
							    CAST_UINT_VOIDPTR req->data.args[0] };
	if (-1 ==
	    (ret_sysinfo = namespace_exec(
		     req->pid, CLONE_NEWALL & (~CLONE_NEWPID) & (~CLONE_NEWCGROUP) & (~CLONE_NEWNS),
		     0, 0, c_seccomp_do_sysinfo_fork, &sysinfo_params))) {
		ERROR_ERRNO("Failed to execute sysinfo");
		goto out;
	}

	TRACE("sysinfo returned %d", ret_sysinfo);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_sysinfo;

out:
	if (info)
		mem_free(info);

	return ret_sysinfo;
}
