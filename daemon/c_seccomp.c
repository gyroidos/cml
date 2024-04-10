/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2023 Fraunhofer AISEC
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
 * @file c_seccomp.c
 *
 * This module handles system call hooking and emulation through the seccomp notify kernel functionality.
 * It applies a seccomp filter matching relevant system calls before the container init process is executed.
 * Access to global resources on behalf of a container through this module is controlled by compartment
 * flags defined in compartment.h. If access to a particular resource is allowed, this module emulates the
 * syscalls a container issues to access the resource.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_seccomp"

#include "compartment.h"
#include "audit.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/event.h"
#include "common/audit.h"
#include "common/kernel.h"
#include "common/proc.h"
#include "common/ns.h"

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timex.h>
#include <sys/utsname.h>

#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <linux/module.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

/**************************/
// clang-format off

#define X32_SYSCALL_BIT 0x40000000

#if defined __x86_64__
	#define C_SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined __aarch64__
	#define C_SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#elif defined __riscv
	#define C_SECCOMP_AUDIT_ARCH AUDIT_ARCH_RISCV64
#endif

/**************************/

#ifndef __NR_pidfd_open
	#if defined __alpha__
		#define __NR_pidfd_open 544
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_pidfd_open (434 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_pidfd_open (434 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_pidfd_open (434 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_pidfd_open (434 + 1024)
	#else
		#define __NR_pidfd_open 434
	#endif
#endif

#ifndef __NR_pidfd_getfd
	#if defined __alpha__
		#define __NR_pidfd_getfd 548
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_pidfd_getfd (438 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_pidfd_getfd (438 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_pidfd_getfd (438 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_pidfd_getfd (438 + 1024)
	#else
		#define __NR_pidfd_getfd 438
	#endif
#endif
// clang-format on

#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE 4
#endif

static int
pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

static int
pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

static int
seccomp(unsigned int op, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(__NR_seccomp, op, flags, args);
}

static int
seccomp_ioctl(int fd, unsigned long request, void *notify_req)
{
	errno = 0;
	return syscall(__NR_ioctl, fd, request, notify_req);
}

static int
finit_module(int fd, const char *param_values, int flags)
{
	return syscall(__NR_finit_module, fd, param_values, flags);
}

static int
capset(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capset, hdrp, datap);
}

static int
capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capget, hdrp, datap);
}
/**************************/

typedef struct c_seccomp {
	compartment_t *compartment;
	struct seccomp_notif_sizes *notif_sizes;
	int notify_fd;
	event_io_t *event;
	unsigned int enabled_features;
	container_t *container;
	list_t *module_list; /* names of modules loaded by this compartment */
} c_seccomp_t;

static int
c_seccomp_install_filter()
{
	/*
	 * This filter allows all system calls other than the explicitly listed
	 * ones, namely
	 * - SYS_mknod
	 * - SYS_mknodat
	 * - SYS_finit_module
	 * - SYS_clock_settime
	 * - SYS_clock_adjtime
	 * - SYS_adjtimex
	 * and thus follows a deny-list approach.
	 */
	struct sock_filter filter[] = {
		/**
		 * Architecture check: load arch from seccomp_data, check if equal
		 * to the expected syscall ABI and kill process if not.
		 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, C_SECCOMP_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

		/*
		 * Syscall filter: load the syscall number and check against each syscall
		 * for that a notification should be sent. If no match is found, the syscall
		 * is allowed.
		 *
		 * NB: The x86_64 ABI and the x32 ABI share AUDIT_ARCH_X86_64 and syscalls
		 * are distinguished using the X32_SYSCALL_BIT. To avoid bypassing the
		 * filter using X32 syscall numbers we block all X32 syscalls.
		 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
#if (C_SECCOMP_AUDIT_ARCH == AUDIT_ARCH_X86_64)
		/* Deny all X32 syscalls */
		BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, (X32_SYSCALL_BIT - 1), 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
#endif
		/*
		 * for mknod(): load args[1] (mode_t mode) from seccomp_data,
		 * check if mode is blk or char dev -> SECCOMP_RET_NOTIFY
		 * otherwise skip emulation. -> SECCOMP_RET_ALLOW
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mknod, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFCHR, 10, 0),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFBLK, 9, 0),

		/*
		 * for mknodat(): load args[2] (mode_t mode) from seccomp_data,
		 * check if mode is blk or char dev -> SECCOMP_RET_NOTIFY
		 * otherwise skip emulation. -> SECCOMP_RET_ALLOW
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mknodat, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[2]))),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFCHR, 6, 0),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFBLK, 5, 0),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_finit_module, 4, 0),

		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_settime, 3, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_adjtime, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_adjtimex, 1, 0),

		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};

	struct sock_fprog prog = { .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
				   .filter = filter };

	int ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (-1 == ret) {
		ERROR_ERRNO("SECCOMP_SET_MODE_FILTER: return value was %d", ret);
		return -1;
	}

	return ret;
}

static bool
c_seccomp_is_pidfd_supported()
{
	return kernel_version_check("5.10.0");
}

static bool
c_seccomp_capable(pid_t pid, uint64_t cap)
{
	struct __user_cap_header_struct cap_header = { .version = _LINUX_CAPABILITY_VERSION_3,
						       .pid = pid };
	struct __user_cap_data_struct cap_data[2];
	mem_memset0(&cap_data, sizeof(cap_data));

	if (capget(&cap_header, cap_data)) {
		ERROR_ERRNO("Could not get capabilty sets!");
		return false;
	}

	return cap_data[CAP_TO_INDEX(cap)].effective & CAP_TO_MASK(cap);
}

static int
c_seccomp_start_pre_exec_child_early(void *seccompp)
{
	ASSERT(seccompp);
	c_seccomp_t *seccomp = seccompp;

	int notify_fd = -1;

	if (-1 == (notify_fd = c_seccomp_install_filter())) {
		ERROR("Failed to install seccomp filter");
		return -1;
	}

	DEBUG("Installed seccomp filter, sending notify fd %d to parent", notify_fd);

	if (fd_write(compartment_get_sync_sock_child(seccomp->compartment), (char *)&notify_fd,
		     sizeof(notify_fd)) < 0) {
		WARN_ERRNO("Could not send notify fd number over sync socket");
		return -1;
	}

	return 0;
}

static void *
c_seccomp_fetch_vm_new(c_seccomp_t *seccomp, int pid, void *rbuf, uint64_t size)
{
	IF_NULL_RETVAL(rbuf, NULL);
	IF_TRUE_RETVAL(pid < 0, NULL);

	void *lbuf = mem_alloc0(size);
	struct iovec local_iov[1];
	struct iovec remote_iov[1];

	local_iov[0].iov_base = lbuf;
	local_iov[0].iov_len = size;

	remote_iov[0].iov_base = rbuf;
	remote_iov[0].iov_len = size;

	ssize_t bytes_read = syscall(SYS_process_vm_readv, pid, local_iov, 1, remote_iov, 1, 0);
	if (bytes_read < 0) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-vm-access-failed",
				compartment_get_name(seccomp->compartment), 2, "pid", pid);

		ERROR_ERRNO("Failed to access memory of remote process, bytes read: %ld",
			    bytes_read);
		mem_free(lbuf);
		return NULL;
	}

	return lbuf;
}

/**
 * Parse module dependencies file "/lib/modules/<release>/modules.dep"
 * to retrieve module dependencies for an allowed module
 */
static list_t *
c_seccomp_get_module_dependencies_new(const char *module_name)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	list_t *ret_list = NULL;

	struct utsname u_name;
	uname(&u_name);

	char *modules_dep_path = mem_printf("/lib/modules/%s/modules.dep", u_name.release);

	fp = fopen(modules_dep_path, "r");
	mem_free0(modules_dep_path);

	IF_NULL_RETVAL(fp, NULL);

	const char *mod_suffix = ".ko";
	char *mod_name = mem_alloc0(strlen(module_name) + strlen(mod_suffix) + 1);
	char *_mod_name = mem_alloc0(strlen(module_name) + strlen(mod_suffix) + 1);

	size_t i;
	for (i = 0; i < strlen(module_name); i++) {
		mod_name[i] = (module_name[i] == '_') ? '-' : module_name[i];
		_mod_name[i] = (module_name[i] == '-') ? '_' : module_name[i];
	}
	for (size_t j = 0; j < strlen(mod_suffix); j++) {
		mod_name[i + j] = mod_suffix[j];
		_mod_name[i + j] = mod_suffix[j];
	}

	TRACE("Searching for (_)mod_name '%s' and '%s'", mod_name, _mod_name);

	bool mod_found_in_line = false;
	ssize_t n;
	/*
	 * Sample lines in modules.dep may look like:
	 *
	 * kernel/arch/x86/crypto/twofish-x86_64.ko.xz: kernel/crypto/twofish_common.ko.xz
	 * [...]
	 * kernel/crypto/twofish_common.ko.xz:
	 *
	 * so we have to match only the first token. If we only use strstr() on
	 * 'line' we would also match the first line if module name was twofish_common
	 */
	while ((n = getline(&line, &len, fp)) != -1) {
		char *_line = mem_strdup(line);
		char *mod_tok = strtok(_line, ":");
		if (strstr(mod_tok, mod_name) || strstr(mod_tok, _mod_name)) {
			mod_found_in_line = true;
			TRACE("found line '%s'", line);
			mem_free(_line);
			break;
		}
		mem_free(_line);
	}

	mem_free0(mod_name);
	mem_free0(_mod_name);

	fclose(fp);

	IF_FALSE_GOTO_ERROR(mod_found_in_line, out);

	/*
	 * A line in modules.dep file looks like:
	 * kernel/net/smc/smc_diag.ko: kernel/net/smc/smc.ko kernel/drivers/infiniband/core/ib_core.ko
	 *
	 * If container config has a module set like this: 'allow_module: "smc-diag"'
	 * this is matched against the constructed '_mode_name = "smc_diag.ko"'
	 *
	 * Thus, now we match the first string by delimiter ": "
	 *	kernel/net/smc/smc_diag.ko: -> first token
	 * afterwards we set the delimiter for tokenizing to " "
	 * 	kernel/net/smc/smc.ko -> second token
	 * 	kernel/drivers/infiniband/core/ib_core.ko -> third token
	 * and append those tokens to the module list
	 */
	char *mod_dep_tok = strtok(line, ": ");
	while (mod_dep_tok) {
		INFO("modules.dep: adding module '%s' to internal matching list!", mod_dep_tok);
		ret_list = list_append(ret_list, mem_strdup(mod_dep_tok));
		mod_dep_tok = strtok(NULL, " ");
	}

out:
	mem_free0(line);
	return ret_list;
}

struct mknodat_fork_data {
	int dirfd;
	const char *pathname;
	const char *cwd;
	mode_t mode;
	dev_t dev;
	uid_t uid;
};

static int
c_seccomp_do_mknodat_fork(const void *data)
{
	const struct mknodat_fork_data *params = data;
	ASSERT(params);

	/*
	 * We change to the mapped root user in the container.
	 * Otherwise, if we just use system root with uid 0, we cannot write
	 * mounts mounted by the container itself, e.g. '/tmp'. This would
	 * result in an "errno (75: Value too large for defined data type)".
	 * To still allow mknod we need to preserve CAP_MKNOD.
	 */
	IF_TRUE_RETVAL(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0), -1);

	if (setgid(params->uid) < 0) {
		ERROR_ERRNO("Could not set gid to '%d' in container", params->uid);
		return -1;
	}

	if (setuid(params->uid) < 0) {
		ERROR_ERRNO("Could not change to mapped root '(%d)' in container", params->uid);
		return -1;
	}

	struct __user_cap_header_struct cap_header = { .version = _LINUX_CAPABILITY_VERSION_3,
						       .pid = 0 };
	struct __user_cap_data_struct cap_data[2];
	mem_memset0(&cap_data, sizeof(cap_data));

	cap_data[CAP_TO_INDEX(CAP_MKNOD)].permitted |= CAP_TO_MASK(CAP_MKNOD);
	cap_data[CAP_TO_INDEX(CAP_MKNOD)].effective |= CAP_TO_MASK(CAP_MKNOD);

	if (capset(&cap_header, cap_data)) {
		ERROR_ERRNO("Could not set CAP_MKNOD effective!");
		return -1;
	}

	if (params->cwd && chdir(params->cwd)) {
		ERROR_ERRNO("Failed to switch to working directory (%s) of target process",
			    params->cwd);
		return -1;
	}

	DEBUG("Executing mknodat %s in mountns of container", params->pathname);
	if (-1 == mknodat(params->dirfd, params->pathname, params->mode, params->dev)) {
		ERROR_ERRNO("Failed to execute mknodat");
		return -1;
	}

	return 0;
}

static void
c_seccomp_handle_notify(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	TRACE("Callback c_service_cb_receive_message has been invoked");
	ASSERT(data);

	c_seccomp_t *seccomp = data;
	if (events & EVENT_IO_EXCEPT) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
				"seccomp-exception-on-notify-fd",
				compartment_get_name(seccomp->compartment), 0);
		ERROR("Got exception on notify fd, unregistering handler");

		event_remove_io(seccomp->event);
		event_io_free(seccomp->event);
		close(seccomp->notify_fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	struct seccomp_notif *req = mem_alloc0(seccomp->notif_sizes->seccomp_notif);
	struct seccomp_notif_resp *resp = mem_alloc0(seccomp->notif_sizes->seccomp_notif);

	TRACE("Attempting to retrieve seccomp notification on fd %d", fd);

	if (seccomp_ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req)) {
		ERROR("SECCOMP_IOCTL_NOTIF_RECV interrupted by %s",
		      EINTR == errno ? "SIGCHLD" : "unexpected event");

		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-rcv-next",
				compartment_get_name(seccomp->compartment), 2, "errno", errno);
		mem_free0(req);
		mem_free0(resp);
		return;
	}

	// default answer
	resp->id = req->id;
	resp->error = -EPERM;

	TRACE("[%llu] Got syscall no. %d by PID %u", req->id, req->data.nr, req->pid);

	if (SYS_clock_adjtime == req->data.nr) {
		int ret_adjtime = -1;

		if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
			DEBUG("Blocking call to SYS_clock_adjtime by PID %d", req->pid);
			goto out;
		}

		DEBUG("Got clock_adjtime, clk_id: %lld, struct timex *: %p", req->data.args[0],
		      (void *)req->data.args[1]);

		struct timex *timex = NULL;

		// Check cap of target pid in its namespace
		if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
			ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
			goto out;
		}

		if (CLOCK_REALTIME != req->data.args[0]) {
			DEBUG("Attempt of container %s to execute clock_settime on clock %llx blocked",
			      uuid_string(compartment_get_uuid(seccomp->compartment)),
			      req->data.args[0]);
			goto out;
		}

		if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(seccomp, req->pid,
								     (void *)req->data.args[1],
								     sizeof(struct timex)))) {
			ERROR_ERRNO("Failed to fetch struct timex");
			goto out;
		}

		DEBUG("Executing clock_adjtime on behalf of container");
		if (-1 == (ret_adjtime = clock_adjtime(CLOCK_REALTIME, timex))) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-emulation-failed",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					SYS_clock_adjtime);
			ERROR_ERRNO("Failed to execute clock_adjtime");
			mem_free(timex);
			goto out;
		}

		DEBUG("clock_adjtime returned %d", ret_adjtime);

		// prepare answer
		resp->id = req->id;
		resp->error = 0;
		resp->val = ret_adjtime;

		mem_free(timex);
	} else if (SYS_adjtimex == req->data.nr) {
		int ret_adjtimex = -1;

		if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
			DEBUG("Blocking call to SYS_adjtimex by PID %d", req->pid);
			goto out;
		}

		DEBUG("Got adjtimex, struct timex *: %p", (void *)req->data.args[0]);

		struct timex *timex = NULL;

		// Check cap of target pid in its namespace
		if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
			ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
			goto out;
		}

		if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(seccomp, req->pid,
								     (void *)req->data.args[0],
								     sizeof(struct timex)))) {
			ERROR_ERRNO("Failed to fetch struct timex");
			goto out;
		}

		DEBUG("Executing adjtimex on behalf of container");
		if (-1 == (ret_adjtimex = adjtimex(timex))) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-emulation-failed",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					SYS_adjtimex);
			ERROR_ERRNO("Failed to execute adjtimex");
			mem_free(timex);
			goto out;
		}

		DEBUG("adjtimex returned %d", ret_adjtimex);

		// prepare answer
		resp->id = req->id;
		resp->error = 0;
		resp->val = ret_adjtimex;

		mem_free(timex);
	} else if (SYS_clock_settime == req->data.nr) {
		int ret_settime = -1;

		if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
			DEBUG("Blocking call to SYS_clock_settime by PID %d", req->pid);
			goto out;
		}

		DEBUG("Got clock_settime, clockid: %lld, struct timespec *: %p", req->data.args[0],
		      (void *)req->data.args[1]);

		struct timespec *timespec = NULL;

		// Check cap of target pid in its namespace
		if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
			ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
			goto out;
		}

		if (CLOCK_REALTIME != req->data.args[0]) {
			DEBUG("Attempt of container %s to execute clock_settime on clock %llx blocked",
			      uuid_string(compartment_get_uuid(seccomp->compartment)),
			      req->data.args[0]);
			goto out;
		}

		if (!(timespec = (struct timespec *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, (void *)req->data.args[1],
			      sizeof(struct timespec)))) {
			ERROR_ERRNO("Failed to fetch struct timespec");
			goto out;
		}

		DEBUG("Executing clock_settime on behalf of container");
		if (-1 == (ret_settime = clock_settime(CLOCK_REALTIME, timespec))) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-emulation-failed",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					SYS_clock_settime);
			ERROR_ERRNO("Failed to execute clock_settime");
			mem_free(timespec);
			goto out;
		}

		DEBUG("clock_settime returned %d", ret_settime);

		// prepare answer
		resp->id = req->id;
		resp->error = 0;
		resp->val = ret_settime;

		mem_free(timespec);
	} else if (SYS_finit_module == req->data.nr) {
		int ret_finit_module = -1;

		if (!(COMPARTMENT_FLAG_MODULE_LOAD & compartment_get_flags(seccomp->compartment))) {
			DEBUG("Blocking call to SYS_finit_module by PID %d", req->pid);
			goto out;
		}

		DEBUG("Got finit_module from pid %d, fd: %lld, const char params_values *: %p, flags: %lld",
		      req->pid, req->data.args[0], (void *)req->data.args[1], req->data.args[2]);

		int fd_in_target = req->data.args[0];
		int flags = req->data.args[2];

		// Check cap of target pid in its namespace
		if (!c_seccomp_capable(req->pid, CAP_SYS_MODULE)) {
			ERROR("Missing CAP_SYS_MODULE for process %d!", req->pid);
			goto out;
		}

		char *mod_filename = proc_get_filename_of_fd_new(req->pid, fd_in_target);

		// Check against list of allowed modules
		bool module_allowed = false;
		for (list_t *l = seccomp->module_list; l; l = l->next) {
			char *mod_name = l->data;
			if (strstr(mod_filename, mod_name)) {
				module_allowed = true;
				break;
			}
		}

		if (!module_allowed) {
			ERROR("Check whitelist for '%s' failed!", mod_filename);
			mem_free0(mod_filename);
			goto out;
		}

		// Validate path for module location
		bool valid_prefix = false;
		const char *valid_path[2] = { "/lib/modules", "/usr/lib/modules" };
		for (int i = 0; i < 2 && valid_prefix == false; ++i) {
			if (0 == strncmp(valid_path[i], mod_filename, strlen(valid_path[i]))) {
				valid_prefix = true;
				break;
			}
		}

		if (!valid_prefix) {
			ERROR("Path validation for '%s' failed! %d!", mod_filename, req->pid);
			mem_free0(mod_filename);
			goto out;
		}

#if 0
		// kernel cmdline and modparams are restricted to 1024 chars
		int param_max_len = 1024;
		char *param_values = mem_alloc0(param_max_len);
		if (!(param_values = (char *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, (void *)req->data.args[1], param_max_len))) {
			ERROR_ERRNO("Failed to fetch module parameters string");
			mem_free0(param_values);
			mem_free0(mod_filename);
			goto out;
		}
#endif
		/*
		 * unitl we do not have a proper module parameters sanity checking,
		 * we white out parameters, since there may be dangerous ones.
		 */
		char *param_values = mem_strdup("");

		DEBUG("Executing finit_module on behalf of container using module %s"
		      " with parameters '%s' from CML",
		      mod_filename, param_values);
		int cml_mod_fd = open(mod_filename, O_RDONLY);
		if (cml_mod_fd < 0) {
			ERROR_ERRNO("Failed to open module %s in CML", mod_filename);
			mem_free0(param_values);
			mem_free0(mod_filename);
			goto out;
		}
		/*
		 * for security reasons we strip out flags MODULE_INIT_IGNORE_MODVERSIONS
		 * MODULE_INIT_IGNORE_VERMAGIC which skips sanity checks and only allow
		 * @flag_mask (currently this is MODULE_INIT_COMPRESSED_FILE only)
		 * however to be save on additional introduced module flags, we do not
		 * explicitly mask out the known bad flags like this:
		 *
		 *	flags &= ~(MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
		 */
		int flag_mask = MODULE_INIT_COMPRESSED_FILE;
		flags &= flag_mask;

		if (-1 == (ret_finit_module = finit_module(cml_mod_fd, param_values, flags))) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-emulation-failed",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					SYS_finit_module);
			ERROR_ERRNO("Failed to execute finit_module");
			mem_free0(param_values);
			mem_free0(mod_filename);
			close(cml_mod_fd);
			goto out;
		}
		close(cml_mod_fd);

		DEBUG("finit_module returned %d", ret_finit_module);

		// prepare answer
		resp->id = req->id;
		resp->error = 0;
		resp->val = ret_finit_module;

		mem_free0(param_values);
		mem_free0(mod_filename);
	} else if (SYS_mknodat == req->data.nr || SYS_mknodat == req->data.nr) {
		int ret_mknodat = -1;
		const char *syscall_name = req->data.nr == SYS_mknodat ? "mknodat" : "mknod";
		int dirfd = -1;
		int arg_offset = 0;

		/*
		 * We emulate mknod() by mknodat() for code dedup:
		 *
		 * mknod() and mknodat() have the same arguments, except that
		 * mknodat has dirfd as first argument:
		 *   int mknod(const char *pathname, mode_t mode, dev_t dev);
		 *   int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
		 *
		 * We therefore use an offset +1 for the data.args array to
		 * retrieve syscall parameters from seccomp req in case of
		 * mknodat() and set dirfd to AT_FDCWD in case of mknod()
		 */
		if (req->data.nr == SYS_mknodat) {
			DEBUG("Got %s() from pid %d, fd: %lld, const char *pathname: %p, mode: %lld, dev: %lld",
			      syscall_name, req->pid, req->data.args[0], (void *)req->data.args[1],
			      req->data.args[2], req->data.args[3]);
			dirfd = req->data.args[arg_offset];
			arg_offset++;
		} else { // SYS_mknod
			DEBUG("Got %s() from pid %d, const char *pathname: %p, mode: %lld, dev: %lld",
			      syscall_name, req->pid, (void *)req->data.args[0], req->data.args[1],
			      req->data.args[2]);
			dirfd = AT_FDCWD;
		}

		mode_t mode = req->data.args[1 + arg_offset];
		dev_t dev = req->data.args[2 + arg_offset];

		/* Check cap of target pid in its namespace */
		if (!c_seccomp_capable(req->pid, CAP_MKNOD)) {
			ERROR("Missing CAP_MKNOD for process %d!", req->pid);
			goto out;
		}

		/* We only handle char and block devices, due to our seccomp filter */
		char dev_type = S_ISCHR(mode) ? 'c' : 'b';

		/* Check if dev is allowed (c_cgroups submodule) */
		if (!container_is_device_allowed(seccomp->container, dev_type, major(dev),
						 minor(dev))) {
			ERROR("Missing cgroup permission for device (%c %d:%d) in process %d!",
			      dev_type, major(dev), minor(dev), req->pid);
			goto out;
		}

		int pathname_max_len = PATH_MAX;
		char *pathname = mem_alloc0(pathname_max_len);
		if (!(pathname = (char *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, (void *)req->data.args[0 + arg_offset],
			      pathname_max_len))) {
			ERROR_ERRNO("Failed to fetch pathname string");
			mem_free0(pathname);
			goto out;
		}

		int cml_dirfd = AT_FDCWD;
		if (dirfd != AT_FDCWD) {
			int pidfd;
			if (-1 == (pidfd = pidfd_open(req->pid, 0))) {
				ERROR_ERRNO("Could not open pidfd for emulating %s()",
					    syscall_name);
				mem_free0(pathname);
				goto out;
			}

			cml_dirfd = pidfd_getfd(pidfd, dirfd, 0);
			if (cml_dirfd < 0) {
				ERROR_ERRNO(
					"Could not open dirfd in target process for emulating %s()",
					syscall_name);
				mem_free0(pathname);
				goto out;
			}
		}

		char *cwd = proc_get_cwd_new(req->pid);

		DEBUG("Emulating %s by executing mknodat %s on behalf of container", syscall_name,
		      pathname);

		struct mknodat_fork_data mknodat_params = { .dirfd = cml_dirfd,
							    .pathname = pathname,
							    .cwd = cwd,
							    .mode = mode,
							    .dev = dev,
							    .uid = container_get_uid(
								    seccomp->container) };
		if (-1 ==
		    (ret_mknodat = namespace_exec(req->pid, CLONE_NEWNS, false,
						  c_seccomp_do_mknodat_fork, &mknodat_params))) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-emulation-failed",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					SYS_mknodat);
			ERROR_ERRNO("Failed to execute mknodat");
			if (cwd)
				mem_free0(cwd);
			mem_free0(pathname);
			if ((AT_FDCWD != cml_dirfd) && (cml_dirfd >= 0))
				close(cml_dirfd);
			goto out;
		}

		DEBUG("mknodat returned %d", ret_mknodat);

		// prepare answer
		resp->id = req->id;
		resp->error = 0;
		resp->val = ret_mknodat;

		if (cwd)
			mem_free0(cwd);
		mem_free0(pathname);
		if ((AT_FDCWD != cml_dirfd) && (cml_dirfd >= 0))
			close(cml_dirfd);
	} else {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-unexpected-syscall",
				compartment_get_name(seccomp->compartment), 2, "syscall",
				req->data.nr);

		ERROR("Got syscall not handled by us: %d", req->data.nr);

		resp->id = req->id;
		resp->error = 0;
		resp->val = 0;
		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	}
out:

	if (-1 == seccomp_ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp)) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-send-respone",
				compartment_get_name(seccomp->compartment), 2, "errno", errno);
		ERROR_ERRNO("Failed to send seccomp notify response");
	} else {
		DEBUG("Successfully handled seccomp notification");
	}

	mem_free(req);
	mem_free(resp);
}

static int
c_seccomp_start_pre_exec(void *seccompp)
{
	c_seccomp_t *seccomp = seccompp;
	ASSERT(seccomp);

	if (!c_seccomp_is_pidfd_supported()) {
		INFO("Kernel does not support pidfd, skipping seccomp_notify-based syscall emulation");
		return 0;
	}

	DEBUG("Attempting to receive seccomp notify fd on socket %d",
	      compartment_get_sync_sock_parent(seccomp->compartment));

	int pidfd = -1, notify_fd_compartment = -1, notify_fd = -1;

	// get notify fd number from child
	if (sizeof(notify_fd_compartment) !=
	    fd_read(compartment_get_sync_sock_parent(seccomp->compartment),
		    (char *)&notify_fd_compartment, sizeof(notify_fd_compartment))) {
		ERROR_ERRNO("Failed to receive notify fd number");
		goto out;
	}

	// copy notfiy fd to this process via pidfd
	DEBUG("Notify fd fd number in child process with PID %d: %d",
	      compartment_get_pid(seccomp->compartment), notify_fd_compartment);

	pidfd = pidfd_open(compartment_get_pid(seccomp->compartment), 0);
	if (-1 == pidfd) {
		ERROR_ERRNO("Failed to open pidfd on child process %d",
			    compartment_get_pid(seccomp->compartment));
		goto out;
	}

	notify_fd = pidfd_getfd(pidfd, notify_fd_compartment, 0);
	if (-1 == notify_fd) {
		ERROR_ERRNO("Failed to receive fd from child process %d",
			    compartment_get_pid(seccomp->compartment));
		goto out;
	}

	if (-1 == close(pidfd)) {
		ERROR_ERRNO("Failed to close pidfd");
		goto out;
	}

	seccomp->notify_fd = notify_fd;

	DEBUG("Register event handler on notify fd %d", seccomp->notify_fd);

	seccomp->event =
		event_io_new(seccomp->notify_fd, EVENT_IO_READ, &c_seccomp_handle_notify, seccomp);
	event_add_io(seccomp->event);

	return 0;

out:
	return -1;
}

void *
c_seccomp_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	// adapted from user-trap.c
	struct seccomp_notif_sizes *sizes = mem_new0(struct seccomp_notif_sizes, 1);
	if (seccomp(SECCOMP_GET_NOTIF_SIZES, 0, sizes) < 0) {
		ERROR("Failed to get seccomp notify sizes");
		return NULL;
	}

	c_seccomp_t *seccomp = mem_new0(c_seccomp_t, 1);

	seccomp->notif_sizes = sizes;
	seccomp->notify_fd = -1;
	seccomp->compartment = compartment;
	seccomp->container = compartment_get_extension_data(compartment);

	seccomp->module_list = NULL;
	const list_t *l = container_get_module_allow_list(seccomp->container);
	for (; l; l = l->next) {
		const char *module_name = l->data;
		seccomp->module_list = list_join(
			seccomp->module_list, c_seccomp_get_module_dependencies_new(module_name));
	}

	return seccomp;
}

static void
c_seccomp_free(void *seccompp)
{
	c_seccomp_t *seccomp = seccompp;
	ASSERT(seccomp);
	if (seccomp->notif_sizes)
		mem_free0(seccomp->notif_sizes);

	for (list_t *l = seccomp->module_list; l; l = l->next) {
		mem_free0(l->data);
	}
	list_delete(seccomp->module_list);

	mem_free0(seccomp);
}

static void
c_seccomp_cleanup(void *seccompp, UNUSED bool is_rebooting)
{
	c_seccomp_t *seccomp = (c_seccomp_t *)seccompp;
	ASSERT(seccomp);

	if (seccomp->event) {
		event_remove_io(seccomp->event);
		event_io_free(seccomp->event);
		seccomp->event = NULL;
	}

	if (-1 != seccomp->notify_fd)
		close(seccomp->notify_fd);
}

static compartment_module_t c_seccomp_module = {
	.name = MOD_NAME,
	.compartment_new = c_seccomp_new,
	.compartment_free = c_seccomp_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_seccomp_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = c_seccomp_start_pre_exec_child_early,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_seccomp_cleanup,
	.join_ns = NULL,
};

static void INIT
c_seccomp_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_seccomp_module);
}
