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

#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timex.h>

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
/**************************/

typedef struct c_seccomp {
	compartment_t *compartment;
	struct seccomp_notif_sizes *notif_sizes;
	int notify_fd;
	event_io_t *event;
	unsigned int enabled_features;
} c_seccomp_t;

/**
 * slightly modified sample code from the seccomp manpage
 * https://man7.org/linux/man-pages/man2/seccomp.2.html
 * an the Linux secomp sample code at samples/seccomp
 */
static int
c_seccomp_install_filter()
{
	/*
	 * This filter allows all system calls other than the explicitly listed
	 * ones, namely
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
	bool ret = true;

	proc_status_t *pstat = proc_status_new(pid);
	if (!pstat) {
		ERROR("Failed to get status of target process %d", pid);
		return false;
	}
	// Check effective set to emulate the kernel capable() check
	if (!(proc_status_get_cap_eff(pstat) & (1ULL << cap))) {
		ERROR("process %d is missing capability!", pid);
		ret = false;
	}

	proc_status_free(pstat);
	return ret;
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

	uint64_t bytes_read = syscall(SYS_process_vm_readv, pid, local_iov, 1, remote_iov, 1, 0);
	if (size != bytes_read) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-vm-access-failed",
				compartment_get_name(seccomp->compartment), 2, "pid", pid);

		ERROR_ERRNO("Failed to access memory of remote process, bytes read: %ld",
			    bytes_read);
		mem_free(lbuf);
		return NULL;
	}

	return lbuf;
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
		goto out;
	}

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

		// kernel cmdline and modparams are restricted to 1024 chars
		int param_max_len = 1024;
		char *param_values = mem_alloc0(param_max_len);
		if (!(param_values = (char *)c_seccomp_fetch_vm_new(
			      seccomp, req->pid, (void *)req->data.args[1], param_max_len))) {
			ERROR_ERRNO("Failed to fetch module paramters string");
			mem_free0(param_values);
			goto out;
		}

		char *mod_filename = proc_get_filename_of_fd_new(req->pid, fd_in_target);

		// TODO check against list in
		// char *mod_name = basename(mod_filename);

		DEBUG("Executing finit_module on behalf of container using module %s from CML",
		      mod_filename);
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

	if (-1 == seccomp_ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp)) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-send-respone",
				compartment_get_name(seccomp->compartment), 2, "errno", errno);
		ERROR_ERRNO("Failed to send seccomp notify response");
	} else {
		DEBUG("Successfully handled seccomp notification");
	}

out:
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
		ERROR("Faild to get seccomp notify sizes");
		return NULL;
	}

	c_seccomp_t *seccomp = mem_new0(c_seccomp_t, 1);

	seccomp->notif_sizes = sizes;
	seccomp->notify_fd = -1;
	seccomp->compartment = compartment;

	return seccomp;
}

static void
c_seccomp_free(void *seccompp)
{
	c_seccomp_t *seccomp = seccompp;
	ASSERT(seccomp);
	if (seccomp->notif_sizes)
		mem_free0(seccomp->notif_sizes);
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
