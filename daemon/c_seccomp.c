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
#include "hardware.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/audit.h"
#include "common/kernel.h"

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/timex.h>

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <linux/netlink.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

// TODO multiarch support?
#define X32_SYSCALL_BIT 0x40000000

/**************************/
// clang-format off
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
int
c_seccomp_install_filter(unsigned int t_arch, UNUSED int f_errno)
{
	unsigned int upper_nr_limit = 0xffffffff;

	/**
	 * Assume that AUDIT_ARCH_X86_64 means the normal x86-64 ABI
	 * (in the x32 ABI, all system calls have bit 30 set in the
	 * 'nr' field, meaning the numbers are >= X32_SYSCALL_BIT)
	 *
	 */
	if (t_arch == AUDIT_ARCH_X86_64)
		upper_nr_limit = X32_SYSCALL_BIT - 1;

	struct sock_filter filter[] = {
		/**
		 * [0] Load architecture from 'seccomp_data' buffer into
		 * accumulator
		 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),

		/**
		 * [1] Jump forward 5 instructions if architecture does not
		 * match 't_arch'
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, t_arch, 0, 6),

		/*
		 * [2] Load system call number from 'seccomp_data' buffer into
		 * accumulator
		 */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

		/**
		 * [3] Check ABI - only needed for x86-64 in blacklist use
		 * cases.Use BPF_JGT instead of checking against the bit
		 * mask to avoid having to reload the syscall number.
		 */
		BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, upper_nr_limit, 4, 0),

		/**
		 * [4] Compare agains each syscal and jump to end of block
		 * if system call number matches 'syscall_nr', jump forward 1
		 * instruction on last check if system call number does not
		 * match 'syscall_nr'
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_settime, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_adjtime, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_adjtimex, 0, 1),

		/**
		 * [5] Matching architecture and system call: don't execute
		 * the system call, and return 'f_errno' in 'errno'
		 */
		BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_USER_NOTIF),

		/**
		 * [6] Destination of system call number mismatch: allow other
		 * system calls
		 */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		/**
		 * [7] Destination of architecture mismatch: kill task
		 */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
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

static int
c_seccomp_start_pre_exec_child_early(void *seccompp)
{
	ASSERT(seccompp);
	c_seccomp_t *seccomp = seccompp;

	int notify_fd = -1;

	if (-1 == (notify_fd = c_seccomp_install_filter(AUDIT_ARCH_X86_64, EPERM))) {
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
	} else if (events & EVENT_IO_READ) {
		struct seccomp_notif *req = mem_alloc0(seccomp->notif_sizes->seccomp_notif);
		struct seccomp_notif_resp *resp = mem_alloc0(seccomp->notif_sizes->seccomp_notif);

		TRACE("Attempting to retrieve seccomp notification on fd %d", fd);

		if (seccomp_ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req)) {
			if (EINTR == errno) {
				ERROR("SECCOMP_IOCTL_NOTIF_RECV interrupted by SIGCHLD");
				audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
						"seccomp-rcv-next",
						compartment_get_name(seccomp->compartment), 2,
						"errno", errno);
				return;
			} else {
				ERROR("SECCOMP_IOCTL_NOTIF_RECV interrupted by unexpected event");
				audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
						"seccomp-rcv-next",
						compartment_get_name(seccomp->compartment), 2,
						"errno", errno);
				return;
			}
		}

		TRACE("[%llu] Got syscall no. %d by PID %u", req->id, req->data.nr, req->pid);

		if (SYS_clock_adjtime == req->data.nr) {
			int ret_adjtime = -1;

			if (!(COMPARTMENT_FLAG_SYSTEM_TIME &
			      compartment_get_flags(seccomp->compartment))) {
				DEBUG("Blocking call to SYS_clock_adjtime by PID %d", req->pid);
				goto out;
			}

			DEBUG("Got clock_adjtime, clk_id: %lld, struct timex *: %p",
			      req->data.args[0], (void *)req->data.args[1]);

			struct timex *timex = NULL;

			if (CLOCK_REALTIME != req->data.args[0]) {
				DEBUG("Attempt of container %s to execute clock_settime on clock %llx blocked",
				      uuid_string(compartment_get_uuid(seccomp->compartment)),
				      req->data.args[0]);
				goto out;
			}

			if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(
				      seccomp, req->pid, (void *)req->data.args[1],
				      sizeof(struct timex)))) {
				ERROR_ERRNO("Failed to fetch struct timex");
				goto out;
			}

			DEBUG("Executing clock_adjtime on behalf of container");
			if (-1 == (ret_adjtime = clock_adjtime(CLOCK_REALTIME, timex))) {
				audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
						"seccomp-emulation-failed",
						compartment_get_name(seccomp->compartment), 2,
						"syscall", SYS_clock_adjtime);
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

			if (!(COMPARTMENT_FLAG_SYSTEM_TIME &
			      compartment_get_flags(seccomp->compartment))) {
				DEBUG("Blocking call to SYS_adjtimex by PID %d", req->pid);
				goto out;
			}

			DEBUG("Got adjtimex, struct timex *: %p", (void *)req->data.args[0]);

			struct timex *timex = NULL;

			if (!(timex = (struct timex *)c_seccomp_fetch_vm_new(
				      seccomp, req->pid, (void *)req->data.args[0],
				      sizeof(struct timex)))) {
				ERROR_ERRNO("Failed to fetch struct timex");
				goto out;
			}

			DEBUG("Executing adjtimex on behalf of container");
			if (-1 == (ret_adjtimex = adjtimex(timex))) {
				audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
						"seccomp-emulation-failed",
						compartment_get_name(seccomp->compartment), 2,
						"syscall", SYS_adjtimex);
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

			if (!(COMPARTMENT_FLAG_SYSTEM_TIME &
			      compartment_get_flags(seccomp->compartment))) {
				DEBUG("Blocking call to SYS_clock_settime by PID %d", req->pid);
				goto out;
			}

			DEBUG("Got clock_settime, clockid: %lld, struct timespec *: %p",
			      req->data.args[0], (void *)req->data.args[1]);

			struct timespec *timespec = NULL;

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
						compartment_get_name(seccomp->compartment), 2,
						"syscall", SYS_clock_settime);
				ERROR_ERRNO("Failed to execute clock_settime");
				goto out;
			}

			DEBUG("clock_settime returned %d", ret_settime);

			// prepare answer
			resp->id = req->id;
			resp->error = 0;
			resp->val = ret_settime;

			mem_free(timespec);
		} else {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-unexpected-syscall",
					compartment_get_name(seccomp->compartment), 2, "syscall",
					req->data.nr);

			ERROR("Got syscall not handled by us: %d", req->data.nr);

			resp->id = req->id;
			resp->error = 0;
			resp->val = 0;
			resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
		}

		if (-1 == seccomp_ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp)) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION,
					"seccomp-send-respone",
					compartment_get_name(seccomp->compartment), 2, "errno",
					errno);
			ERROR_ERRNO("Failed to send seccomp notify response");
		} else {
			DEBUG("Successfully handled seccomp notification");
		}

	out:
		mem_free(req);
		mem_free(resp);
	}
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
	//TODO: port to multiarch support
	IF_FALSE_RETURN(0 == strcmp("x86", hardware_get_name()));
	// register this module in compartment.c
	compartment_register_module(&c_seccomp_module);
}
