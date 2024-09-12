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
 * @file c_seccomp/seccomp.c
 *
 * This module handles system call hooking and emulation through the seccomp notify kernel functionality.
 * It applies a seccomp filter matching relevant system calls before the container init process is executed.
 * Access to global resources on behalf of a container through this module is controlled by compartment
 * flags defined in compartment.h. If access to a particular resource is allowed, this module emulates the
 * syscalls a container issues to access the resource.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_seccomp"

#include "../compartment.h"
#include "../audit.h"

#include <common/macro.h>
#include <common/mem.h>
#include <common/fd.h>
#include <common/file.h>
#include <common/event.h>
#include <common/audit.h>
#include <common/kernel.h>
#include <common/proc.h>

#include "seccomp.h"

#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <linux/seccomp.h>

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

int
pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

int
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

int
capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
	return syscall(__NR_capget, hdrp, datap);
}
/**************************/

static int
c_seccomp_install_filter(c_seccomp_t *_seccomp)
{
	struct sock_filter filter_head[] = {
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
	};

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
	struct sock_filter filter_tail[] = {
#if (C_SECCOMP_AUDIT_ARCH != AUDIT_ARCH_AARCH64)
		/*
		 * Note for future syscalls
		 * ========================
		 *
		 * Note that the offset to the SECCOMP_RET_USER_NOTIF statement
		 * depends on whether SYS_mknod is handled and is therefore
		 * architecture dependent. For all syscalls handled above these
		 * lines, make sure that these are self contained, i.e. have a
		 * fixed offset to their ALLOW/USER_NOTIF statement!
		 */

		/*
		 * for mknod(): load args[1] (mode_t mode) from seccomp_data,
		 * check if mode is blk or char dev -> SECCOMP_RET_NOTIFY
		 * otherwise skip emulation. -> SECCOMP_RET_ALLOW
		 *
		 * The mknod system call is not defined for the arm64 architecture,
		 * therefore disable this check on arm64 as SYS_mknod is not defined
		 * there.
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mknod, 0, 3),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFCHR, 10, 0),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, S_IFBLK, 9, 0),
#endif

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

	int filter_ioctl_size = 0;
	struct sock_filter *filter_ioctl = c_seccomp_ioctl_get_filter(_seccomp, &filter_ioctl_size);

	size_t filter_head_len = sizeof(filter_head) / sizeof(struct sock_filter);
	size_t filter_tail_len = sizeof(filter_tail) / sizeof(struct sock_filter);
	size_t filter_ioctl_len =
		filter_ioctl_size > 0 ? filter_ioctl_size / sizeof(struct sock_filter) : 0;

	size_t filter_len = filter_head_len + filter_ioctl_len + filter_tail_len;

	struct sock_filter *filter = mem_new0(struct sock_filter, filter_len);

	memcpy(filter, &filter_head[0], sizeof(filter_head));
	if (filter_ioctl && filter_ioctl_size > 0)
		memcpy(&filter[filter_head_len], filter_ioctl, filter_ioctl_size);

	memcpy(&filter[filter_head_len + filter_ioctl_len], filter_tail, sizeof(filter_tail));

	struct sock_fprog prog = { .len = filter_len, .filter = filter };

	int ret = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
	if (-1 == ret) {
		ERROR_ERRNO("SECCOMP_SET_MODE_FILTER: return value was %d", ret);
		mem_free0(filter);
		return -1;
	}

	mem_free0(filter);
	return ret;
}

static bool
c_seccomp_is_pidfd_supported()
{
	return kernel_version_check("5.10.0");
}

bool
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

void *
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

		seccomp->event = NULL;
		seccomp->notify_fd = -1;

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

	/*
	 * Emulation helpers set return value to value of the syscall executed by cmld
	 * on behalf of the container. If early errors occure emulation returns 0.
	 * If the excuted system call exits with an error (-1) we log the emulation error
	 * to the audit subsystem.
	 */
	int ret_syscall = 0;

	switch (req->data.nr) {
	case SYS_clock_adjtime:
		ret_syscall = c_seccomp_emulate_adjtime(seccomp, req, resp);
		break;
	case SYS_adjtimex:
		ret_syscall = c_seccomp_emulate_adjtimex(seccomp, req, resp);
		break;
	case SYS_clock_settime:
		ret_syscall = c_seccomp_emulate_settime(seccomp, req, resp);
		break;
	case SYS_ioctl:
		ret_syscall = c_seccomp_emulate_ioctl(seccomp, req, resp);
		break;
	case SYS_finit_module:
		ret_syscall = c_seccomp_emulate_finit_module(seccomp, req, resp);
		break;
#if (C_SECCOMP_AUDIT_ARCH != AUDIT_ARCH_AARCH64)
	// SYS_mknod not defined on arm64
	case SYS_mknod:
#endif
	case SYS_mknodat:
		ret_syscall = c_seccomp_emulate_mknodat(seccomp, req, resp);
		break;
	default:
		ret_syscall = 0;
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-unexpected-syscall",
				compartment_get_name(seccomp->compartment), 2, "syscall",
				req->data.nr);

		ERROR("Got syscall not handled by us: %d", req->data.nr);

		resp->error = 0;
		resp->val = 0;
		resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
	}

	if (-1 == ret_syscall) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-emulation-failed",
				compartment_get_name(seccomp->compartment), 2, "syscall",
				req->data.nr);
	}

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
c_seccomp_start_pre_exec_child_early(void *seccompp)
{
	ASSERT(seccompp);
	c_seccomp_t *seccomp = seccompp;

	int notify_fd = -1;

	if (-1 == (notify_fd = c_seccomp_install_filter(seccomp))) {
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

	seccomp->notify_fd = -1;
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
