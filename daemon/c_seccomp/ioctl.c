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
 * @file c_seccomp/ioctl.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for the ioctl()
 * system call. It only handles RTC related ioctls to allow setting the hwclock.
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"

#include <common/macro.h>
#include <common/mem.h>
#include <common/ns.h>
#include <common/proc.h>

#include "seccomp.h"

#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/rtc.h>
#include <linux/seccomp.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

/*
 * This partial filter continues all system calls and only handles
 * (notify) SYS_ioctl.
 * Remember that this needs to be integrated in the overall filter
 * since we assume syscall nr already loaded and if it is not
 * SYS_ioctl, we jump one instruction beyond the last instruction
 * of filter_ioctl to the next comparison of syscall number.
 */
static struct sock_filter c_seccomp_filter_ioctl[] = {
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 6),
	BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTC_EPOCH_SET, 3, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTC_SET_TIME, 2, 0),
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, RTC_PARAM_SET, 1, 0),

	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
};

static int
rtc_ioctl(unsigned int fd, unsigned int cmd, unsigned long param)
{
	return syscall(__NR_ioctl, fd, cmd, param);
}

struct ioctl_fork_data {
	unsigned int fd;
	unsigned int cmd;
	unsigned long param;
};

static int
c_seccomp_do_ioctl_fork(const void *data)
{
	const struct ioctl_fork_data *params = data;
	ASSERT(params);

	DEBUG("Executing ioctl in namespaces of container");
	int ret = rtc_ioctl(params->fd, params->cmd, params->param);
	if (ret == -1)
		ERROR_ERRNO("rtc_ioctl() failed in namespaces of container!");

	return ret;
}

static int
c_seccomp_proc_get_rtc_major(void)
{
	FILE *file = fopen("/proc/devices", "r");
	char line[256];
	int major = -1;
	int n = -1;

	IF_NULL_RETVAL(file, -1);

	while (fgets(line, sizeof(line), file)) {
		if (!strstr(line, "rtc"))
			continue;

		n = sscanf(line, "%d rtc", &major);
		TRACE("line: %s, n=%d; major=%d", line, n, major);
		break;
	}

	fclose(file);

	IF_TRUE_RETVAL(n != 1, -1);

	TRACE("Parsed major of /dev/rtc*: %d", major);
	return major;
}

struct sock_filter *
c_seccomp_ioctl_get_filter(c_seccomp_t *seccomp, int *size)
{
	*size = 0;

	if ((!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment)) ||
	     c_seccomp_proc_get_rtc_major() <= 0)) {
		DEBUG("Compartment seccomp filter will not handle ioctl() syscalls");
		return NULL;
	}

	*size = sizeof(c_seccomp_filter_ioctl);

	INFO("Enable rtc specific ioctl() emulation!");
	return c_seccomp_filter_ioctl;
}

int
c_seccomp_emulate_ioctl(c_seccomp_t *seccomp, struct seccomp_notif *req,
			struct seccomp_notif_resp *resp)
{
	int ret_ioctl = 0;
	int fd_in_target = -1;
	unsigned int cmd = 0;
	unsigned long param = 0;

	/*
	 * in any case of error just continue the syscall in the kernel,
	 * we are only interested in /dev/rtc* devices to allow setting the hw clock
	 */
	resp->error = 0;
	resp->val = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

	if (!(COMPARTMENT_FLAG_SYSTEM_TIME & compartment_get_flags(seccomp->compartment))) {
		TRACE("Flag SYSTEM_TIME not set. Continue syscall as is: %d", req->data.nr);

		goto out;
	}

	DEBUG("Got ioctl from pid %d, fd: %u, cmd: %u, param: %lu", req->pid,
	      (unsigned int)req->data.args[0], (unsigned int)req->data.args[1],
	      (unsigned long)req->data.args[2]);

	cmd = (unsigned int)req->data.args[1];
	switch (cmd) {
	case RTC_EPOCH_SET:
		TRACE("handling RTC_EPOCH_SET!");
		if (!(param = (unsigned long)c_seccomp_fetch_vm_new(seccomp, req->pid,
								    (void *)req->data.args[2],
								    sizeof(unsigned long)))) {
			ERROR_ERRNO("Failed to fetch struct rtc_time");
		}
		break;
	case RTC_SET_TIME:
		TRACE("handling RTC_SET_TIME!");
		if (!(param = (unsigned long)c_seccomp_fetch_vm_new(seccomp, req->pid,
								    (void *)req->data.args[2],
								    sizeof(struct rtc_time)))) {
			ERROR_ERRNO("Failed to fetch struct rtc_time");
		}
		break;
	case RTC_PARAM_SET:
		TRACE("handling RTC_PARAM_SET!");
		if (!(param = (unsigned long)c_seccomp_fetch_vm_new(seccomp, req->pid,
								    (void *)req->data.args[2],
								    sizeof(struct rtc_param)))) {
			ERROR_ERRNO("Failed to fetch struct rtc_time");
		}
		break;
	default:
		ERROR("cmd %d != RTC_EPOCH_SET, RTC_SET_TIME, RTC_PARAM_SET not handled by us",
		      cmd);
		goto out;
	}

	int pidfd = pidfd_open(req->pid, 0);
	IF_TRUE_GOTO_ERROR(-1 == pidfd, out);

	fd_in_target = pidfd_getfd(pidfd, req->data.args[0], 0);
	if (fd_in_target < 0) {
		ERROR("Failed to get dup of target fd %u!", (unsigned int)req->data.args[0]);
		goto out;
	}

	struct stat s;
	if (!(!fstat(fd_in_target, &s) && S_ISCHR(s.st_mode))) {
		TRACE("fd_in_target is no char dev, continue as is.");
		goto out;
	}

	/* Check cap of target pid in its namespace */
	if (!c_seccomp_capable(req->pid, CAP_SYS_TIME)) {
		ERROR("Missing CAP_SYS_TIME for process %d!", req->pid);
		goto out;
	}

	/* Check if dev is allowed (c_cgroups submodule) */
	dev_t dev = s.st_rdev;
	if (!container_is_device_allowed(seccomp->container, 'c', major(dev), minor(dev))) {
		ERROR("Missing cgroup permission for device (c %d:%d) in process %d!", major(dev),
		      minor(dev), req->pid);
		goto out;
	}

	struct ioctl_fork_data ioctl_params = { .fd = fd_in_target, .cmd = cmd, .param = param };
	if (-1 ==
	    (ret_ioctl = namespace_exec(req->pid, CLONE_NEWALL & (~CLONE_NEWPID) & (~CLONE_NEWUSER),
					container_get_uid(seccomp->container), CAP_SYS_TIME,
					c_seccomp_do_ioctl_fork, &ioctl_params))) {
		ERROR_ERRNO("Failed to execute rtc_ioctl");
		goto out;
	}

	DEBUG("ioctl returned %d", ret_ioctl);

	/* prepare answer */
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_ioctl;
	/* ioctl emulated by us, so clear SECCOMP_USER_NOTIF_FLAG_CONTINUE flag */
	resp->flags = 0;

out:
	if (fd_in_target > 0)
		close(fd_in_target);

	return ret_ioctl;
}
