/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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

#define _GNU_SOURCE

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "uevent.h"

#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>

#include "event.h"
#include "fd.h"
#include "file.h"
#include "dir.h"
#include "macro.h"
#include "mem.h"
#include "nl.h"
#include "proc.h"
#include "list.h"

#ifndef UEVENT_SEND
#define UEVENT_SEND 16
#endif

static nl_sock_t *uevent_netlink_sock = NULL;
static event_io_t *uevent_io_event = NULL;

// registerd uev events
static list_t *uevent_uev_kernel_list = NULL;
static list_t *uevent_uev_udev_list = NULL;

#define UDEV_MONITOR_TAG "libudev"
#define UDEV_MONITOR_MAGIC 0xfeedcafe

struct uevent_uev {
	uevent_uev_type_t type;
	unsigned actions;
	void (*func)(unsigned actions, uevent_event_t *event, void *data);
	void *data;
};

struct udev_monitor_netlink_header {
	/* "libudev" prefix to distinguish libudev and kernel messages */
	char prefix[8];
	/*
         * magic to protect against daemon <-> library message format mismatch
         * used in the kernel from socket filter rules; needs to be stored in network order
         */
	unsigned int magic;
	/* total length of header structure known to the sender */
	unsigned int header_size;
	/* properties string buffer */
	unsigned int properties_off;
	unsigned int properties_len;
	/*
         * hashes of primary device properties strings, to let libudev subscribers
         * use in-kernel socket filters; values need to be stored in network order
         */
	unsigned int filter_subsystem_hash;
	unsigned int filter_devtype_hash;
	unsigned int filter_tag_bloom_hi;
	unsigned int filter_tag_bloom_lo;
};

struct uevent_event {
	union {
		struct udev_monitor_netlink_header nlh;
		char raw[UEVENT_BUF_LEN]; //!< The raw string that we get from the kernel
	} msg;
	size_t msg_len;	       //!< The length of the uevent
	char *action;	       //!< The uevent ACTION, points inside of raw
	char *subsystem;       //!< The uevent SUBSYSTEM, points inside of raw
	char *devname;	       //!< The uevent DEVNAME, points inside of raw
	char *devpath;	       //!< The uevent DEVPATH, points inside of raw
	char *devtype;	       //!< The uevent DEVTYPE, points inside of raw
	char *driver;	       //!< The uevent DRIVER, points inside of raw
	int major;	       //!< The major number of the device
	int minor;	       //!< The minor number of the device
	char *type;	       //!< The uevent TYPE, points inside of raw
	char *product;	       //!< The uevent PRODUCT, points inside of raw (usb relevant)
	uint16_t id_vendor_id; //!< The udev event ID_VENDOR_ID inside of raw (usb relevenat)
	uint16_t id_model_id;  //!< The udev event ID_MODEL_ID of the device (usb relevant)
	char *id_serial_short; //!< The udev event ID_SERIAL_SHORT of the device (usb relevant)
	char *interface;       //!< The uevent INTERFACE, points inside of raw
	char *synth_uuid;      //!< The uevent SYNTH_UUID, points inside of raw (coldboot relevant)
	unsigned long long seqnum; //!< The seuqunze number of the uevent
};

static void
uevent_trace(uevent_event_t *uevent, char *raw_p)
{
	int i = 0;
	char *_raw_p = raw_p;
	while (*_raw_p || _raw_p < uevent->msg.raw + uevent->msg_len) {
		TRACE("uevent_raw[%d] '%s'", i++, _raw_p);
		/* advance to after the next \0 */
		while (*_raw_p++)
			;
	}
}

static bool
uevent_event_is_udev(const uevent_event_t *event)
{
	return !strncmp(event->msg.nlh.prefix, "libudev", event->msg_len);
}

static int
uevent_parse(uevent_event_t *uevent, char *raw_p_hint)
{
	char *raw_p;

	uevent->action = "";
	uevent->devpath = "";
	uevent->devname = "";
	uevent->devtype = "";
	uevent->major = -1;
	uevent->minor = -1;
	uevent->devname = "";
	uevent->subsystem = "";
	uevent->product = "";
	uevent->id_model_id = 0;
	uevent->id_vendor_id = 0;
	uevent->id_serial_short = "";
	uevent->interface = "";
	uevent->synth_uuid = "";

	if (raw_p_hint)
		raw_p = raw_p_hint;
	else
		raw_p = uevent->msg.raw;

	uevent_trace(uevent, raw_p);

	/* Parse the uevent->raw buffer and set the pointer in the uevent
	 * struct to point into the buffer at the correct locations */
	// TODO check if running out of the buffer
	while (*raw_p) {
		if (!strncmp(raw_p, "ACTION=", 7)) {
			raw_p += 7;
			uevent->action = raw_p;
		} else if (!strncmp(raw_p, "DEVPATH=", 8)) {
			raw_p += 8;
			uevent->devpath = raw_p;
		} else if (!strncmp(raw_p, "SUBSYSTEM=", 10)) {
			raw_p += 10;
			uevent->subsystem = raw_p;
		} else if (!strncmp(raw_p, "MAJOR=", 6)) {
			raw_p += 6;
			uevent->major = atoi(raw_p);
		} else if (!strncmp(raw_p, "MINOR=", 6)) {
			raw_p += 6;
			uevent->minor = atoi(raw_p);
		} else if (!strncmp(raw_p, "DEVNAME=", 8)) {
			raw_p += 8;
			uevent->devname = raw_p;
		} else if (!strncmp(raw_p, "DEVTYPE=", 8)) {
			raw_p += 8;
			uevent->devtype = raw_p;
		} else if (!strncmp(raw_p, "DRIVER=", 7)) {
			raw_p += 7;
			uevent->driver = raw_p;
		} else if (!strncmp(raw_p, "PRODUCT=", 8)) {
			raw_p += 8;
			uevent->product = raw_p;
		} else if (!strncmp(raw_p, "ID_VENDOR_ID=", 13)) {
			raw_p += 13;
			sscanf(raw_p, "%hx", &uevent->id_vendor_id);
		} else if (!strncmp(raw_p, "ID_MODEL_ID=", 12)) {
			raw_p += 12;
			sscanf(raw_p, "%hx", &uevent->id_model_id);
		} else if (!strncmp(raw_p, "ID_SERIAL_SHORT=", 16)) {
			raw_p += 16;
			uevent->id_serial_short = raw_p;
		} else if (!strncmp(raw_p, "INTERFACE=", 10)) {
			raw_p += 10;
			uevent->interface = raw_p;
		} else if (!strncmp(raw_p, "SYNTH_UUID=", 11)) {
			raw_p += 11;
			uevent->synth_uuid = raw_p;
		} else if (!strncmp(raw_p, "SEQNUM=", 7)) {
			raw_p += 7;
			uevent->seqnum = strtoull(raw_p, NULL, 10);
		}

		/* advance to after the next \0 */
		while (*raw_p++)
			;

		/* check if message ended */
		if (raw_p >= uevent->msg.raw + uevent->msg_len) {
			break;
		}
	}

	TRACE("uevent { '%s', '%s', '%s', '%s', %d, %d, '%s'}", uevent->action, uevent->devpath,
	      uevent->subsystem, uevent->devname, uevent->major, uevent->minor, uevent->interface);

	return 0;
}

uevent_event_t *
uevent_parse_from_string_new(const char *uev)
{
	IF_NULL_RETVAL_ERROR(uev, NULL);

	int len = strlen(uev);

	uevent_event_t *event = mem_new0(uevent_event_t, 1);

	memcpy(event->msg.raw, uev, len);
	event->msg_len = len;

	// replace newlines by null bytes
	for (int i = 0; i < len; i++) {
		if ('\n' == event->msg.raw[i]) {
			event->msg.raw[i] = '\0';
		}
	}

	uevent_parse(event, NULL);

	return event;
}

static int
uevent_parse_nl(uevent_event_t *uevent)
{
	ASSERT(uevent);

	char *raw_p = uevent->msg.raw;

	// skip header
	if (uevent_event_is_udev(uevent)) {
		/* udev message needs proper version magic */
		if (uevent->msg.nlh.magic != htonl(UDEV_MONITOR_MAGIC)) {
			WARN("unrecognized message signature (%x != %x)", uevent->msg.nlh.magic,
			     htonl(UDEV_MONITOR_MAGIC));
			return -1;
		}
		if (uevent->msg.nlh.properties_off + 32 > uevent->msg_len) {
			WARN("message smaller than expected (%u > %zd)",
			     uevent->msg.nlh.properties_off + 32, uevent->msg_len);
			return -1;
		}
		raw_p += uevent->msg.nlh.properties_off;
	} else if (strchr(raw_p, '@')) {
		/* kernel message */
		TRACE("kernel uevent: %s", raw_p ? raw_p : "NULL");
		raw_p += strlen(raw_p) + 1;
	} else {
		/* kernel message */
		TRACE("no uevent: %s", raw_p);
		return -1;
	}

	return uevent_parse(uevent, raw_p);
}

uevent_event_t *
uevent_replace_member(const uevent_event_t *uevent, char *oldmember, char *newmember)
{
	ASSERT(uevent);
	ASSERT(oldmember > uevent->msg.raw && oldmember < uevent->msg.raw + uevent->msg_len);

	uevent_event_t *newevent = mem_new(uevent_event_t, 1);
	//interface name is located in name and devpath members
	int diff_len = strlen(newmember) - strlen(oldmember);

	newevent->msg_len = uevent->msg_len + diff_len;

	//copy netlink header to cloned uevent
	if (!memcpy(&newevent->msg.nlh, &uevent->msg.nlh,
		    sizeof(struct udev_monitor_netlink_header))) {
		ERROR("Failed to clone netlink header");
		goto error;
	}
	newevent->msg.nlh.properties_len = uevent->msg.nlh.properties_len + diff_len;

	//copy uevent up to position of interface string
	int off_member = oldmember - uevent->msg.raw;
	if (!memcpy(newevent->msg.raw, uevent->msg.raw, off_member)) {
		ERROR("Failed to copy beginning of uevent");
		goto error;
	}

	//copy new member to uevent
	if (!strcpy(newevent->msg.raw + off_member, newmember)) {
		ERROR("Failed to new member to uevent");
		goto error;
	}

	//copy uevent after interface string
	size_t off_after_old = off_member + strlen(oldmember) + 1;
	size_t off_after_new = off_member + strlen(newmember) + 1;

	if (!memcpy(newevent->msg.raw + off_after_new, uevent->msg.raw + off_after_old,
		    uevent->msg_len - off_after_old)) {
		ERROR("Failed to copy remainder of uevent");
		goto error;
	}

	// add termianting null char
	if (newevent->msg_len > UEVENT_BUF_LEN)
		newevent->msg.raw[UEVENT_BUF_LEN - 1] = '\0';
	else
		newevent->msg.raw[newevent->msg_len] = '\0';

	IF_TRUE_GOTO_ERROR(uevent_parse_nl(newevent) == -1, error);

	return newevent;

error:
	if (newevent)
		mem_free0(newevent);

	return NULL;
}

uint16_t
uevent_event_get_usb_vendor(const uevent_event_t *uevent)
{
	if (uevent->id_vendor_id != 0)
		return (uint16_t)uevent->id_vendor_id;
	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_vendor;
}

uint16_t
uevent_event_get_usb_product(const uevent_event_t *uevent)
{
	if (uevent->id_model_id != 0)
		return (uint16_t)uevent->id_model_id;

	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_product;
}

char *
uevent_event_get_synth_uuid(const uevent_event_t *event)
{
	ASSERT(event);
	return event->synth_uuid;
}

char *
uevent_event_get_devname(const uevent_event_t *event)
{
	ASSERT(event);
	return event->devname;
}

char *
uevent_event_get_devtype(const uevent_event_t *event)
{
	ASSERT(event);
	return event->devtype;
}

char *
uevent_event_get_devpath(const uevent_event_t *event)
{
	ASSERT(event);
	return event->devpath;
}

char *
uevent_event_get_subsystem(const uevent_event_t *event)
{
	ASSERT(event);
	return event->subsystem;
}

char *
uevent_event_get_interface(const uevent_event_t *event)
{
	ASSERT(event);
	return event->interface;
}

int
uevent_event_get_minor(const uevent_event_t *event)
{
	ASSERT(event);
	return event->minor;
}

int
uevent_event_get_major(const uevent_event_t *event)
{
	ASSERT(event);
	return event->major;
}

uevent_event_t *
uevent_event_replace_synth_uuid_new(const uevent_event_t *event, char *uuid_string)
{
	ASSERT(event);
	uevent_event_t *event_new = uevent_replace_member(event, event->synth_uuid, uuid_string);
	return event_new;
}

uevent_event_t *
uevent_event_copy_new(const uevent_event_t *event)
{
	uevent_event_t *event_clone = mem_new0(uevent_event_t, 1);
	memcpy(event_clone, event, sizeof(uevent_event_t));

	// update internal pointers to cloned raw buffer
	if (uevent_parse_nl(event_clone) == -1)
		mem_free0(event_clone);

	return event_clone;
}

/**
 * This function forks a new child in the target netns (and userns) of netns_pid
 * in which the uevents should be injected. In the child the UEVENT netlink socket
 * is connected and a new message containing the raw uevent will be created and
 * sent to that socket.
 */
int
uevent_event_inject_into_netns(uevent_event_t *event, pid_t netns_pid, bool join_userns)
{
	int status;
	char *uevent = event->msg.raw;
	size_t size = event->msg_len;

	pid_t pid = fork();

	if (pid == -1) {
		ERROR_ERRNO("Could not fork for switching to netns of %d", netns_pid);
		return -1;
	} else if (pid == 0) {
		if (join_userns) {
			char *usrns = mem_printf("/proc/%d/ns/user", netns_pid);
			int usrns_fd = open(usrns, O_RDONLY);
			if (usrns_fd == -1)
				FATAL_ERRNO("Could not open userns file %s!", usrns);
			mem_free0(usrns);
			if (setns(usrns_fd, CLONE_NEWUSER) == -1)
				FATAL_ERRNO("Could not join uesr namespace of pid %d!", netns_pid);
			if (setuid(0) < 0)
				FATAL_ERRNO("Could setuid to root in user namespace of pid %d!",
					    netns_pid);
			if (setgid(0) < 0)
				FATAL_ERRNO("Could setgid to root in user namespace of pid %d!",
					    netns_pid);
			if (setgroups(0, NULL) < 0)
				FATAL_ERRNO("Could setgroups to root in user namespace of pid %d!",
					    netns_pid);
		}
		char *netns = mem_printf("/proc/%d/ns/net", netns_pid);
		int netns_fd = open(netns, O_RDONLY);
		if (netns_fd == -1)
			FATAL_ERRNO("Could not open netns file %s!", netns);
		mem_free0(netns);
		if (setns(netns_fd, CLONE_NEWNET) == -1)
			FATAL_ERRNO("Could not join network namespace of pid %d!", netns_pid);
		nl_sock_t *target = nl_sock_uevent_new(0);
		if (NULL == target)
			FATAL("Could not connect to nl socket!");
		nl_msg_t *nl_msg = nl_msg_new();
		if (NULL == nl_msg)
			FATAL_ERRNO("Could not allocate nl_msg!");
		if (nl_msg_set_type(nl_msg, UEVENT_SEND) < 0)
			FATAL("Could not set type UEVENT_SEND of nl_msg!");
		if (nl_msg_set_flags(nl_msg, NLM_F_ACK | NLM_F_REQUEST))
			FATAL("Could not set flages for acked request of nl_msg!");
		if (nl_msg_set_buf_unaligned(nl_msg, uevent, size) < 0)
			FATAL_ERRNO("Could not add uevent to nl_msg!");
		if (nl_msg_send_kernel(target, nl_msg) < 0)
			FATAL_ERRNO("Could not inject uevent!");
		if (nl_msg_receive_and_check_kernel(target))
			FATAL_ERRNO("Could not verify resp to injected uevent!");
		nl_sock_free(target);
		nl_msg_free(nl_msg);
		_exit(0);
	} else {
		if (proc_waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%d'", pid);
		} else if (!WIFEXITED(status)) {
			ERROR("Child %d in netns_pid '%d' terminated abnormally", pid, netns_pid);
		} else {
			return WEXITSTATUS(status) ? -1 : 0;
		}
	}
	return -1;
}

static unsigned
uevent_action_from_string(const char *action)
{
	if (!strcmp(action, "add"))
		return UEVENT_ACTION_ADD;
	if (!strcmp(action, "bind"))
		return UEVENT_ACTION_BIND;
	if (!strcmp(action, "change"))
		return UEVENT_ACTION_CHANGE;
	if (!strcmp(action, "remove"))
		return UEVENT_ACTION_REMOVE;
	if (!strcmp(action, "unbind"))
		return UEVENT_ACTION_UNBIND;
	if (!strcmp(action, "move"))
		return UEVENT_ACTION_MOVE;

	return 0;
}

static void
handle_uev_list(uevent_event_t *uevent, list_t *event_list)
{
	TRACE("handle_udev_event");

	/* handle registerd uev udev events */
	for (list_t *l = event_list; l; l = l->next) {
		uevent_uev_t *uev = l->data;
		unsigned action = uevent_action_from_string(uevent->action);
		if (action & uev->actions)
			uev->func(action, uevent, uev->data);
	}
	TRACE("Handled uevent seqnum=%llu.", uevent->seqnum);
}

static void
uevent_handle(UNUSED int fd, UNUSED unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	uevent_event_t *uev = mem_new0(uevent_event_t, 1);

	// read uevent into raw buffer and assure that last char is '\0'
	if ((uev->msg_len = nl_msg_receive_kernel(uevent_netlink_sock, uev->msg.raw,
						  sizeof(uev->msg.raw) - 1, true)) <= 0) {
		WARN("could not read uevent");
		goto err;
	}

	IF_TRUE_GOTO_TRACE(uevent_parse_nl(uev) == -1, err);

	char *raw_p = uev->msg.raw;

	if (uevent_event_is_udev(uev)) {
		/* udev message */
		TRACE("udev uevent: %s", raw_p ? raw_p : "NULL");
		handle_uev_list(uev, uevent_uev_udev_list);
	} else if (strchr(raw_p, '@')) {
		/* kernel message */
		TRACE("kernel uevent: %s", raw_p ? raw_p : "NULL");
		handle_uev_list(uev, uevent_uev_kernel_list);
	}
err:
	mem_free0(uev);
}

static int
uevent_init()
{
	if (uevent_netlink_sock != NULL) {
		ERROR("Uevent netlink_socket already exists.");
		return -1;
	}
	if (uevent_io_event != NULL) {
		ERROR("Uevent io_event already exists.");
		return -1;
	}

	/* find the udevd started by cml's init */
	pid_t udevd_pid = proc_find(1, "systemd-udevd");
	pid_t eudevd_pid = proc_find(1, "udevd");

	if (eudevd_pid < udevd_pid && eudevd_pid > 0)
		udevd_pid = eudevd_pid;

	if (!(uevent_netlink_sock = nl_sock_uevent_new(udevd_pid))) {
		ERROR("Could not open netlink socket");
		return -1;
	}

	if (fd_make_non_blocking(nl_sock_get_fd(uevent_netlink_sock))) {
		ERROR("Could not set fd of netlink sockt to non blocking!");
		nl_sock_free(uevent_netlink_sock);
		return -1;
	}

	uevent_io_event = event_io_new(nl_sock_get_fd(uevent_netlink_sock), EVENT_IO_READ,
				       &uevent_handle, NULL);
	event_add_io(uevent_io_event);

	return 0;
}

static void
uevent_deinit()
{
	if (uevent_io_event) {
		event_remove_io(uevent_io_event);
		event_io_free(uevent_io_event);
	}
	if (uevent_netlink_sock) {
		nl_sock_free(uevent_netlink_sock);
	}
}

uevent_uev_t *
uevent_uev_new(uevent_uev_type_t type, unsigned actions,
	       void (*func)(unsigned actions, uevent_event_t *event, void *data), void *data)
{
	uevent_uev_t *uev;

	IF_FALSE_RETVAL(actions, NULL);
	IF_NULL_RETVAL(func, NULL);

	uev = mem_new0(uevent_uev_t, 1);
	uev->type = type;
	uev->actions = actions;
	uev->func = func;
	uev->data = data;

	return uev;
}

void
uevent_uev_free(uevent_uev_t *uev)
{
	mem_free0(uev);
}

int
uevent_add_uev(uevent_uev_t *uev)
{
	IF_NULL_RETVAL(uev, -1);

	if (uevent_io_event == NULL) {
		if (uevent_init()) {
			ERROR("Low-level uevent handling not available!");
			return -1;
		}
	}

	if (uev->type == UEVENT_UEV_TYPE_KERNEL) {
		uevent_uev_kernel_list = list_append(uevent_uev_kernel_list, uev);
	} else if (uev->type == UEVENT_UEV_TYPE_UDEV) {
		uevent_uev_udev_list = list_append(uevent_uev_udev_list, uev);
	} else {
		ERROR("Unknown type %d for uev", uev->type);
		return -1;
	}

	TRACE("Added uev uevent %p (func=%p, data=%p, actions=0x%x)", (void *)uev,
	      CAST_FUNCPTR_VOIDPTR uev->func, uev->data, uev->actions);

	return 0;
}

void
uevent_remove_uev(uevent_uev_t *uev)
{
	IF_NULL_RETURN(uev);
	TRACE("Removing uev uevent %p", (void *)uev);

	if (uev->type == UEVENT_UEV_TYPE_KERNEL) {
		uevent_uev_kernel_list = list_remove(uevent_uev_kernel_list, uev);
	} else if (uev->type == UEVENT_UEV_TYPE_UDEV) {
		uevent_uev_udev_list = list_remove(uevent_uev_udev_list, uev);
	} else {
		ERROR("Unknown type %d for uev", uev->type);
		return;
	}

	TRACE("Removed uev event %p (func=%p, data=%p, actions=0x%x)", (void *)uev,
	      CAST_FUNCPTR_VOIDPTR uev->func, uev->data, uev->actions);

	if (uevent_uev_udev_list == NULL && uevent_uev_kernel_list == NULL) {
		TRACE("Last uevent handler removed, disconnect from low-level uevent handling");
		uevent_deinit();
	}
}

struct uevent_udev_coldboot_data {
	const uuid_t *synth_uuid;
	bool (*filter)(int major, int minor, void *data);
	void *data;
};

static int
uevent_trigger_coldboot_foreach_cb(const char *path, const char *name, void *data)
{
	int ret = 0;
	char buf[256];
	int major, minor;

	struct uevent_udev_coldboot_data *coldboot_data = data;
	IF_NULL_RETVAL(coldboot_data, -1);

	char *full_path = mem_printf("%s/%s", path, name);
	char *dev_file = NULL;

	if (file_is_dir(full_path)) {
		if (0 > dir_foreach(full_path, &uevent_trigger_coldboot_foreach_cb, data)) {
			WARN("Could not trigger coldboot uevents! No '%s'!", full_path);
			ret--;
		}
	} else if (!strcmp(name, "uevent")) {
		dev_file = mem_printf("%s/dev", path);

		IF_FALSE_GOTO_TRACE(file_exists(dev_file), out);

		major = minor = -1;
		IF_TRUE_GOTO(-1 == file_read(dev_file, buf, sizeof(buf)), out);
		IF_TRUE_GOTO((sscanf(buf, "%d:%d", &major, &minor) < 0), out);
		IF_FALSE_GOTO((major > -1 && minor > -1), out);

		// only trigger for allowed devices
		if (coldboot_data->filter)
			IF_FALSE_GOTO_TRACE(
				coldboot_data->filter(major, minor, coldboot_data->data), out);

		char *trigger = mem_printf("add %s", uuid_string(coldboot_data->synth_uuid));
		if (-1 == file_printf(full_path, "%s", trigger)) {
			WARN("Could not trigger event %s <- %s", full_path, trigger);
			ret--;
		} else {
			DEBUG("Trigger event %s <- %s", full_path, trigger);
		}
		mem_free0(trigger);
	}
out:
	mem_free0(full_path);
	if (dev_file)
		mem_free0(dev_file);
	return ret;
}

void
uevent_udev_trigger_coldboot(const uuid_t *synth_uuid,
			     bool (*filter)(int major, int minor, void *data), void *data)
{
	const char *sysfs_devices = "/sys/devices";
	struct uevent_udev_coldboot_data coldboot_data = { .synth_uuid = synth_uuid,
							   .filter = filter,
							   .data = data };
	// for the first time iterate through sysfs to find device
	if (0 > dir_foreach(sysfs_devices, &uevent_trigger_coldboot_foreach_cb, &coldboot_data)) {
		WARN("Could not trigger coldboot uevents! No '%s'!", sysfs_devices);
	}
}
