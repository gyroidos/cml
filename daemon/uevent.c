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

#define _GNU_SOURCE
#include "uevent.h"
#include <arpa/inet.h>
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "cmld.h"
#include "container.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/nl.h"
#include "common/proc.h"

#ifndef UEVENT_SEND
#define UEVENT_SEND 16
#endif

static nl_sock_t *uevent_netlink_sock = NULL;
static event_io_t *uevent_io_event = NULL;

// track usb devices mapped to containers
static list_t *uevent_container_dev_mapping_list = NULL;

#define UDEV_MONITOR_TAG "libudev"
#define UDEV_MONITOR_MAGIC 0xfeedcafe

struct uevent_usbdev {
	char *i_serial;
	uint16_t id_vendor;
	uint16_t id_product;
	int major;
	int minor;
	bool assign;
};

uevent_usbdev_t *
uevent_usbdev_new(uint16_t id_vendor, uint16_t id_product, char *i_serial, bool assign)
{
	uevent_usbdev_t *usbdev = mem_new0(uevent_usbdev_t, 1);
	usbdev->id_vendor = id_vendor;
	usbdev->id_product = id_product;
	usbdev->i_serial = mem_strdup(i_serial);
	usbdev->assign = assign;
	usbdev->major = -1;
	usbdev->minor = -1;
	return usbdev;
}

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

struct uevent {
	union {
		struct udev_monitor_netlink_header nlh;
		char raw[UEVENT_BUF_LEN]; //!< The raw string that we get from the kernel
	} msg;
	size_t msg_len;	//!< The length of the uevent
	char *action;	  //!< The uevent ACTION, points inside of raw
	char *subsystem;       //!< The uevent SUBSYSTEM, points inside of raw
	char *devname;	 //!< The uevent DEVNAME, points inside of raw
	char *devpath;	 //!< The uevent DEVPATH, points inside of raw
	char *devtype;	 //!< The uevent DEVTYPE, points inside of raw
	char *driver;	  //!< The uevent DRIVER, points inside of raw
	int major;	     //!< The major number of the device
	int minor;	     //!< The minor number of the device
	char *type;	    //!< The uevent TYPE, points inside of raw
	char *product;	 //!< The uevent PRODUCT, points inside of raw (usb relevant)
	uint16_t id_vendor_id; //!< The udev event ID_VENDOR_ID inside of raw (usb relevenat)
	uint16_t id_model_id;  //!< The udev event ID_MODEL_ID of the device (usb relevant)
	char *id_serial_short; //!< The udev event ID_SERIAL_SHORT of the device (usb relevant)
	char *interface;       //!< The uevent INTERFACE, points inside of raw
};

typedef struct uevent_container_dev_mapping {
	container_t *container;
	uevent_usbdev_t *usbdev;
	bool assign;
} uevent_container_dev_mapping_t;

uint16_t
uevent_usbdev_get_id_vendor(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_vendor;
}

uint16_t
uevent_usbdev_get_id_product(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->id_product;
}

char *
uevent_usbdev_get_i_serial(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->i_serial;
}

bool
uevent_usbdev_is_assigned(uevent_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	return usbdev->assign;
}

void
uevent_usbdev_set_major(uevent_usbdev_t *usbdev, int major)
{
	ASSERT(usbdev);
	usbdev->major = major;
}

void
uevent_usbdev_set_minor(uevent_usbdev_t *usbdev, int minor)
{
	ASSERT(usbdev);
	usbdev->minor = minor;
}

static uevent_container_dev_mapping_t *
uevent_container_dev_mapping_new(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping = mem_new0(uevent_container_dev_mapping_t, 1);
	mapping->container = container;
	mapping->usbdev = mem_new0(uevent_usbdev_t, 1);
	mapping->usbdev->i_serial = mem_strdup(usbdev->i_serial);
	mapping->usbdev->id_vendor = usbdev->id_vendor;
	mapping->usbdev->id_product = usbdev->id_product;
	mapping->usbdev->major = usbdev->major;
	mapping->usbdev->minor = usbdev->minor;
	mapping->usbdev->assign = usbdev->assign;

	return mapping;
}

static void
uevent_container_dev_mapping_free(uevent_container_dev_mapping_t *mapping)
{
	if (mapping->usbdev) {
		if (mapping->usbdev->i_serial)
			mem_free(mapping->usbdev->i_serial);
		mem_free(mapping->usbdev);
	}
	mem_free(mapping);
}

static void
uevent_trace(struct uevent *uevent, char *raw_p)
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

static void
uevent_parse(struct uevent *uevent, char *raw_p)
{
	ASSERT(uevent);

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
		}

		/* advance to after the next \0 */
		while (*raw_p++)
			;

		/* check if message ended */
		if (raw_p >= uevent->msg.raw + uevent->msg_len)
			break;
	}

	TRACE("uevent { '%s', '%s', '%s', '%s', %d, %d, '%s'}", uevent->action, uevent->devpath,
	      uevent->subsystem, uevent->devname, uevent->major, uevent->minor, uevent->interface);
}

static uint16_t
uevent_get_usb_vendor(struct uevent *uevent)
{
	if (uevent->id_vendor_id != 0)
		return (uint16_t)uevent->id_vendor_id;
	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_vendor;
}

static uint16_t
uevent_get_usb_product(struct uevent *uevent)
{
	if (uevent->id_model_id != 0)
		return (uint16_t)uevent->id_model_id;

	uint16_t id_vendor = 0;
	uint16_t id_product = 0;
	uint16_t version = 0;
	sscanf(uevent->product, "%hx/%hx/%hx", &id_vendor, &id_product, &version);

	return id_product;
}

/**
 * This function forks a new child in the target netns (and userns) of netns_pid
 * in which the uevents should be injected. In the child the UEVENT netlink socket
 * is connected and a new message containing the raw uevent will be created and
 * sent to that socket.
 */
static int
uevent_inject_into_netns(char *uevent, size_t size, pid_t netns_pid, bool join_userns)
{
	int status;
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
			mem_free(usrns);
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
		mem_free(netns);
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
		exit(0);
	} else {
		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%d'", pid);
		} else if (!WIFEXITED(status)) {
			ERROR("Child %d in netns_pid '%d' terminated abnormally", pid, netns_pid);
		} else {
			return WEXITSTATUS(status) ? -1 : 0;
		}
	}
	return -1;
}

static int
uevent_create_device_node(struct uevent *uevent, container_t *container)
{
	char *path = mem_printf("%s/dev/%s", container_get_rootdir(container), uevent->devname);

	if (file_exists(path)) {
		mem_free(path);
		return 0;
	}

	// dirname may modify original string, thus strdup
	char *path_dirname = mem_strdup(path);
	if (dir_mkdir_p(dirname(path_dirname), 0755) < 0) {
		ERROR("Could not create path for device node");
		goto err;
	}
	dev_t dev = makedev(uevent->major, uevent->minor);
	mode_t mode = strcmp(uevent->devtype, "disk") ? S_IFCHR : S_IFBLK;
	INFO("Creating device node (%c %d:%d) in %s", S_ISBLK(mode) ? 'd' : 'c', uevent->major,
	     uevent->minor, path);
	if (mknod(path, mode, dev) < 0) {
		ERROR_ERRNO("Could not create device node");
		goto err;
	}
	if (container_shift_ids(container, path, false) < 0) {
		ERROR("Failed to fixup uids for '%s' in usernamspace of container %s", path,
		      container_get_name(container));
		goto err;
	}
	mem_free(path_dirname);
	mem_free(path);
	return 0;
err:
	mem_free(path_dirname);
	mem_free(path);
	return -1;
}

static void
uevent_sysfs_timer_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	char *interface = data;

	char *phy_path = mem_printf("/sys/class/net/%s/phy80211", interface);
	if (!file_exists(phy_path)) {
		mem_free(phy_path);
		return;
	}

	if (container_add_net_iface(cmld_containers_get_a0(), interface, false))
		ERROR("Cannot move '%s' to c0!", interface);
	else
		INFO("Moved phys network interface '%s' to c0", interface);

	mem_free(phy_path);
	mem_free(interface);
	event_remove_timer(timer);
	event_timer_free(timer);
}

static void
handle_kernel_event(struct uevent *uevent, char *raw_p)
{
	uevent_parse(uevent, raw_p);

	/* just handle add,remove or change events to containers */
	IF_TRUE_RETURN_TRACE(strncmp(uevent->action, "add", 3) &&
			     strncmp(uevent->action, "remove", 6) &&
			     strncmp(uevent->action, "change", 6));

	/* move network ifaces to c0 */
	if (!strncmp(uevent->action, "add", 3) && !strcmp(uevent->subsystem, "net") &&
	    !strstr(uevent->devpath, "virtual")) {
		if (!strcmp(uevent->devtype, "wlan")) {
			// give sysfs some time to settle if iface is wifi
			event_timer_t *e = event_timer_new(100, EVENT_TIMER_REPEAT_FOREVER,
							   uevent_sysfs_timer_cb,
							   mem_strdup(uevent->interface));
			event_add_timer(e);
		} else if (container_add_net_iface(cmld_containers_get_a0(), uevent->interface,
						   false)) {
			ERROR("Cannot move '%s' to c0!", uevent->interface);
		} else {
			INFO("Moved phys network interface '%s' to c0", uevent->interface);
		}
	}

	/* Iterate over containers */
	for (int i = 0; i < cmld_containers_get_count(); i++) {
		container_t *c = cmld_container_get_by_index(i);
		if (!c) {
			WARN("Could not get container with index %d", i);
			continue;
		}
		if ((container_get_state(c) == CONTAINER_STATE_BOOTING) ||
		    (container_get_state(c) == CONTAINER_STATE_RUNNING) ||
		    (container_get_state(c) == CONTAINER_STATE_SETUP)) {
			if (!container_is_device_allowed(c, uevent->major, uevent->minor))
				continue;

			if (uevent_create_device_node(uevent, c) < 0) {
				ERROR("Could not create device node");
				continue;
			}

			if (uevent_inject_into_netns(uevent->msg.raw, uevent->msg_len,
						     container_get_pid(c),
						     container_has_userns(c)) < 0) {
				WARN("Could not inject uevent into netns of container %s!",
				     container_get_name(c));
			} else {
				TRACE("Sucessfully injected uevent into netns of container %s!",
				      container_get_name(c));
			}
		}
	}
}

static void
handle_udev_event(struct uevent *uevent, char *raw_p)
{
	uevent_parse(uevent, raw_p);

	IF_TRUE_RETURN_TRACE(strncmp(uevent->subsystem, "usb", 3) ||
			     strncmp(uevent->devtype, "usb_device", 10));

	if (0 == strncmp(uevent->action, "unbind", 6)) {
		TRACE("unbind");
		list_t *found = NULL;
		for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
			uevent_container_dev_mapping_t *mapping = l->data;
			if ((uevent->major == mapping->usbdev->major) &&
			    (uevent->minor == mapping->usbdev->minor)) {
				found = list_append(found, mapping);
				container_device_deny(mapping->container, mapping->usbdev->major,
						      mapping->usbdev->minor);
				INFO("Denied access to unbound device node %d:%d mapped in container %s",
				     mapping->usbdev->major, mapping->usbdev->minor,
				     container_get_name(mapping->container));
			}
		}
		return;
	}

	if (0 == strncmp(uevent->action, "bind", 4)) {
		TRACE("bind");
		for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
			uevent_container_dev_mapping_t *mapping = l->data;
			uint16_t vendor_id = uevent_get_usb_vendor(uevent);
			uint16_t product_id = uevent_get_usb_product(uevent);
			char *serial = uevent->id_serial_short;

			INFO("check mapping: %04x:%04x '%s' for %s bound device node %d:%d -> container %s",
			     vendor_id, product_id, serial, (mapping->assign) ? "assign" : "allow",
			     uevent->major, uevent->minor, container_get_name(mapping->container));

			if ((mapping->usbdev->id_vendor == vendor_id) &&
			    (mapping->usbdev->id_product == product_id) &&
			    (0 == strcmp(mapping->usbdev->i_serial, serial))) {
				mapping->usbdev->major = uevent->major;
				mapping->usbdev->minor = uevent->minor;
				INFO("%s bound device node %d:%d -> container %s",
				     (mapping->assign) ? "assign" : "allow", mapping->usbdev->major,
				     mapping->usbdev->minor,
				     container_get_name(mapping->container));

				container_device_allow(mapping->container, mapping->usbdev->major,
						       mapping->usbdev->minor, mapping->assign);

				if (uevent_create_device_node(uevent, mapping->container) < 0)
					WARN("Could not create device node");
			}
		}
		for (int i = 0; i < cmld_containers_get_count(); ++i) {
			container_t *c = cmld_container_get_by_index(i);
			// newer versions of udev prepends '/dev/' in DEVNAME
			char *devname =
				mem_printf("%s%s%s", container_get_rootdir(c),
					   strncmp("/dev/", uevent->devname, 4) ? "/dev/" : "",
					   uevent->devname);
			if (container_shift_ids(c, devname, false) < 0)
				ERROR("Failed to fixup uids for '%s' in usernamspace of container %s",
				      devname, container_get_name(c));
			else
				DEBUG("Fixup uids for '%s'", devname);
			mem_free(devname);
		}
		return;
	}
}

static void
uevent_handle(UNUSED int fd, UNUSED unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	struct uevent *uev = mem_new0(struct uevent, 1);

	// read uevent into raw buffer and assure that last char is '\0'
	if ((uev->msg_len = nl_msg_receive_kernel(uevent_netlink_sock, uev->msg.raw,
						  sizeof(uev->msg.raw) - 1, true)) <= 0) {
		WARN("could not read uevent");
		goto err;
	}

	char *raw_p = uev->msg.raw;

	if (memcmp(raw_p, "libudev", 8) == 0) {
		/* udev message needs proper version magic */
		if (uev->msg.nlh.magic != htonl(UDEV_MONITOR_MAGIC)) {
			WARN("unrecognized message signature (%x != %x)", uev->msg.nlh.magic,
			     htonl(UDEV_MONITOR_MAGIC));
			goto err;
		}
		if (uev->msg.nlh.properties_off + 32 > uev->msg_len) {
			WARN("message smaller than expected (%u > %zd)",
			     uev->msg.nlh.properties_off + 32, uev->msg_len);
			goto err;
		}
		raw_p += uev->msg.nlh.properties_off;
		handle_udev_event(uev, raw_p);
	} else if (strchr(raw_p, '@')) {
		/* kernel message */
		TRACE("kernel uevent: %s", raw_p);
		raw_p += strlen(raw_p) + 1;
		handle_kernel_event(uev, raw_p);
	} else {
		/* kernel message */
		TRACE("no uevent: %s", raw_p);
	}
err:
	mem_free(uev);
}

int
uevent_init()
{
	/* find the udevd started by cml's init */
	pid_t udevd_pid = proc_find(1, "udevd");

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

void
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

int
uevent_register_usbdevice(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping =
		uevent_container_dev_mapping_new(container, usbdev);
	uevent_container_dev_mapping_list = list_append(uevent_container_dev_mapping_list, mapping);

	INFO("Registered usbdevice %04x:%04x '%s' [c %d:%d] for container %s",
	     mapping->usbdev->id_vendor, mapping->usbdev->id_product, mapping->usbdev->i_serial,
	     mapping->usbdev->major, mapping->usbdev->minor,
	     container_get_name(mapping->container));

	return 0;
}

int
uevent_unregister_usbdevice(container_t *container, uevent_usbdev_t *usbdev)
{
	uevent_container_dev_mapping_t *mapping_to_remove = NULL;

	for (list_t *l = uevent_container_dev_mapping_list; l; l = l->next) {
		uevent_container_dev_mapping_t *mapping = l->data;
		if ((mapping->container == container) &&
		    (mapping->usbdev->id_vendor == usbdev->id_vendor) &&
		    (mapping->usbdev->id_product == usbdev->id_product) &&
		    (0 == strcmp(mapping->usbdev->i_serial, usbdev->i_serial))) {
			mapping_to_remove = mapping;
		}
	}

	IF_NULL_RETVAL(mapping_to_remove, -1);

	uevent_container_dev_mapping_list =
		list_remove(uevent_container_dev_mapping_list, mapping_to_remove);

	INFO("Unregistered usbdevice %04x:%04x '%s' for container %s",
	     mapping_to_remove->usbdev->id_vendor, mapping_to_remove->usbdev->id_product,
	     mapping_to_remove->usbdev->i_serial, container_get_name(mapping_to_remove->container));

	uevent_container_dev_mapping_free(mapping_to_remove);

	return 0;
}

void
uevent_udev_trigger_coldboot(void)
{
	const char *const argv[] = { "udevadm", "trigger", "--action=add", NULL };
	if (-1 == proc_fork_and_execvp(argv))
		WARN("Could not trigger coldboot uevents!");
}
