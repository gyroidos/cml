/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2019 Fraunhofer AISEC
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

#include "uevent.h"

#include <arpa/inet.h>
#include <string.h>

#include "cmld.h"
#include "common/event.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/nl.h"
#include "common/proc.h"

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
		}

		/* advance to after the next \0 */
		while (*raw_p++)
			;

		/* check if message ended */
		if (raw_p >= uevent->msg.raw + uevent->msg_len)
			break;
	}

	TRACE("uevent { '%s', '%s', '%s', '%s', %d, %d }", uevent->action, uevent->devpath,
	      uevent->subsystem, uevent->devname, uevent->major, uevent->minor);
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
			}
		}
		return;
	}
}

static void
uevent_handle(UNUSED int fd, UNUSED unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	struct uevent *uev = mem_new0(struct uevent, 1);

	if ((uev->msg_len = nl_msg_receive_kernel(uevent_netlink_sock, uev->msg.raw,
						  sizeof(uev->msg.raw), true)) <= 0) {
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
	} else {
		/* kernel message */
		raw_p += strlen(raw_p) + 1;
		// kernel uvents are redundant
	}

#if 0
	int i=0;
	while(*raw_p || raw_p < uev->msg.raw + uev->msg_len) {
		INFO("uevent_raw[%d] '%s'", i++, raw_p);
		/* advance to after the next \0 */
		while(*raw_p++)
			;
	}
#endif
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
