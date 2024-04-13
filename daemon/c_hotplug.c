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
 * @file c_hotplug.c
 *
 * This submodule provides functionality to acct on hotplug events
 * and forward devices according to the container configuration.
 */

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define MOD_NAME "c_hotplug"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/file.h"
#include "common/uuid.h"
#include "common/uevent.h"

#include "container.h"

#include <libgen.h>
#include <sys/sysmacros.h>
#include <unistd.h>

typedef struct c_hotplug {
	container_t *container; // weak reference
	uevent_uev_t *uev;
} c_hotplug_t;

static int
c_hotplug_create_device_node(c_hotplug_t *hotplug, char *path, int major, int minor,
			     const char *devtype)
{
	char *path_dirname = NULL;

	if (file_exists(path)) {
		TRACE("Node '%s' exits, just fixup uids", path);
		goto shift;
	}

	// dirname may modify original string, thus strdup
	path_dirname = mem_strdup(path);
	if (dir_mkdir_p(dirname(path_dirname), 0755) < 0) {
		ERROR("Could not create path for device node");
		goto err;
	}
	dev_t dev = makedev(major, minor);
	mode_t mode = (0 == strcmp(devtype, "disk") || 0 == strcmp(devtype, "partition")) ?
			      S_IFBLK :
			      S_IFCHR;
	INFO("Creating device node (%c %d:%d) in %s", S_ISBLK(mode) ? 'b' : 'c', major, minor,
	     path);
	if (mknod(path, mode, dev) < 0) {
		ERROR_ERRNO("Could not create device node");
		goto err;
	}
shift:
	if (container_shift_ids(hotplug->container, path, path, NULL) < 0) {
		ERROR("Failed to fixup uids for '%s' in usernamspace of container %s", path,
		      container_get_name(hotplug->container));
		goto err;
	}
	mem_free0(path_dirname);
	return 0;
err:
	mem_free0(path_dirname);
	return -1;
}

static int
c_hotplug_usbdev_sysfs_foreach_cb(const char *path, const char *name, void *data)
{
	uint16_t id_product, id_vendor;
	char buf[256];
	int len;
	bool found;
	int dev[2];

	container_usbdev_t *usbdev = data;
	IF_NULL_RETVAL(usbdev, -1);

	found = false;

	char *id_product_file = mem_printf("%s/%s/idProduct", path, name);
	char *id_vendor_file = mem_printf("%s/%s/idVendor", path, name);
	char *i_serial_file = mem_printf("%s/%s/serial", path, name);
	char *dev_file = mem_printf("%s/%s/dev", path, name);

	TRACE("id_product_file: %s", id_product_file);
	TRACE("id_vendor_file: %s", id_vendor_file);
	TRACE("i_serial_file: %s", i_serial_file);

	IF_FALSE_GOTO_TRACE(file_exists(id_product_file), out);
	IF_FALSE_GOTO_TRACE(file_exists(id_vendor_file), out);
	IF_FALSE_GOTO_TRACE(file_exists(dev_file), out);

	len = file_read(id_product_file, buf, sizeof(buf));
	IF_TRUE_GOTO((len < 4), out);
	IF_TRUE_GOTO((sscanf(buf, "%hx", &id_product) < 0), out);
	found = (id_product == container_usbdev_get_id_product(usbdev));
	TRACE("found: %d", found);

	len = file_read(id_vendor_file, buf, sizeof(buf));
	IF_TRUE_GOTO((len < 4), out);
	IF_TRUE_GOTO((sscanf(buf, "%hx", &id_vendor) < 0), out);
	found &= (id_vendor == container_usbdev_get_id_vendor(usbdev));
	TRACE("found: %d", found);

	if (file_exists(i_serial_file)) {
		len = file_read(i_serial_file, buf, sizeof(buf));
		TRACE("%s len=%d", buf, len);
		TRACE("%s len=%zu", container_usbdev_get_i_serial(usbdev),
		      strlen(container_usbdev_get_i_serial(usbdev)));
		found &= (0 == strncmp(buf, container_usbdev_get_i_serial(usbdev),
				       strlen(container_usbdev_get_i_serial(usbdev))));
		TRACE("found: %d", found);
	} else {
		buf[0] = '\0';
	}
	IF_FALSE_GOTO_TRACE(found, out);

	// major = minor = -1;
	dev[0] = dev[1] = -1;
	found = false; // we use this in case of error during file parsing

	len = file_read(dev_file, buf, sizeof(buf));
	IF_TRUE_GOTO(len < 0, out);
	IF_TRUE_GOTO((sscanf(buf, "%d:%d", &dev[0], &dev[1]) < 0), out);
	IF_FALSE_GOTO((dev[0] > -1 && dev[1] > -1), out);

	found = true; // parsing dev_file succeded.

	container_usbdev_set_major(usbdev, dev[0]);
	container_usbdev_set_minor(usbdev, dev[1]);

out:
	mem_free0(id_product_file);
	mem_free0(id_vendor_file);
	mem_free0(i_serial_file);
	mem_free0(dev_file);
	return found ? 1 : 0;
}

static int
c_hotplug_usbdev_set_sysfs_props(container_usbdev_t *usbdev)
{
	ASSERT(usbdev);
	const char *sysfs_path = "/sys/bus/usb/devices";

	// for the first time iterate through sysfs to find device
	if (0 >= dir_foreach(sysfs_path, &c_hotplug_usbdev_sysfs_foreach_cb, usbdev)) {
		WARN("Could not find usb device (%d:%d, %s) in %s!",
		     container_usbdev_get_id_vendor(usbdev),
		     container_usbdev_get_id_product(usbdev), container_usbdev_get_i_serial(usbdev),
		     sysfs_path);
		return -1;
	}

	return 0;
}

struct c_hotplug_token_data {
	container_t *container;
	char *devname;
};

static void
c_hotplug_token_timer_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	struct c_hotplug_token_data *token_data = data;

	static int retries = 10;

	DEBUG("devname: %s", token_data->devname);

	IF_TRUE_GOTO(0 > retries--, out);

	// wait for device node to become available
	IF_TRUE_RETURN(!file_exists(token_data->devname));

	container_token_attach(token_data->container);
	INFO("Processed token attachment of token %s for container %s", token_data->devname,
	     container_get_name(token_data->container));

out:
	mem_free0(token_data->devname);
	mem_free0(token_data);
	event_remove_timer(timer);
	event_timer_free(timer);
}

/*
 * Return true if the calling uevent handler should deny access to the device node
 * during further processing the event.
 */
static bool
c_hotplug_handle_usb_hotplug(unsigned actions, uevent_event_t *event, c_hotplug_t *hotplug)
{
	ASSERT(hotplug);
	ASSERT(event);

	IF_TRUE_RETVAL_TRACE(strncmp(uevent_event_get_subsystem(event), "usb", 3) ||
				     strncmp(uevent_event_get_devtype(event), "usb_device", 10),
			     false);

	if (actions & UEVENT_ACTION_REMOVE) {
		for (list_t *l = container_get_usbdev_list(hotplug->container); l; l = l->next) {
			container_usbdev_t *ud = l->data;
			int major = container_usbdev_get_major(ud);
			int minor = container_usbdev_get_minor(ud);
			container_usbdev_type_t type = container_usbdev_get_type(ud);

			if ((uevent_event_get_major(event) == major) &&
			    (uevent_event_get_minor(event) == minor)) {
				if (CONTAINER_USBDEV_TYPE_TOKEN == type) {
					INFO("HOTPLUG USB TOKEN removed");
					container_token_detach(hotplug->container);
				}
				return true;
			}
		}
	}

	if (actions & UEVENT_ACTION_ADD) {
		TRACE("usb add");

		char *serial_path = mem_printf("/sys/%s/serial", uevent_event_get_devpath(event));
		char *serial = NULL;
		uint16_t vendor_id = uevent_event_get_usb_vendor(event);
		uint16_t product_id = uevent_event_get_usb_product(event);
		int major = uevent_event_get_major(event);
		int minor = uevent_event_get_minor(event);

		if (file_exists(serial_path))
			serial = file_read_new(serial_path, 255);

		mem_free0(serial_path);

		if (!serial || strlen(serial) < 1) {
			TRACE("Failed to read serial of usb device");
			return false;
		}

		if ('\n' == serial[strlen(serial) - 1]) {
			serial[strlen(serial) - 1] = 0;
		}

		for (list_t *l = container_get_usbdev_list(hotplug->container); l; l = l->next) {
			container_usbdev_t *ud = l->data;

			TRACE("check mapping: %04x:%04x '%s' for %s bound device node %d:%d -> container %s",
			      vendor_id, product_id, serial,
			      (container_usbdev_is_assigned(ud)) ? "assign" : "allow",
			      uevent_event_get_major(event), uevent_event_get_minor(event),
			      container_get_name(hotplug->container));

			if ((vendor_id == container_usbdev_get_id_vendor(ud)) &&
			    (product_id == container_usbdev_get_id_product(ud)) &&
			    (0 == strcmp(serial, container_usbdev_get_i_serial(ud)))) {
				container_usbdev_set_major(ud, major);
				container_usbdev_set_minor(ud, minor);
				INFO("%s bound device node %d:%d -> container %s",
				     (container_usbdev_is_assigned(ud)) ? "assign" : "allow", major,
				     minor, container_get_name(hotplug->container));
				if (CONTAINER_USBDEV_TYPE_TOKEN == container_usbdev_get_type(ud)) {
					INFO("HOTPLUG USB TOKEN added");
					struct c_hotplug_token_data *token_data =
						mem_new0(struct c_hotplug_token_data, 1);
					token_data->container = hotplug->container;
					token_data->devname = mem_printf(
						"%s%s",
						strncmp("/dev/", uevent_event_get_devname(event),
							4) ?
							"/dev/" :
							"/",
						uevent_event_get_devname(event));

					// give devfs some time to create device node for token
					event_timer_t *e =
						event_timer_new(100, EVENT_TIMER_REPEAT_FOREVER,
								c_hotplug_token_timer_cb,
								token_data);
					event_add_timer(e);
				}
				container_device_allow(hotplug->container, 'c', major, minor,
						       container_usbdev_is_assigned(ud));
			}
		}
		mem_free0(serial);
	}
	return false;
}

static void
c_hotplug_handle_event_cb(unsigned actions, uevent_event_t *event, void *data)
{
	c_hotplug_t *hotplug = data;
	ASSERT(hotplug);

	uevent_event_t *event_coldboot = NULL;
	char *devname = NULL;
	uuid_t *synth_uuid = NULL;

	bool container_is_up =
		(container_get_state(hotplug->container) == COMPARTMENT_STATE_BOOTING) ||
		(container_get_state(hotplug->container) == COMPARTMENT_STATE_RUNNING) ||
		(container_get_state(hotplug->container) == COMPARTMENT_STATE_STARTING);

	/* handle usb hotplug devices */
	bool hotplugged_do_deny = false;
	if (0 == strncmp(uevent_event_get_subsystem(event), "usb", 3)) {
		// just forward all usb_interface events, as those do not have a major, minor
		IF_TRUE_GOTO(container_is_up && (0 == strncmp(uevent_event_get_devtype(event),
							      "usb_interface", 12)),
			     send);

		hotplugged_do_deny = c_hotplug_handle_usb_hotplug(actions, event, hotplug);
	}

	int major = uevent_event_get_major(event);
	int minor = uevent_event_get_minor(event);
	const char *devtype = uevent_event_get_devtype(event);

	char type = (!strcmp(devtype, "disk") || !strcmp(devtype, "partition")) ? 'b' : 'c';

	if (!container_is_device_allowed(hotplug->container, type, major, minor)) {
		TRACE("skip not allowed device (%c %d:%d) for container %s", type, major, minor,
		      container_get_name(hotplug->container));
		return;
	}

	if (hotplugged_do_deny) {
		container_device_deny(hotplug->container, type, major, minor);
		INFO("Denied access to unbound device node (%c %d:%d)"
		     " mapped in container %s",
		     type, major, minor, container_get_name(hotplug->container));
	}

	// If target container is not running, skip hotplug handling
	IF_FALSE_GOTO(container_is_up, err);

	/* handle coldboot events just for target container */
	synth_uuid = uuid_new(uevent_event_get_synth_uuid(event));
	if (synth_uuid) {
		if (uuid_equals(container_get_uuid(hotplug->container), synth_uuid)) {
			TRACE("Got synth add/remove/change uevent SYNTH_UUID=%s",
			      uuid_string(synth_uuid));
			event_coldboot = uevent_event_replace_synth_uuid_new(event, "0");
			if (!event_coldboot) {
				ERROR("Failed to mask out container uuid from SYNTH_UUID in uevent");
				goto err;
			}
			event = event_coldboot;
			goto send;
		} else {
			TRACE("Skip coldboot event's for other conainer");
			goto err;
		}
	}

	// newer versions of udev prepends '/dev/' in DEVNAME
	devname = mem_printf("%s%s%s", container_get_rootdir(hotplug->container),
			     strncmp("/dev/", uevent_event_get_devname(event), 4) ? "/dev/" : "",
			     uevent_event_get_devname(event));

	if (actions & UEVENT_ACTION_ADD) {
		if (c_hotplug_create_device_node(hotplug, devname, major, minor, devtype) < 0) {
			ERROR("Could not create device node");
			goto err;
		}
	} else if (actions & UEVENT_ACTION_REMOVE) {
		if (unlink(devname) < 0 && errno != ENOENT) {
			WARN_ERRNO("Could not remove device node");
		}
	}

send:
	if (uevent_event_inject_into_netns(event, container_get_pid(hotplug->container),
					   container_has_userns(hotplug->container)) < 0) {
		WARN("Could not inject uevent into netns of container %s!",
		     container_get_name(hotplug->container));
	} else {
		TRACE("Sucessfully injected hotplug into netns of container %s!",
		      container_get_name(hotplug->container));
	}
err:
	if (synth_uuid)
		uuid_free(synth_uuid);
	if (devname)
		mem_free0(devname);
	if (event_coldboot)
		mem_free0(event_coldboot);
}

static void *
c_hotplug_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_hotplug_t *hotplug = mem_new0(c_hotplug_t, 1);
	hotplug->container = compartment_get_extension_data(compartment);

	hotplug->uev =
		uevent_uev_new(UEVENT_UEV_TYPE_KERNEL,
			       UEVENT_ACTION_ADD | UEVENT_ACTION_CHANGE | UEVENT_ACTION_REMOVE |
				       UEVENT_ACTION_BIND | UEVENT_ACTION_UNBIND,
			       c_hotplug_handle_event_cb, hotplug);

	// register hotplug handling for this c_hotplug container submodule
	if (uevent_add_uev(hotplug->uev)) {
		uevent_uev_free(hotplug->uev);
		mem_free0(hotplug);
		return NULL;
	}

	return hotplug;
}

static void
c_hotplug_free(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	uevent_remove_uev(hotplug->uev);
	uevent_uev_free(hotplug->uev);

	mem_free0(hotplug);
}

static bool
c_hotplug_coldboot_dev_filter_cb(int major, int minor, void *data)
{
	c_hotplug_t *hotplug = data;
	ASSERT(hotplug);

	if (container_is_device_allowed(hotplug->container, 'c', major, minor))
		return true;

	if (container_is_device_allowed(hotplug->container, 'b', major, minor))
		return true;

	TRACE("filter coldboot uevent for device (%d:%d)", major, minor);
	return false;
}

static void
c_hotplug_boot_complete_cb(container_t *container, container_callback_t *cb, void *data)
{
	ASSERT(container);
	ASSERT(cb);
	c_hotplug_t *hotplug = data;
	ASSERT(hotplug);

	compartment_state_t state = container_get_state(container);
	if (state == COMPARTMENT_STATE_RUNNING) {
		// fixup device nodes in userns by triggering hotplug forwarding of coldboot events
		if (container_has_userns(hotplug->container)) {
			uevent_udev_trigger_coldboot(container_get_uuid(hotplug->container),
						     c_hotplug_coldboot_dev_filter_cb, hotplug);
		}
		container_unregister_observer(container, cb);
	}
}

static int
c_hotplug_start_post_exec(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	/* register an observer to wait for the container to be running */
	if (!container_register_observer(hotplug->container, &c_hotplug_boot_complete_cb,
					 hotplug)) {
		WARN("Could not register c_hotplug_boot_complete observer callback for %s",
		     container_get_description(hotplug->container));
	}

	return 0;
}

static int
c_hotplug_usbdev_allow(c_hotplug_t *hotplug, container_usbdev_t *usbdev)
{
	ASSERT(hotplug);
	ASSERT(usbdev);
	if (0 != c_hotplug_usbdev_set_sysfs_props(usbdev)) {
		ERROR("Failed to find usbdev in sysfs");
		return -1;
	}

	if (-1 == container_device_allow(hotplug->container, 'c',
					 container_usbdev_get_major(usbdev),
					 container_usbdev_get_minor(usbdev),
					 container_usbdev_is_assigned(usbdev))) {
		WARN("Could not %s char device %d:%d !",
		     container_usbdev_is_assigned(usbdev) ? "assign" : "allow",
		     container_usbdev_get_major(usbdev), container_usbdev_get_minor(usbdev));
		return -1;
	}

	return 0;
}

static int
c_hotplug_coldplug_usbdevs(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	/* initially allow allready plugged usb devices to devices_subsystem */
	for (list_t *l = container_get_usbdev_list(hotplug->container); l; l = l->next) {
		container_usbdev_t *usbdev = l->data;
		// USB devices of type PIN_READER are only required outside the container to enter the pin
		// before the container starts and should not be mapped into the container, as they can
		// be used for multiple containers and a container should not be able to log the pin of
		// another container
		if (container_usbdev_get_type(usbdev) == CONTAINER_USBDEV_TYPE_PIN_ENTRY) {
			TRACE("Device of type pin reader is not mapped into the container");
			continue;
		} else if (container_usbdev_get_type(usbdev) == CONTAINER_USBDEV_TYPE_TOKEN) {
			c_hotplug_usbdev_allow(hotplug, usbdev);
		} else if (container_usbdev_get_type(usbdev) == CONTAINER_USBDEV_TYPE_GENERIC) {
			c_hotplug_usbdev_allow(hotplug, usbdev);
		} else {
			ERROR("Unknown CONTAINER_USBDEV_TYPE. Device has not been configured!");
		}
	}
	return 0;
}

static compartment_module_t c_hotplug_module = {
	.name = MOD_NAME,
	.compartment_new = c_hotplug_new,
	.compartment_free = c_hotplug_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
#ifdef CGROUPS_LEGACY
	.start_post_clone = NULL,
	.start_pre_exec = c_hotplug_coldplug_usbdevs,
#else
	.start_post_clone = c_hotplug_coldplug_usbdevs,
	.start_pre_exec = NULL,
#endif
	.start_post_exec = c_hotplug_start_post_exec,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_hotplug_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_hotplug_module);
}
