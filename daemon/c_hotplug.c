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
#include "common/network.h"
#include "common/uuid.h"
#include "common/uevent.h"

#include "container.h"
#include "cmld.h"

#include <libgen.h>
#include <sys/sysmacros.h>
#include <unistd.h>

typedef struct c_hotplug {
	container_t *container; // weak reference
	uevent_uev_t *uev;
} c_hotplug_t;

// all physical network interfaces which are mapped in a container
list_t *c_hotplug_pnet_mapped_list = NULL; // list of type container_pnet_cfg_t *

static int
c_hotplug_create_device_node(c_hotplug_t *hotplug, const char *path, int major, int minor,
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
							5) ?
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

static char *
c_hotplug_replace_devpath_new(const char *str, const char *oldstr, const char *newstr)
{
	char *ptr_old = NULL;
	int len_diff = strlen(newstr) - strlen(oldstr);
	if (!(ptr_old = strstr(str, oldstr))) {
		DEBUG("Could not find %s in %s", oldstr, str);
		return NULL;
	}

	unsigned int off_old;
	char *str_replaced = mem_alloc0((strlen(str) + 1) + len_diff);
	unsigned int pos_new = 0;

	off_old = ptr_old - str;

	strncpy(str_replaced, str, off_old);
	pos_new += off_old;

	strcpy(str_replaced + pos_new, newstr);
	pos_new += strlen(newstr);

	strcpy(str_replaced + pos_new, ptr_old + strlen(oldstr));

	return str_replaced;
}

static char *
c_hotplug_rename_ifi_new(const char *oldname, const char *infix)
{
	static unsigned int cmld_wlan_idx = 0;
	static unsigned int cmld_eth_idx = 0;

	//generate interface name that is unique
	//in the root network namespace
	unsigned int *ifi_idx;
	char *newname = NULL;

	ifi_idx = !strcmp(infix, "wlan") ? &cmld_wlan_idx : &cmld_eth_idx;

	if (-1 == asprintf(&newname, "%s%s%d", "cml", infix, *ifi_idx)) {
		ERROR("Failed to generate new interface name");
		return NULL;
	}

	*ifi_idx += 1;

	INFO("Renaming %s to %s", oldname, newname);

	if (network_rename_ifi(oldname, newname)) {
		ERROR("Failed to rename interface %s", oldname);
		mem_free0(newname);
		return NULL;
	}

	return newname;
}

static uevent_event_t *
c_hotplug_rename_interface(const uevent_event_t *event)
{
	char *event_ifname = uevent_event_get_interface(event);
	char *event_devpath = uevent_event_get_devpath(event);
	const char *prefix = uevent_event_get_devtype(event);

	char *new_ifname = NULL;
	char *new_devpath = NULL;
	uevent_event_t *uev_chname = NULL;
	uevent_event_t *uev_chdevpath = NULL;

	// if no devtype is set in uevent prefix with eth by default
	if (!*prefix)
		prefix = "eth";

	new_ifname = c_hotplug_rename_ifi_new(event_ifname, prefix);

	if (!new_ifname) {
		DEBUG("Failed to prepare renamed uevent member (ifname)");
		goto err;
	}

	new_devpath = c_hotplug_replace_devpath_new(event_devpath, event_ifname, new_ifname);

	if (!new_devpath) {
		DEBUG("Failed to prepare renamed uevent member (devpath)");
		goto err;
	}

	uev_chname = uevent_replace_member(event, event_ifname, new_ifname);

	if (!uev_chname) {
		ERROR("Failed to rename interface name %s in uevent", event_ifname);
		goto err;
	}

	event_devpath = uevent_event_get_devpath(uev_chname);
	uev_chdevpath = uevent_replace_member(uev_chname, event_devpath, new_devpath);

	if (!uev_chdevpath) {
		ERROR("Failed to rename devpath %s in uevent", event_devpath);
		goto err;
	}
	DEBUG("Injected renamed interface name %s, devpath %s into uevent", new_ifname,
	      new_devpath);

	mem_free0(new_ifname);
	mem_free0(new_devpath);
	mem_free0(uev_chname);

	return uev_chdevpath;

err:
	if (new_ifname)
		mem_free0(new_ifname);
	if (new_devpath)
		mem_free0(new_devpath);
	if (uev_chname)
		mem_free0(uev_chname);

	return NULL;
}

int
c_hotplug_netdev_mapped_interfaces_append(container_t *container)
{
	ASSERT(container);

	uint8_t mac[6];

	for (list_t *l = container_get_pnet_cfg_list(container); l; l = l->next) {
		container_pnet_cfg_t *pnet_cfg = l->data;
		char *if_name_macstr = pnet_cfg->pnet_name;
		char *if_name = NULL;
		TRACE("mv_name_list add ifname %s", if_name_macstr);
		mem_memset(&mac, 0, 6);
		// check if string is mac address
		if (0 == network_str_to_mac_addr(if_name_macstr, mac)) {
			TRACE("mv_name_list add if by mac: %s", if_name_macstr);
			// register at c_hotplug subsys
			INFO("Occupy interface for mac '%s' for container %s", if_name_macstr,
			     container_get_name(container));

			if_name = network_get_ifname_by_addr_new(mac);
			if (NULL == if_name) {
				INFO("Interface for mac '%s' is not yet connected.",
				     if_name_macstr);
			}
		} else {
			INFO("Occupy interface by name '%s' for container %s", if_name_macstr,
			     container_get_name(container));
		}

		// Add this pnet to the global list of mapped (occupied) pnets
		if (list_find(c_hotplug_pnet_mapped_list, pnet_cfg)) {
			ERROR("Physical netif with %s %s already taken by another container!",
			      if_name ? "mac" : "name", if_name_macstr);
			mem_free0(if_name);
			return -1;
		}
		c_hotplug_pnet_mapped_list = list_append(c_hotplug_pnet_mapped_list, pnet_cfg);
		mem_free0(if_name);
	}

	return 0;
}

static int
c_hotplug_netdev_move(uevent_event_t *event, container_pnet_cfg_t *pnet_cfg, container_t *container)
{
	ASSERT(event);
	ASSERT(pnet_cfg);
	ASSERT(container);

	uint8_t iface_mac[6];
	char *macstr = NULL;
	uevent_event_t *newevent = NULL;

	char *event_ifname = uevent_event_get_interface(event);

	if (network_get_mac_by_ifname(event_ifname, iface_mac)) {
		ERROR("Iface '%s' with no mac, skipping!", event_ifname);
		goto error;
	}

	// rename network interface to avoid name clashes when moving to container
	DEBUG("Renaming new interface we were notified about");
	newevent = c_hotplug_rename_interface(event);

	// uevent pointer is not freed inside this function, therefore we can safely drop it
	if (newevent) {
		DEBUG("using renamed uevent");
		event = newevent;
		event_ifname = uevent_event_get_interface(event);
		container_pnet_cfg_set_pnet_name(pnet_cfg, event_ifname);
	} else {
		WARN("failed to rename interface %s. injecting uevent as it is", event_ifname);
	}

	macstr = network_mac_addr_to_str_new(iface_mac);
	if (container_add_net_interface(container, pnet_cfg)) {
		ERROR("cannot move '%s' to %s!", macstr, container_get_name(container));
		goto error;
	} else {
		INFO("moved phys network interface '%s' (mac: %s) to %s", event_ifname, macstr,
		     container_get_name(container));
	}

	// if mac_filter is applied we have a bridge interface and do not
	// need to send the uevent about the physical if
	if (pnet_cfg->mac_filter) {
		goto out;
	}

	// if moving was successful also inject uevent
	if (uevent_event_inject_into_netns(event, container_get_pid(container),
					   container_has_userns(container)) < 0) {
		WARN("could not inject uevent into netns of container %s!",
		     container_get_name(container));
	} else {
		TRACE("successfully injected uevent into netns of container %s!",
		      container_get_name(container));
	}
out:
	if (newevent)
		mem_free0(newevent);
	mem_free0(macstr);
	return 0;
error:
	if (newevent)
		mem_free0(newevent);
	mem_free0(macstr);
	return -1;
}

typedef struct c_hotplug_netif_data {
	container_t *container;
	container_pnet_cfg_t *pnet_cfg;
	uevent_event_t *event;
} c_hotplug_netif_data_t;

static c_hotplug_netif_data_t *
c_hotplug_netif_data_new(uevent_event_t *event, container_pnet_cfg_t *pnet_cfg,
			 container_t *container)
{
	ASSERT(event);
	ASSERT(container);

	c_hotplug_netif_data_t *netif_data = mem_new0(c_hotplug_netif_data_t, 1);
	netif_data->event = uevent_event_copy_new(event);
	netif_data->container = container;
	netif_data->pnet_cfg = pnet_cfg;

	return netif_data;
}

static void
c_hotplug_netif_data_free(c_hotplug_netif_data_t *netif_data)
{
	mem_free0(netif_data->event);
	mem_free0(netif_data);
	if (netif_data->pnet_cfg)
		mem_free0(netif_data->pnet_cfg);
}

static void
c_hotplug_sysfs_netif_timer_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	c_hotplug_netif_data_t *cb_data = data;

	// if sysfs is not ready in case of wifi just return and retry.
	IF_TRUE_RETURN(!strcmp(uevent_event_get_devtype(cb_data->event), "wlan") &&
		       !network_interface_is_wifi(uevent_event_get_interface(cb_data->event)));

	if (c_hotplug_netdev_move(cb_data->event, cb_data->pnet_cfg, cb_data->container) == -1)
		WARN("Did not move net interface!");
	else
		INFO("Moved net interface to target.");

	c_hotplug_netif_data_free(cb_data);
	event_remove_timer(timer);
	event_timer_free(timer);
}

/*
 * Return true if the event is handled competly by this function and the calling uevent handler
 * should just return.
 */
static bool
c_hotplug_handle_pnet_hotplug(unsigned actions, uevent_event_t *event, c_hotplug_t *hotplug,
			      bool container_is_up)
{
	ASSERT(hotplug);
	ASSERT(event);

	if (!(actions & UEVENT_ACTION_ADD && !strcmp(uevent_event_get_subsystem(event), "net") &&
	      !strstr(uevent_event_get_devpath(event), "virtual")))
		return false;

	/* move network ifaces to containers */
	uint8_t mac[6];
	uint8_t event_mac[6];
	char *event_ifname = uevent_event_get_interface(event);
	container_pnet_cfg_t *pnet_cfg = NULL;

	if (network_get_mac_by_ifname(event_ifname, event_mac)) {
		ERROR("Iface '%s' with no mac, skipping!", event_ifname);
		return true;
	}

	if (hotplug->container == cmld_containers_get_c0()) {
		for (list_t *l = c_hotplug_pnet_mapped_list; l; l = l->next) {
			container_pnet_cfg_t *container_pnet_cfg = l->data;
			char *if_name_macstr = container_pnet_cfg->pnet_name;
			mem_memset(&mac, 0, 6);
			if ((0 == network_str_to_mac_addr(if_name_macstr, mac)) &&
			    (0 == memcmp(event_mac, mac, 6))) {
				// pnet is occupied by container not moving to c0
				return true;
			}
		}

		// no mapping found move to c0
		pnet_cfg = container_pnet_cfg_new(event_ifname, false, NULL);
	} else {
		for (list_t *l = container_get_pnet_cfg_list(hotplug->container); l; l = l->next) {
			container_pnet_cfg_t *container_pnet_cfg = l->data;
			char *if_name_macstr = container_pnet_cfg->pnet_name;
			mem_memset(&mac, 0, 6);
			if ((0 == network_str_to_mac_addr(if_name_macstr, mac)) &&
			    (0 == memcmp(event_mac, mac, 6))) {
				pnet_cfg =
					container_pnet_cfg_new(container_pnet_cfg->pnet_name,
							       container_pnet_cfg->mac_filter,
							       container_pnet_cfg->mac_whitelist);
				break;
			}
		}
	}

	// no iterface to handle for this container
	IF_NULL_RETVAL(pnet_cfg, true);

	if (!container_is_up) {
		WARN("Target container '%s' is not running, skip moving %s",
		     container_get_description(hotplug->container), event_ifname);
		return true;
	}

	// give sysfs some time to settle if iface is wifi
	c_hotplug_netif_data_t *cb_data =
		c_hotplug_netif_data_new(event, pnet_cfg, hotplug->container);
	event_timer_t *e = event_timer_new(100, EVENT_TIMER_REPEAT_FOREVER,
					   c_hotplug_sysfs_netif_timer_cb, cb_data);
	event_add_timer(e);
	return true;
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

	/* handle pnet hotplug */
	if (c_hotplug_handle_pnet_hotplug(actions, event, hotplug, container_is_up))
		return;

	/* handle usb hotplug devices */
	bool hotplugged_do_deny = false;
	if (0 == strncmp(uevent_event_get_subsystem(event), "usb", 3)) {
		// just forward all usb_interface events, as those do not have a major, minor
		IF_TRUE_GOTO(container_is_up && (0 == strncmp(uevent_event_get_devtype(event),
							      "usb_interface", 13)),
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
			TRACE("Skip coldboot event's for other container");
			goto err;
		}
	}

	// newer versions of udev prepends '/dev/' in DEVNAME
	devname = mem_printf("%s%s%s", container_get_rootdir(hotplug->container),
			     strncmp("/dev/", uevent_event_get_devname(event), 5) ? "/dev/" : "",
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

	// initially register/occupy physical ethernet/wifi interfaces
	IF_TRUE_GOTO_ERROR(-1 == c_hotplug_netdev_mapped_interfaces_append(hotplug->container),
			   err);

	// register hotplug handling for this c_hotplug container submodule
	IF_TRUE_GOTO_ERROR(uevent_add_uev(hotplug->uev), err);

	return hotplug;
err:
	uevent_uev_free(hotplug->uev);
	mem_free0(hotplug);
	return NULL;
}

static void
c_hotplug_free(void *hotplugp)
{
	c_hotplug_t *hotplug = hotplugp;
	ASSERT(hotplug);

	uevent_remove_uev(hotplug->uev);
	uevent_uev_free(hotplug->uev);

	for (list_t *l = c_hotplug_pnet_mapped_list; l;) {
		list_t *next = l->next;
		container_pnet_cfg_t *container_pnet_cfg = l->data;
		if (list_find(container_get_pnet_cfg_list(hotplug->container), container_pnet_cfg))
			c_hotplug_pnet_mapped_list = list_unlink(c_hotplug_pnet_mapped_list, l);

		l = next;
	}

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
