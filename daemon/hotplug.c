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

#include "hotplug.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "cmld.h"
#include "container.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/network.h"
#include "common/str.h"
#include "common/uevent.h"

typedef struct hotplug_net_dev_mapping {
	container_t *container;
	container_pnet_cfg_t *pnet_cfg;
	uint8_t mac[MAC_ADDR_LEN];
} hotplug_container_netdev_mapping_t;

/**
 * Persistent MAC → original kernel name mapping.
 * Entries are never removed, so the original name survives container
 * assignment/unassignment cycles where the interface may be renamed.
 */
typedef struct {
	uint8_t mac[MAC_ADDR_LEN];
	char *ifname;
} hotplug_netif_name_t;

static list_t *hotplug_known_names_list = NULL;

static hotplug_netif_name_t *
hotplug_netif_name_new(const uint8_t mac[MAC_ADDR_LEN], const char *ifname)
{
	hotplug_netif_name_t *entry = mem_new0(hotplug_netif_name_t, 1);
	memcpy(entry->mac, mac, MAC_ADDR_LEN);
	entry->ifname = mem_strdup(ifname);
	return entry;
}

static void
hotplug_netif_name_free(hotplug_netif_name_t *entry)
{
	IF_NULL_RETURN(entry);
	if (entry->ifname)
		mem_free0(entry->ifname);
	mem_free0(entry);
}

static void
hotplug_register_name(const uint8_t mac[MAC_ADDR_LEN], const char *ifname)
{
	IF_NULL_RETURN(mac);
	IF_NULL_RETURN(ifname);

	// Only store the first name seen for a given MAC
	for (list_t *l = hotplug_known_names_list; l; l = l->next) {
		hotplug_netif_name_t *entry = l->data;
		if (0 == memcmp(mac, entry->mac, MAC_ADDR_LEN))
			return;
	}

	hotplug_netif_name_t *entry = hotplug_netif_name_new(mac, ifname);

	char *mac_str = network_mac_addr_to_str_new(mac);
	DEBUG("Registered persistent name '%s' for MAC %s", ifname, mac_str);
	mem_free0(mac_str);

	hotplug_known_names_list = list_append(hotplug_known_names_list, entry);
}

static const char *
hotplug_get_ifname_by_mac(const uint8_t mac[MAC_ADDR_LEN])
{
	IF_NULL_RETVAL(mac, NULL);

	for (list_t *l = hotplug_known_names_list; l; l = l->next) {
		hotplug_netif_name_t *entry = l->data;
		if (0 == memcmp(mac, entry->mac, MAC_ADDR_LEN))
			return entry->ifname;
	}

	return NULL;
}

static uevent_uev_t *uevent_uev = NULL;

// track net devices mapped to containers
static list_t *hotplug_container_netdev_mapping_list = NULL;

static void
hotplug_container_netdev_mapping_free(hotplug_container_netdev_mapping_t *mapping)
{
	mem_free0(mapping);
}

static hotplug_container_netdev_mapping_t *
hotplug_container_netdev_mapping_new(container_t *container, container_pnet_cfg_t *pnet_cfg)
{
	hotplug_container_netdev_mapping_t *mapping =
		mem_new0(hotplug_container_netdev_mapping_t, 1);
	mapping->container = container;
	mapping->pnet_cfg = pnet_cfg;

	// We only accept mac strings in pnet config for mappings
	if (-1 == network_str_to_mac_addr(pnet_cfg->pnet_name, mapping->mac)) {
		hotplug_container_netdev_mapping_free(mapping);
		return NULL;
	}

	return mapping;
}

static char *
hotplug_replace_devpath_new(const char *str, const char *oldstr, const char *newstr)
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
hotplug_rename_ifi_new(const char *oldname, const char *infix)
{
	static unsigned int cmld_wlan_idx = 0;
	static unsigned int cmld_eth_idx = 0;

	unsigned int *ifi_idx;
	char *newname = NULL;

	/*
	 * Check if this interface has a known name from a previous assignment.
	 * This handles interfaces returning from containers (which may have
	 * renamed them) or from cleanup (which uses cml-prefixed collision names).
	 */
	uint8_t mac[MAC_ADDR_LEN];
	if (network_get_mac_by_ifname(oldname, mac) == 0) {
		const char *known_name = hotplug_get_ifname_by_mac(mac);

		if (known_name) {
			if (!strcmp(oldname, known_name)) {
				DEBUG("Keeping ifname %s", oldname);
				network_remove_all_altnames(oldname);
				return mem_strdup(oldname);
			}

			INFO("Restoring known name %s for %s", known_name, oldname);
			if (network_rename_ifi(oldname, known_name)) {
				ERROR("Failed to restore name %s for %s", known_name, oldname);
				return NULL;
			}

			network_remove_all_altnames(known_name);
			return mem_strdup(known_name);
		}
	}

	// do not rename twice (new interface already with cml prefix)
	if (!strncmp(oldname, "cml", 3)) {
		DEBUG("Keeping ifname %s", oldname);
		network_remove_all_altnames(oldname);
		return mem_strdup(oldname);
	}

	// New interface: assign next sequential cml name
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

	network_remove_all_altnames(newname);
	return newname;
}

static uevent_event_t *
hotplug_rename_interface(const uevent_event_t *event)
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

	new_ifname = hotplug_rename_ifi_new(event_ifname, prefix);

	if (!new_ifname) {
		DEBUG("Failed to prepare renamed uevent member (ifname)");
		goto err;
	}

	// Register the cml-prefixed name as the persistent original name
	uint8_t rename_mac[MAC_ADDR_LEN];
	if (network_get_mac_by_ifname(new_ifname, rename_mac) == 0) {
		hotplug_register_name(rename_mac, new_ifname);
	}

	new_devpath = hotplug_replace_devpath_new(event_devpath, event_ifname, new_ifname);

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

static int
hotplug_netdev_move(uevent_event_t *event)
{
	uint8_t iface_mac[MAC_ADDR_LEN];
	char *macstr = NULL;
	uevent_event_t *newevent = NULL;
	container_pnet_cfg_t *pnet_cfg_c0 = NULL;
	char *event_ifname = uevent_event_get_interface(event);

	if (network_get_mac_by_ifname(event_ifname, iface_mac)) {
		ERROR("Iface '%s' with no mac, skipping!", event_ifname);
		goto error;
	}

	macstr = network_mac_addr_to_str_new(iface_mac);

	container_t *container = NULL;
	container_pnet_cfg_t *pnet_cfg = NULL;
	for (list_t *l = hotplug_container_netdev_mapping_list; l; l = l->next) {
		hotplug_container_netdev_mapping_t *mapping = l->data;
		if (0 == memcmp(iface_mac, mapping->mac, MAC_ADDR_LEN)) {
			container = mapping->container;
			pnet_cfg = mapping->pnet_cfg;
			break;
		}
	}

	// no mapping found move to c0, use MAC string as pnet_name
	// This ways c0's pnet_mv_list stays valid even if c0's OS renames the interface
	if (!container) {
		container = cmld_containers_get_c0();
		pnet_cfg_c0 = container_pnet_cfg_new(macstr, false, NULL);
		pnet_cfg = pnet_cfg_c0;
	}

	// Rename interface before any early-out — ensures returning interfaces
	// get their original name restored even if the target container isn't running yet
	DEBUG("Renaming new interface we were notified about");
	newevent = hotplug_rename_interface(event);

	// uevent pointer is not freed inside this function, therefore we can safely drop it
	if (newevent) {
		DEBUG("using renamed uevent");
		event = newevent;
		event_ifname = uevent_event_get_interface(event);
	} else {
		WARN("failed to rename interface %s. injecting uevent as it is", event_ifname);
	}

	if (!container) {
		WARN("Target container not found, skip moving %s", event_ifname);
		goto error;
	}

	if ((container_get_state(container) != COMPARTMENT_STATE_BOOTING) &&
	    (container_get_state(container) != COMPARTMENT_STATE_RUNNING) &&
	    (container_get_state(container) != COMPARTMENT_STATE_STARTING)) {
		WARN("Target container '%s' is not running, skip moving %s",
		     container_get_description(container), event_ifname);
		goto error;
	}

	macstr = network_mac_addr_to_str_new(iface_mac);
	if (cmld_container_add_net_iface(container, pnet_cfg, false)) {
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
	if (pnet_cfg_c0)
		mem_free0(pnet_cfg_c0);
	mem_free0(macstr);
	return -1;
}

static void
hotplug_sysfs_netif_timer_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);
	uevent_event_t *event = data;

	// if sysfs is not ready in case of wifi just return and retry.
	IF_TRUE_RETURN(!strcmp(uevent_event_get_devtype(event), "wlan") &&
		       !network_interface_is_wifi(uevent_event_get_interface(event)));

	if (hotplug_netdev_move(event) == -1)
		WARN("Did not move net interface!");
	else
		INFO("Moved net interface to target.");

	mem_free0(event);
	event_remove_timer(timer);
	event_timer_free(timer);
}

static void
hotplug_handle_uevent_cb(unsigned actions, uevent_event_t *event, UNUSED void *data)
{
	TRACE("Got new add/remove/change uevent");

	/* move network ifaces to containers */
	if (actions & UEVENT_ACTION_ADD && !strcmp(uevent_event_get_subsystem(event), "net") &&
	    !strstr(uevent_event_get_devpath(event), "virtual")) {
		char *if_name = uevent_event_get_interface(event);

		bool found = false;
		for (list_t *l = hotplug_container_netdev_mapping_list; l; l = l->next) {
			hotplug_container_netdev_mapping_t *mapping = l->data;
			char *registered_if_name = network_get_ifname_by_addr_new(mapping->mac);

			// Interface may be inside a container's netns and not visible
			if (registered_if_name) {
				if (!strcmp(if_name, registered_if_name)) {
					found = true;
					DEBUG("Found a hotplug mapping for netif: %s. Won't add to physical list",
					      registered_if_name);
					mem_free0(registered_if_name);
					break;
				}
				mem_free0(registered_if_name);
			}
		}

		if (!found) {
			// got new physical interface, initially add to cmld tracking list
			uint8_t new_mac[MAC_ADDR_LEN];
			if (network_get_mac_by_ifname(if_name, new_mac) == 0) {
				cmld_netif_phys_add_by_mac(new_mac);
			}
		}

		// give sysfs some time to settle if iface is wifi
		event_timer_t *e =
			event_timer_new(100, EVENT_TIMER_REPEAT_FOREVER,
					hotplug_sysfs_netif_timer_cb, uevent_event_copy_new(event));
		event_add_timer(e);
	}
}

static int
hotplug_trigger_net_uevent_foreach_cb(const char *path, const char *name, UNUSED void *data)
{
	int ret = 0;
	char *uevent_path = mem_printf("%s/%s/uevent", path, name);
	char *driver_path = mem_printf("%s/%s/device/driver", path, name);

	TRACE("checking uevent_path: '%s'", uevent_path);
	if (!file_exists(uevent_path) || !file_exists(driver_path)) {
		goto out;
	}

	// if already in list just do 'nothing' (check by MAC address)
	uint8_t check_mac[MAC_ADDR_LEN];
	if (network_get_mac_by_ifname(name, check_mac) == 0) {
		bool already_tracked = cmld_netif_phys_remove_by_mac(check_mac);
		if (already_tracked) {
			cmld_netif_phys_add_by_mac(check_mac);
			goto out;
		}
	}

	if (-1 == file_printf(uevent_path, "add")) {
		WARN("Could not trigger event %s <- add", uevent_path);
		ret--;
	} else {
		DEBUG("Trigger net event %s <- add", uevent_path);
	}
out:
	mem_free0(uevent_path);
	mem_free0(driver_path);
	return ret;
}

int
hotplug_init()
{
	if (!cmld_is_hostedmode_active()) {
		// Initially rename all physical interfaces before starting uevent handling.
		// The phys list contains MAC byte arrays; resolve to kernel name for rename.
		for (list_t *l = cmld_get_netif_phys_list(); l; l = l->next) {
			uint8_t *mac = l->data;
			char *ifname = network_get_ifname_by_addr_new(mac);
			if (!ifname)
				continue;
			const char *prefix = (network_interface_is_wifi(ifname)) ? "wlan" : "eth";
			char *if_name_new = hotplug_rename_ifi_new(ifname, prefix);
			// Register the cml-prefixed name as the persistent original name
			if (if_name_new) {
				hotplug_register_name(mac, if_name_new);
				mem_free0(if_name_new);
			}
			mem_free0(ifname);
		}
	}

	// Register uevent handler for kernel events
	uevent_uev = uevent_uev_new(UEVENT_UEV_TYPE_KERNEL,
				    UEVENT_ACTION_ADD | UEVENT_ACTION_CHANGE | UEVENT_ACTION_REMOVE,
				    hotplug_handle_uevent_cb, NULL);

	IF_TRUE_RETVAL(uevent_add_uev(uevent_uev), -1);

	if (cmld_is_hostedmode_active())
		return 0;

	const char *sysfs_net = "/sys/class/net";
	// retrigger possibly missed early plugged netdevice through sysfs
	if (0 > dir_foreach(sysfs_net, &hotplug_trigger_net_uevent_foreach_cb, NULL)) {
		WARN("Could not trigger net uevents! No '%s'!", sysfs_net);
	}
	return 0;
}

void
hotplug_cleanup()
{
	IF_NULL_RETURN(uevent_uev);

	uevent_remove_uev(uevent_uev);
	uevent_uev_free(uevent_uev);

	for (list_t *l = hotplug_known_names_list; l; l = l->next) {
		hotplug_netif_name_free(l->data);
	}
	list_delete(hotplug_known_names_list);
}

int
hotplug_register_netdev(container_t *container, container_pnet_cfg_t *pnet_cfg)
{
	hotplug_container_netdev_mapping_t *mapping =
		hotplug_container_netdev_mapping_new(container, pnet_cfg);

	IF_NULL_RETVAL(mapping, -1);

	hotplug_container_netdev_mapping_list =
		list_append(hotplug_container_netdev_mapping_list, mapping);
	char *macstr = network_mac_addr_to_str_new(mapping->mac);

	INFO("Registered netdev '%s' for container %s", macstr,
	     container_get_name(mapping->container));

	mem_free0(macstr);
	return 0;
}

int
hotplug_unregister_netdev(container_t *container, uint8_t mac[MAC_ADDR_LEN])
{
	hotplug_container_netdev_mapping_t *mapping_to_remove = NULL;

	for (list_t *l = hotplug_container_netdev_mapping_list; l; l = l->next) {
		hotplug_container_netdev_mapping_t *mapping = l->data;
		if ((mapping->container == container) &&
		    (0 == memcmp(mapping->mac, mac, MAC_ADDR_LEN))) {
			mapping_to_remove = mapping;
		}
	}

	IF_NULL_RETVAL(mapping_to_remove, -1);

	hotplug_container_netdev_mapping_list =
		list_remove(hotplug_container_netdev_mapping_list, mapping_to_remove);

	char *macstr = network_mac_addr_to_str_new(mapping_to_remove->mac);

	INFO("Unregistered netdev '%s' for container %s", macstr,
	     container_get_name(mapping_to_remove->container));

	hotplug_container_netdev_mapping_free(mapping_to_remove);
	mem_free0(macstr);

	/*
	 * If the NIC is in root ns, add to phys available list synchronously and
	 * trigger a uevent so it gets reassigned (e.g., to c0).
	 * The synchronous add is needed because during config updates, the
	 * replacement container's c_net_start_post_clone may run before the
	 * retriggered uevent is processed by the event loop.
	 */
	char *if_name = network_get_ifname_by_addr_new(mac);
	if (if_name) {
		cmld_netif_phys_add_by_mac(mac);
		char *uevent_path = mem_printf("/sys/class/net/%s/uevent", if_name);
		if (file_exists(uevent_path)) {
			if (-1 == file_printf(uevent_path, "add")) {
				WARN("Could not retrigger uevent for %s", if_name);
			} else {
				DEBUG("Retriggered uevent for unregistered netdev %s", if_name);
			}
		}
		mem_free0(uevent_path);
		mem_free0(if_name);
	}

	return 0;
}
