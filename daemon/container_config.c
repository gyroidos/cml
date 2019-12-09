/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

#include "container_config.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/container.pb-c.h"
#else
#include "container.pb-c.h"
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/list.h"
#include "common/protobuf.h"

#include <stdint.h>
#include <inttypes.h>

#include "guestos.h"
#include "guestos_mgr.h"
#include "hardware.h"

struct container_config {
	char *file;

	ContainerConfig *cfg;
};

#define C_CONFIG_MAX_RAM_LIMIT (1 << 30) // TODO 1GB? (< 4GB due to uint32)
#define C_CONFIG_MAX_STORAGE (4LL << 30) // TODO 4GB?

// used to validate config
#define C_CONFIG_FEATURES_LEN 7
static const char *container_config_features[C_CONFIG_FEATURES_LEN] = {
	"generic", "bluetooth", "camera", "gapps", "gps", "telephony", "fhgapps",
};

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
container_type_t
container_config_proto_to_type(ContainerType type)
{
	switch (type) {
	case CONTAINER_TYPE__CONTAINER:
		return CONTAINER_TYPE_CONTAINER;
	case CONTAINER_TYPE__KVM:
		return CONTAINER_TYPE_KVM;
	default:
		FATAL("Unhandled value for ContainerType: %d", type);
	}
}

/******************************************************************************/

#if 0
/**
 * Fill the storage_size array according to the operating system mount table.
 * TODO: This seems to be too complicated, find a better way to provide config options to c_vol.
 */
static void
container_config_storage_size(container_config_t *config)
{
	const guestos_t *os;
	size_t i, n;

	ASSERT(config);

	if (config->storage_size)
		mem_free(config->storage_size);

	os = guestos_get_by_name(container_config_get_guestos(config));
	n = guestos_get_mount_count(os);
	config->storage_size = mem_new0(uint64_t, n);

	// this list must match guestos_get_mounts
	for (i = 0; i < n; i++) {
		const guestos_mount_t *mnt;
		const char *name;

		mnt = guestos_get_mount(os, i);
		name = guestos_mount_get_img(mnt);

		if (!strcmp(name, "data"))
			config->storage_size[i] = 1024;
		else if (!strcmp(name, "cache"))
			config->storage_size[i] = 512;
		else
			config->storage_size[i] = 0;
	}
}
#endif
/******************************************************************************/

container_config_t *
container_config_new(const char *file, const uint8_t *buf, size_t len)
{
	ContainerConfig *ccfg = NULL;

	ASSERT(file);

	if (buf) {
		DEBUG("Loading container config from buf storing to file \"%s\".", file);
		ccfg = (ContainerConfig *)protobuf_message_new_from_buf(buf, len, &container_config__descriptor);
		if (!ccfg)
			WARN("Failed loading container config from buf");
	}
	if (!ccfg) {
		DEBUG("Loading container config from file \"%s\".", file);
		ccfg = (ContainerConfig *)protobuf_message_new_from_textfile(file, &container_config__descriptor);
		if (!ccfg) {
			WARN("Failed loading container config from file \"%s\".", file);
			return NULL;
		}
	}

	container_config_t *config = mem_new0(container_config_t, 1);
	config->file = mem_strdup(file);
	config->cfg = ccfg;
	return config;
}

void
container_config_free(container_config_t *config)
{
	ASSERT(config);
	protobuf_free_message((ProtobufCMessage *)config->cfg);
	mem_free(config->file);
	mem_free(config);
}

int
container_config_write(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	ASSERT(config->file);

	if (protobuf_message_write_to_file(config->file, (ProtobufCMessage *)config->cfg) < 0) {
		WARN("Could not write container config to \"%s\"", config->file);
		return -1;
	}

	return 0;
}

const char *
container_config_get_name(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->name;
}

void
container_config_set_name(container_config_t *config, UNUSED const char *name)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (config->cfg->name)
		mem_free(config->cfg->name);
	config->cfg->name = mem_strdup(name);
}

const char *
container_config_get_guestos(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->guest_os;
}

void
container_config_set_guestos(container_config_t *config, const char *os)
{
	ASSERT(config);
	ASSERT(config->cfg);
	if (config->cfg->guest_os)
		mem_free(config->cfg->guest_os);
	config->cfg->guest_os = mem_strdup(os);
}

unsigned int
container_config_get_ram_limit(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->ram_limit;
}

void
container_config_set_ram_limit(container_config_t *config, unsigned int ram_limit)
{
	ASSERT(config);
	ASSERT(config->cfg);
	// TODO sanity checks for max. number of potatoes, etc.
	if (ram_limit > C_CONFIG_MAX_RAM_LIMIT) {
		WARN("Cannot set ram_limit to %d, maximum is %d.", ram_limit, C_CONFIG_MAX_RAM_LIMIT);
		return;
	}
	config->cfg->ram_limit = ram_limit;
}

void
container_config_fill_mount(const container_config_t *config, mount_t *mnt)
{
	ASSERT(config);
	ASSERT(config->cfg);

	// get size and real image name for each user-generated partition from container config
	ContainerConfig *cfg = config->cfg;
	for (size_t i = 0; i < cfg->n_image_sizes; i++) {
		char *name = cfg->image_sizes[i]->image_name;
		char *file = cfg->image_sizes[i]->image_file;
		ASSERT(name);
		mount_entry_t *mntent = mount_get_entry_by_img(mnt, name);
		if (!mntent) {
			WARN("Unknown mount entry \"%s\" in config for container \"%s\", skipping!", name, cfg->name);
			continue;
		}

		// update alternative image file name if container provides containerspecific image
		// e.g. in guestos mige file name is ids but container should use ids-core
		mount_entry_set_img(mntent, file);

		if ((mount_entry_get_type(mntent) == MOUNT_TYPE_EMPTY) ||
		    (mount_entry_get_type(mntent) == MOUNT_TYPE_OVERLAY_RW)) {
			uint64_t size = cfg->image_sizes[i]->image_size;
			mount_entry_set_size(mntent, size);
		} else {
			ERROR("Forbidden: Cannot override image size for mount entry \"%s\" "
			      "in config for container \"%s\"!",
			      name, cfg->name);
		}
	}
}
#if 0
uint64_t
container_config_get_storage_size(const container_config_t *config)
{
	ASSERT(config && config->cfg);
	return config->cfg->storage_size;
}

void
container_config_set_storage_size(container_config_t *config, uint64_t storage_size)
{
	ASSERT(config);
	ASSERT(config->cfg);
	// TODO sanity checks, etc.
	if (storage_size > C_CONFIG_MAX_STORAGE) {
		WARN("Cannot set storage_size to %llu, maximum is %llu.",
				storage_size, C_CONFIG_MAX_STORAGE);
		return;
	}
	config->cfg->storage_size = storage_size;
}
#endif
uint32_t
container_config_get_color(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->color;
}

void
container_config_set_color(container_config_t *config, uint32_t color)
{
	ASSERT(config);
	ASSERT(config->cfg);
	config->cfg->color = color;
}

container_type_t
container_config_get_type(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return container_config_proto_to_type(config->cfg->type);
}

uint64_t
container_config_get_guestos_version(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->guestos_version;
}

void
container_config_set_guestos_version(container_config_t *config, uint64_t guestos_version)
{
	ASSERT(config);
	ASSERT(config->cfg);
	config->cfg->has_guestos_version = true;
	config->cfg->guestos_version = guestos_version;
}

bool
container_config_get_allow_autostart(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->allow_autostart;
}

void
container_config_set_allow_autostart(container_config_t *config, bool allow_autostart)
{
	ASSERT(config);
	ASSERT(config->cfg);
	config->cfg->allow_autostart = allow_autostart;
}

static bool
container_config_is_valid_feature(const char *feature)
{
	for (size_t i = 0; i < C_CONFIG_FEATURES_LEN; i++) {
		if (strcmp(container_config_features[i], feature) == 0)
			return true;
	}
	return false;
}

list_t *
container_config_get_feature_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *feature_list = NULL;

	for (size_t i = 0; i < config->cfg->n_feature_enabled; i++) {
		if (container_config_is_valid_feature(config->cfg->feature_enabled[i])) {
			feature_list = list_append(feature_list, mem_strdup(config->cfg->feature_enabled[i]));
		}
	}
	return feature_list;
}

list_t *
container_config_get_net_ifaces_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *net_ifaces_list = NULL;
	for (size_t i = 0; i < config->cfg->n_net_ifaces; i++) {
		net_ifaces_list = list_append(net_ifaces_list, mem_strdup(config->cfg->net_ifaces[i]));
	}
	return net_ifaces_list;
}

char **
container_config_get_dev_allow_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	char **dev_whitelist = mem_new0(char *, config->cfg->n_allow_dev + 1);
	for (size_t i = 0; i < config->cfg->n_allow_dev; i++) {
		dev_whitelist[i] = mem_strdup(config->cfg->allow_dev[i]);
	}
	dev_whitelist[config->cfg->n_allow_dev] = NULL;
	return dev_whitelist;
}

char **
container_config_get_dev_assign_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	char **dev_assign_list = mem_new0(char *, config->cfg->n_assign_dev + 1);
	for (size_t i = 0; i < config->cfg->n_assign_dev; i++) {
		dev_assign_list[i] = mem_strdup(config->cfg->assign_dev[i]);
	}
	dev_assign_list[config->cfg->n_assign_dev] = NULL;
	return dev_assign_list;
}

#if 0
bool
container_config_get_autostart(container_config_t *config)
{
	ASSERT(config && config->cfg);
	return !strcmp(config->cfg->name, "a0"); // FIXME
}

void
container_config_set_autostart(container_config_t *config, UNUSED bool autostart)
{
	ASSERT(config && config->cfg);
	ASSERT(0);
	// TODO
}
#endif

const char *
container_config_get_dns_server(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->dns_server;
}

bool
container_config_has_netns(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->netns;
}

void
container_config_append_net_ifaces(const container_config_t *config, const char *iface)
{
	ASSERT(config);
	ASSERT(config->cfg);

	int n = config->cfg->n_net_ifaces++;
	char **old_net_ifaces = config->cfg->net_ifaces;

	config->cfg->net_ifaces = mem_new0(char *, n + 1);

	for (int i = 0; i < n; i++) {
		config->cfg->net_ifaces[i] = mem_strdup(old_net_ifaces[i]);
		mem_free(old_net_ifaces[i]);
	}
	if (n > 0)
		mem_free(old_net_ifaces);

	config->cfg->net_ifaces[n] = mem_strdup(iface);
}

void
container_config_remove_net_ifaces(const container_config_t *config, const char *iface)
{
	ASSERT(config);
	ASSERT(config->cfg);

	int n = config->cfg->n_net_ifaces;
	int nremove = 0;
	char **old_net_ifaces = config->cfg->net_ifaces;

	for (int i = 0; i < n; i++) {
		if (!strcmp(iface, old_net_ifaces[i]))
			nremove++;
	}
	if (nremove == 0)
		return;

	config->cfg->net_ifaces = mem_new0(char *, n - nremove);
	config->cfg->n_net_ifaces = n - nremove;

	for (int i = 0, j = 0; i < n; i++) {
		if (strcmp(iface, old_net_ifaces[i])) {
			config->cfg->net_ifaces[j++] = mem_strdup(old_net_ifaces[i]);
		}
		mem_free(old_net_ifaces[i]);
	}
	mem_free(old_net_ifaces);
}

list_t *
container_config_get_vnet_cfg_list_new(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	list_t *if_cfg_list = NULL;
	for (size_t i = 0; i < config->cfg->n_vnet_configs; ++i) {
		uint8_t mac[6];
		if (config->cfg->vnet_configs[i]->if_mac == NULL) {
			INFO("Generating new mac for if %s", config->cfg->vnet_configs[i]->if_name);
			file_read("/dev/urandom", (char *)mac, 6);
			config->cfg->vnet_configs[i]->if_mac =
				mem_printf("%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8,
					   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		} else {
			INFO("Using mac %s for if %s", config->cfg->vnet_configs[i]->if_mac,
			     config->cfg->vnet_configs[i]->if_name);
			sscanf(config->cfg->vnet_configs[i]->if_mac,
			       "%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8, &mac[0],
			       &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		}
		// sanitize mac veth otherwise kernel may reject the mac
		mac[0] &= 0xfe; /* clear multicast bit */
		mac[0] |= 0x02; /* set local assignment bit (IEEE802) */

		container_vnet_cfg_t *if_cfg = container_vnet_cfg_new(config->cfg->vnet_configs[i]->if_name, NULL, mac,
								      config->cfg->vnet_configs[i]->configure);
		if_cfg_list = list_append(if_cfg_list, if_cfg);
	}

	if (if_cfg_list == NULL) {
		list_t *nw_name_list = hardware_get_nw_name_list();
		for (list_t *l = nw_name_list; l != NULL; l = l->next) {
			char *if_name = l->data;
			uint8_t mac[6];
			file_read("/dev/urandom", (char *)mac, 6);
			mac[0] &= 0xfe; /* clear multicast bit */
			mac[0] |= 0x02; /* set local assignment bit (IEEE802) */
			container_vnet_cfg_t *if_cfg = container_vnet_cfg_new(if_name, NULL, mac, true);
			if_cfg_list = list_append(if_cfg_list, if_cfg);
		}
		list_delete(nw_name_list);
	}
	return if_cfg_list;
}

size_t
container_config_get_init_env_len(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->n_init_env;
}

char **
container_config_get_init_env(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->init_env;
}
