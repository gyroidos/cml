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

#include "guestos.h"
#include "guestos_mgr.h"

struct container_config {
	char *file;

	ContainerConfig *cfg;
};

#define C_CONFIG_MAX_RAM_LIMIT  (1<<30)     // TODO 1GB? (< 4GB due to uint32)
#define C_CONFIG_MAX_STORAGE    (4LL<<30)   // TODO 4GB?

// used to validate config
#define C_CONFIG_FEATURES_LEN 7
static const char *container_config_features[C_CONFIG_FEATURES_LEN] = {
	"generic",
	"bluetooth",
	"camera",
	"gapps",
	"gps",
	"telephony",
	"fhgapps",
};

/*
 * TODO: replace dummy implementation by protobuf config files
 * For now name AND os are "a0" or "a1" or "a2"
 */

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

// TODO: remove this code! the config should be generated by GUI or MDM
static uint32_t
container_config_get_rand_color(void)
{
	static int i = 0;

	switch (i++ % 5) {
		case 0: return 0x004456ff; // a1 color
		case 1: return 0x550d0dff; // a2 (private) color
		case 2: return 0xffff00ff;
		case 3: return 0x00ffffff;
		case 4: return 0xff00ffff;
		default: ASSERT(0);
	}
}

container_config_t *
container_config_new(const char *file, const char *buf, UNUSED size_t len)
{
	ASSERT(file);
	DEBUG("Loading container config from file \"%s\".", file);

	ContainerConfig *ccfg = (ContainerConfig *)
		protobuf_message_new_from_textfile(file, &container_config__descriptor);
	if (!ccfg) {
		// TODO properly initialize defaults (buf != name/os)
		if (!buf) {
			ERROR("Cannot create default container config instance "
					"without specifying the name.");
			return NULL;
		}

		WARN("Failed loading container config from file \"%s\"."
				" Using default values and given name.", file);
		//static LEDColor led_color = LEDCOLOR__RED;
		ccfg = mem_new(ContainerConfig, 1);
		container_config__init(ccfg);
		ccfg->name = mem_strdup(buf);       // FIXME
		ccfg->guest_os = "axos";   // FIXME
		ccfg->color = container_config_get_rand_color();//led_color++;      // FIXME
		ccfg->guestos_version = 0;      // FIXME
		//if (led_color > LEDCOLOR__YELLOW) {
		//	WARN("Running out of LED colors. Going back to RED.");
		//	led_color = LEDCOLOR__RED;
		//}
		//config->max_ram = 1024; // use default from .proto definition
		//config->storage_size = 100; // use default from .proto definition
	}
	ASSERT(ccfg);

	/* Upgrade code, to be removed when all devices are running axos containers only */
	if (!strcmp(ccfg->guest_os, "a1os")) {
		mem_free(ccfg->guest_os);
		ccfg->guest_os = mem_printf("%s","axos");
		ccfg->guestos_version = guestos_get_version(guestos_mgr_get_latest_by_name("axos", true));
		ccfg->n_feature_enabled = 1;
		ccfg->feature_enabled = mem_new0(char*, 1);
		/* enable fhgapps for "a1" */
		ccfg->feature_enabled[0] = mem_strdup(container_config_features[C_CONFIG_FEATURES_LEN-1]);
		INFO("%s: enable feature %s", ccfg->name, ccfg->feature_enabled[0]);
		INFO("Upgraded a1os container to axos");
	}
	if (!strcmp(ccfg->guest_os, "a2os")) {
		mem_free(ccfg->guest_os);
		ccfg->guest_os = mem_printf("%s","axos");
		ccfg->guestos_version = guestos_get_version(guestos_mgr_get_latest_by_name("axos", true));
		/* enable all other features for "a2" execpt generic */
		ccfg->n_feature_enabled = C_CONFIG_FEATURES_LEN-2;
		ccfg->feature_enabled = mem_new0(char*, C_CONFIG_FEATURES_LEN-2);
		for (size_t i = 0; i < C_CONFIG_FEATURES_LEN-2; i++) {
			ccfg->feature_enabled[i] = mem_strdup(container_config_features[i+1]);
			INFO("%s: enable feature %s", ccfg->name, ccfg->feature_enabled[i]);
		}
		INFO("Upgraded a2os container to axos");
	}
	/* end */

	container_config_t *config = mem_new0(container_config_t, 1);
	config->file = mem_strdup(file);
	config->cfg = ccfg;
	return config;
}

void
container_config_free(container_config_t *config)
{
	ASSERT(config);
	protobuf_free_message((ProtobufCMessage *) config->cfg);
	mem_free(config->file);
	mem_free(config);
}

int
container_config_write(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	ASSERT(config->file);

	if (protobuf_message_write_to_file(config->file, (ProtobufCMessage *) config->cfg) < 0) {
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
		WARN("Cannot set ram_limit to %d, maximum is %d.",
				ram_limit, C_CONFIG_MAX_RAM_LIMIT);
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
			WARN("Unknown mount entry \"%s\" in config for container \"%s\", skipping!",
					name, cfg->name);
			continue;
		}

		// update alternative image file name if container provides containerspecific image
		// e.g. in guestos mige file name is ids but container should use ids-core
		mount_entry_set_img(mntent, file);

		if (mount_entry_get_type(mntent) == MOUNT_TYPE_EMPTY) {
			uint64_t size = cfg->image_sizes[i]->image_size;
			mount_entry_set_size(mntent, size);
		}
		else {
			ERROR("Forbidden: Cannot override image size for mount entry \"%s\" "
					"in config for container \"%s\"!", name, cfg->name);
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
container_config_get_allow_container_switch(const container_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	return config->cfg->allow_container_switch;
}

void
container_config_set_allow_container_switch(container_config_t *config, bool allow_container_switch)
{
	ASSERT(config);
	ASSERT(config->cfg);
	config->cfg->allow_container_switch = allow_container_switch;
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
