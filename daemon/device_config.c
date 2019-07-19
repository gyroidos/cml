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

#include "device_config.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/device.pb-c.h"
#else
#include "device.pb-c.h"
#endif

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/uuid.h"

struct device_config {
	char *file;

	DeviceConfig *cfg;
};


/******************************************************************************/

device_config_t *
device_config_new(const char *path)
{
	char *file = NULL;
	DeviceConfig *cfg = NULL;
	if (!path) {
		cfg = mem_new(DeviceConfig, 1);
		device_config__init(cfg);
	} else {
		file = mem_strdup(path);
		DEBUG("Loading device config from \"%s\".", file);

		cfg = (DeviceConfig *)
			protobuf_message_new_from_textfile(file, &device_config__descriptor);
		if (!cfg) {
			WARN("Failed loading device config from file \"%s\". Reverting to default values.", file);
			cfg = mem_new(DeviceConfig, 1);
			device_config__init(cfg);
			//TODO: fix. identifiers don't exist anymore
			uuid_t *uuid = uuid_new(NULL);
			cfg->uuid = mem_strdup(uuid_string(uuid));
			uuid_free(uuid);
		}
	}
	ASSERT(cfg);

	device_config_t *config = mem_new0(device_config_t, 1);
	config->file = file;
	config->cfg = cfg;
	return config;
}

void
device_config_free(device_config_t *config)
{
	ASSERT(config);
	protobuf_free_message((ProtobufCMessage *) config->cfg);
	mem_free(config->file);
	mem_free(config);
}

#if 0
int
device_config_write(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);
	ASSERT(config->file);

	if (protobuf_message_write_to_file(config->file, (ProtobufCMessage *) config->cfg) < 0) {
		WARN("Could not write device config to \"%s\"", config->file);
		return -1;
	}

	return 0;
}
#endif

const char *
device_config_get_uuid(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->uuid;
}

const char *
device_config_get_mdm_node(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->mdm_node;
}

const char *
device_config_get_mdm_service(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->mdm_service;
}

const char *
device_config_get_telephony_uuid(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->telephony_uuid;
}

const char *
device_config_get_update_base_url(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->update_base_url;
}

int
device_config_get_should_led_blink(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->should_led_blink;
}

const char *
device_config_get_c0os(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->c0os;
}

const char *
device_config_get_host_addr(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->host_addr;
}

const char *
device_config_get_host_dns(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->host_dns;
}

const char *
device_config_get_host_gateway(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->host_gateway;
}

uint32_t
device_config_get_host_subnet(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->host_subnet;
}

const char *
device_config_get_host_if(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->host_if;
}

bool
device_config_get_locally_signed_images(const device_config_t *config)
{
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->locally_signed_images;
}
