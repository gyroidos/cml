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

#include "container.stub.h"

#include "common/uuid.h"
#include "common/mem.h"
#include "common/macro.h"

/**
 * Unit-test stub for container.h.
 */

struct container {
	uuid_t *uuid;
	const char *name;
	const char *config_filename;
	char *imei;
	char *mac_address;
	char *phone_number;
};

container_t *
container_stub_new(char const *container_name)
{
	container_t *container = mem_new0(container_t, 1);
	container->name = mem_strdup(container_name);
	container->config_filename = mem_printf("test_%s.conf", container_name);
	container->uuid = uuid_new(NULL);
	return container;
}

/**
 * Free a container data structure. Does not remove the persistent parts of the container,
 * i.e. the configuration and the images.
 */
void
container_free(container_t *container)
{
	uuid_free(container->uuid);
	mem_free((void *)container->name);
	mem_free((void *)container);
}

/**
 * Returns the name of the container.
 */
const char *
container_get_name(const container_t *container)
{
	ASSERT(container);
	return container->name;
}

/**
 * Returns the name of the container config.
 */
const char *
container_get_config_filename(const container_t *container)
{
	ASSERT(container);
	return container->config_filename;
}

/**
 * Returns the uuid of the container.
 */
const uuid_t *
container_get_uuid(const container_t *container)
{
	ASSERT(container);
	return container->uuid;
}

container_state_t
container_get_state(UNUSED const container_t *container)
{
	return CONTAINER_STATE_STOPPED;
}

pid_t
container_get_pid(UNUSED const container_t *container) {
	return 0;
}

char*
container_get_imei(container_t *container)
{
	ASSERT(container);
	return container->imei;
}

char*
container_get_mac_address(container_t *container)
{
	ASSERT(container);
	return container->mac_address;
}

char*
container_get_phone_number(container_t *container)
{
	ASSERT(container);
	return container->phone_number;
}

void
container_set_radio_ip(container_t *container, char *ip)
{
	ASSERT(container);
	INFO("STUB: c_properties_set_radio_ip(container->prop, ip=%s)", ip);
}

void
container_set_radio_dns(container_t *container, char *dns)
{
	ASSERT(container);
	INFO("STUB: c_properties_set_radio_dns(container->prop, dns=%s)", dns);
}

void
container_set_radio_gateway(container_t *container, char *gateway)
{
	ASSERT(container);
	INFO("STUB: c_properties_set_radio_gateway(container->prop, gateway=%s)", gateway);
}
