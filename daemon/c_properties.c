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

#include "c_properties.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include "container.h"

#include <sys/stat.h>


// path defined in bionic, init automatically loads ro. props from there
#define PROP_PATH_FACTORY          "/factory/factory.prop"

struct c_properties {
	const container_t *container;
	char *telephony_name;
};


static int
c_properties_write_prop(const char *prop_name, const char *prop_value)
{
	return file_printf_append(PROP_PATH_FACTORY, "%s=%s\n", prop_name, prop_value);
}

c_properties_t *
c_properties_new(const container_t *container, const char *telephony_name)
{
	c_properties_t *prop = mem_new0(c_properties_t, 1);
	prop->container = container;
	if (telephony_name)
		prop->telephony_name = mem_strdup(telephony_name);
	return prop;
}

void
c_properties_free(c_properties_t *prop)
{
	ASSERT(prop);

	if (prop->telephony_name)
		mem_free(prop->telephony_name);
}

int
c_properties_start_child(c_properties_t *prop)
{
	ASSERT(prop);

	// just to be sure: cleanup old propfile
	if (file_exists(PROP_PATH_FACTORY))
		remove(PROP_PATH_FACTORY);

	// write boot properties to prop file
	if (container_is_privileged(prop->container)) {
		if (c_properties_write_prop("ro.trustme.a0", "1") < 0)
			goto error;
		if (c_properties_write_prop("ro.trustme.telephony.name", prop->telephony_name) < 0) 
			goto error;
		DEBUG("trustme.telephony.name=%s for container %s set.",
				container_get_name(prop->container), prop->telephony_name);
	}

	if (c_properties_write_prop("ro.trustme.wifi.moduleloading",
			container_is_privileged(prop->container) ? "1" : "0" ) < 0)
		goto error;

	if (c_properties_write_prop("ro.trustme.audio.csdclient",
			container_is_privileged(prop->container) ? "true" : "false" ) < 0)
		goto error;

	if (c_properties_write_prop("ro.trustme.telephony",
			container_is_feature_enabled(prop->container, "telephony") ? "1": "0") < 0)
		goto error;

	if (c_properties_write_prop("ro.trustme.fakesignatures", "1") < 0 )
		goto error;

	if (c_properties_write_prop("ro.trustme.customnotification", "0") < 0)
		goto error;

	if (chmod(PROP_PATH_FACTORY, 00644) < 0)
		ERROR_ERRNO("changing of file access rights failed");

	INFO("Property file generated");
	return 0;

error:
	ERROR("Cannot write property file!");
	return -1;
}

void
c_properties_set_telephony_name(c_properties_t *prop, const char* name)
{
	if (prop->telephony_name)
		mem_free(prop->telephony_name);
	prop->telephony_name = mem_strdup(name);
}

