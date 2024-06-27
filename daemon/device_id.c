/*
 * This file is part of GyroidOS
 * Copyright(c) 2024 Fraunhofer AISEC
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

#include "device_id.h"
#include "device.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"
#include "common/uuid.h"

struct device_id {
	char *file;

	DeviceId *did;
};

/******************************************************************************/

device_id_t *
device_id_new(const char *path)
{
	char *file = NULL;
	DeviceId *did = NULL;

	IF_NULL_RETVAL(path, NULL);

	file = mem_strdup(path);
	DEBUG("Loading device_id from \"%s\".", file);

	did = (DeviceId *)protobuf_message_new_from_textfile(file, &device_id__descriptor);
	if (!did)
		FATAL("Failed loading device_id from file \"%s\". Did scd initially run provisioning?",
		      file);

	device_id_t *device_id = mem_new0(device_id_t, 1);
	device_id->file = file;
	device_id->did = did;
	return device_id;
}

void
device_id_free(device_id_t *device_id)
{
	ASSERT(device_id);
	protobuf_free_message((ProtobufCMessage *)device_id->did);
	mem_free0(device_id->file);
	mem_free0(device_id);
}

const char *
device_id_get_uuid(const device_id_t *device_id)
{
	ASSERT(device_id);
	ASSERT(device_id->did);

	return device_id->did->uuid;
}
