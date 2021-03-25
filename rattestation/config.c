/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>

#include "config.pb-c.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/protobuf.h"

RAttestationConfig *
rattestation_read_config_new(const char *file)
{
	RAttestationConfig *config = NULL;

	off_t conf_len = 0;
	uint8_t *buf = NULL;
	ASSERT(file);

	DEBUG("Checking if config file %s exists", file);

	IF_FALSE_GOTO(file_exists(file), err);

	DEBUG("File exists");

	size_t file_len = strlen(file);

	IF_TRUE_GOTO(file_len < 5 || strcmp(file + file_len - 5, ".conf"), err);

	conf_len = file_size(file);
	if (conf_len <= 0) {
		WARN("Failed to get file-size of configuration file");
		goto err;
	}

	buf = mem_alloc(conf_len);
	if (-1 == file_read(file, (char *)buf, conf_len)) {
		WARN("Failed to read rattestation configuration file");
		goto err;
	}

	config = (RAttestationConfig *)protobuf_message_new_from_buf(
		buf, conf_len, &rattestation_config__descriptor);

	if (!config) {
		WARN("Failed to load rattestation configuration");
	}

err:
	mem_free(buf);
	return config;
}
