/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>

#include "macro.h"
#include "mem.h"

#include "uuid.h"

struct uuid {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;

	/* This field is normally divided in:
	 * uint8_t clock_seq_high_and_reserved;
	 * uint8_t clock_seq_low; */
	uint16_t clock_seq;

	/* This field is only 48 bits in RFC. Here we use
	 * a uint64_t for easier usability. */
	uint64_t node;

	/* The string representation of the UUID */
	char *string;
};

static int
uuid_fill_from_string(uuid_t *uuid, const char *string)
{
	TRACE("Trying to fill UUID from string: %s", string);

	if (strlen(string) != 36) {
		goto error;
	}

	int ret = sscanf(string, "%" SCNx32 "-%" SCNx16 "-%" SCNx16 "-%" SCNx16 "-%" SCNx64,
			 &uuid->time_low, &uuid->time_mid, &uuid->time_hi_and_version,
			 &uuid->clock_seq, &uuid->node);

	TRACE("Parsed %d values from string", ret);

	if (ret != 5) {
		goto error;
	}

	return 0;

error:
	TRACE("Could not parse UUID from string (not a valid UUID string?)");
	return -1;
}

static int
uuid_fill_from_hex_string(uuid_t *uuid, const char *string)
{
	int ret = 0;
	char *str;
	int offset = 0;

	TRACE("Trying to fill UUID from string: %s", string);

	if (strlen(string) < 32) {
		goto error;
	}

	str = mem_strndup(string + offset, 8);
	ret += sscanf(str, "%" SCNx32, &uuid->time_low);
	mem_free(str);
	offset += 8;

	str = mem_strndup(string + offset, 4);
	ret += sscanf(str, "%" SCNx16, &uuid->time_mid);
	mem_free(str);
	offset += 4;

	str = mem_strndup(string + offset, 4);
	ret += sscanf(str, "%" SCNx16, &uuid->time_hi_and_version);
	mem_free(str);
	offset += 4;

	str = mem_strndup(string + offset, 4);
	ret += sscanf(str, "%" SCNx16, &uuid->clock_seq);
	mem_free(str);
	offset += 4;

	str = mem_strndup(string + offset, 12);
	ret += sscanf(str, "%" SCNx64, &uuid->node);
	mem_free0(str);

	TRACE("Parsed %d values from string", ret);

	if (ret != 5) {
		goto error;
	}

	return 0;

error:
	TRACE("Could not parse UUID from hex string '%s' (not a valid hex string?)", string);
	return -1;
}

uuid_t *
uuid_new(char const *uuid)
{
	uuid_t *u = mem_new0(uuid_t, 1);
	u->string = mem_new0(char, 37);

	bool skip_check = false;

	if (!uuid) {
		/* No UUID string provided, generate it randomly */
#ifdef __APPLE__
		DEBUG("Using arc4random to generate random UUID");
		arc4random_buf((void *)&u->time_low, sizeof(u->time_low));
		arc4random_buf((void *)&u->time_mid, sizeof(u->time_mid));
		arc4random_buf((void *)&u->time_hi_and_version, sizeof(u->time_hi_and_version));
		arc4random_buf((void *)&u->clock_seq, sizeof(u->clock_seq));
		arc4random_buf((void *)&u->node, sizeof(u->node));
		/* Make sure the random UUID has the correct format */
		u->time_hi_and_version &= 0x0fff; // Clear version bits
		u->time_hi_and_version |= 0x4000; // Set to version 4 ((pseudo)random UUID)
		u->clock_seq &= 0x3fff;		  // Clear reserved bits
		u->clock_seq |=
			0x8000; // Set reserved bits to 10 indicating UUID conforming to RFC 4122
#else				/* LINUX */
		// get a uuid string from /proc/kernel/random/uuid
		FILE *f = fopen("/proc/sys/kernel/random/uuid", "r");
		if (!f) {
			WARN_ERRNO("Could not open UUID providing file in sys filesystem");
			goto error;
		}
		char buf[37];
		if (!fgets(buf, 37, f)) {
			WARN_ERRNO("Could not read from UUID file in sys filesystem");
			fclose(f);
			goto error;
		}
		fclose(f);
		int ret = uuid_fill_from_string(u, buf);
		if (ret < 0) {
			goto error;
		}
#endif
	} else {
		/* UUID string provided, fill the structure from it */
		int ret = uuid_fill_from_string(u, uuid);
		if (ret < 0) {
			ret = uuid_fill_from_hex_string(u, uuid);
			if (ret < 0) {
				goto error;
			}
			skip_check = true;
		}
	}

	/* generate the UUID string from the filled structure */
	snprintf(u->string, 37,
		 "%08" PRIx32 "-%04" PRIx16 "-%04" PRIx16 "-%04" PRIx16 "-%012" PRIx64, u->time_low,
		 u->time_mid, u->time_hi_and_version, u->clock_seq, u->node);

	/* final check if the input string and the generated string match */
	if (uuid && !skip_check) {
		if (strncasecmp(uuid, u->string, 37)) {
			WARN("%s and %s are not equal! Final check for string equality failed, not generating an UUID",
			     uuid, u->string);
			goto error;
		}
	}

	return u;

error:
	uuid_free(u);
	return NULL;
}

bool
uuid_equals(const uuid_t *uuid1, const uuid_t *uuid2)
{
	IF_NULL_RETVAL(uuid1, false);
	IF_NULL_RETVAL(uuid2, false);

	if (uuid1->time_low == uuid2->time_low && uuid1->time_mid == uuid2->time_mid &&
	    uuid1->time_hi_and_version == uuid2->time_hi_and_version &&
	    uuid1->clock_seq == uuid2->clock_seq && uuid1->node == uuid2->node)
		return true;
	return false;
}

void
uuid_free(uuid_t *uuid)
{
	IF_NULL_RETURN(uuid);

	mem_free0(uuid->string);
	mem_free0(uuid);
}

const char *
uuid_string(const uuid_t *uuid)
{
	IF_NULL_RETVAL(uuid, NULL);
	return uuid->string;
}

uint64_t
uuid_get_node(const uuid_t *uuid)
{
	ASSERT(uuid);

	uint64_t node = 0;

	// 48-bit correspond to 12 hex characters
	if (1 != sscanf(uuid->string + strlen(uuid->string) - 12, "%12" SCNx64, &node)) {
		ERROR_ERRNO("Failed to read node ID");
		DEBUG("Failed to return id");
		return ULLONG_MAX;
	}

	return node;
}
