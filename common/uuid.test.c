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

#include <string.h>

#include "uuid.h"

#include "common/macro.h"

int main()
{
	logf_register(&logf_file_write, stdout);

	uuid_t *uuid_rand1 = uuid_new(NULL);
	ASSERT(uuid_rand1);

	uuid_t *uuid_rand2 = uuid_new(NULL);
	ASSERT(uuid_rand2);

	DEBUG("UUID_RAND1: %s", uuid_string(uuid_rand1));
	DEBUG("UUID_RAND2: %s", uuid_string(uuid_rand2));

	char uuid_str[] = "425a83cf-7d22-4561-ac08-20817d94da3b";
	uuid_t *uuid1 = uuid_new(uuid_str);
	ASSERT(uuid1);

	DEBUG("UUID1: %s", uuid_string(uuid1));
	/* Test the uuid_string method */
	ASSERT(!strcmp(uuid_string(uuid1), uuid_str));

	uuid_t *uuid2 = uuid_new("425a83cf-7d22-4561-ac08-20817d94da3b");
	ASSERT(uuid2);
	DEBUG("UUID2: %s", uuid_string(uuid2));

	uuid_t *uuid3 = uuid_new("bd42af59-e003-4426-84ef-d3a9c1dce8fd");
	ASSERT(uuid3);
	DEBUG("UUID3: %s", uuid_string(uuid3));

	uuid_t *uuid4 = uuid_new(uuid_string(uuid3));
	ASSERT(uuid_equals(uuid3, uuid4));
	ASSERT(!strcmp(uuid_string(uuid3), uuid_string(uuid4)));

	uuid_t *uuid_inval1 = uuid_new("this-is-not-a-valid-uuid");
	ASSERT(!uuid_inval1);

	uuid_t *uuid_inval2 = uuid_new("bd42af59-e003-4426-84ef-d3a9c1dce8f");
	ASSERT(!uuid_inval2);

	uuid_t *uuid_inval3 = uuid_new("bd42af59-e003-4426-84ef-d3a9c1dce8fd0");
	ASSERT(!uuid_inval3);

	uuid_t *uuid_inval4 = uuid_new("bd42af59-e003-4426-84ef-d3a9c1dce8fx");
	ASSERT(!uuid_inval4);

	uuid_t *uuid_inval5 = uuid_new("bd42af59-e003-4426-84ef-d3a9c1dce8f-");
	ASSERT(!uuid_inval5);

	uuid_t *uuid_inval6 = uuid_new("bd4-af590e003-442628-ff-d3a9c1dce8f0");
	ASSERT(!uuid_inval6);

	/* Two random UUIDs should never be the same ... */
	ASSERT(!uuid_equals(uuid_rand1, uuid_rand2));

	/* Two UUIDs created from the same UUID string should be equal */
	ASSERT(uuid_equals(uuid1, uuid2));

	/* Two UUIDs created from different strings should be different */
	ASSERT(!uuid_equals(uuid1, uuid3));

	uuid_free(uuid_rand1);
	uuid_free(uuid_rand2);
	uuid_free(uuid1);
	uuid_free(uuid2);
	uuid_free(uuid3);
	uuid_free(uuid4);

	return 0;
}
