/*
 * This file is part of GyroidOS
 * Copyright(c) 2026 Fraunhofer AISEC
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

#include "tpm2d_common.h"
#include "common/mem.h"
#include "common/macro.h"

char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	size_t len = MUL_WITH_OVERFLOW_CHECK(length, (size_t)2);
	len = MUL_WITH_OVERFLOW_CHECK(len, sizeof(char));
	len = ADD_WITH_OVERFLOW_CHECK(len, 1);
	char *hex = mem_alloc0(len);

	for (int i = 0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex + i * 2, 3, "%.2x", bin[i]);
	}

	return hex;
}

uint8_t *
convert_hex_to_bin_new(const char *hex_str, int *out_length)
{
	int len = strlen(hex_str);
	int i = 0, j = 0;
	*out_length = (len + 1) / 2;

	uint8_t *bin = mem_alloc0(*out_length);

	if (len % 2 == 1) {
		// odd length -> we need to pad
		IF_FALSE_GOTO(sscanf(&(hex_str[0]), "%1hhx", &(bin[0])) == 1, err);
		i = j = 1;
	}

	for (; i < len; i += 2, j++) {
		IF_FALSE_GOTO(sscanf(&(hex_str[i]), "%2hhx", &(bin[j])) == 1, err);
	}

	return bin;
err:
	ERROR("Converstion of hex string to bin failed!");
	mem_free0(bin);
	return NULL;
}
