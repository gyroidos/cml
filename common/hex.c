/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "macro.h"
#include "mem.h"

int
convert_hex_to_bin(const char *in, size_t inlen, uint8_t *out, size_t outlen)
{
	ASSERT(inlen >= 2);

	char *pos = (char *)in;
	size_t len = inlen;
	if (strncmp("0X", in, 2) == 0) {
		pos += 2;
		len -= 2;
	}
	if ((len % 2) != 0) {
		return -1;
	}
	if (outlen != (len / 2)) {
		return -2;
	}
	for (size_t i = 0; i < outlen; i++) {
		if ((uint8_t)*pos < 0x30 || (uint8_t)*pos > 0x66 ||
		    ((uint8_t)*pos > 0x39 && (uint8_t)*pos < 0x40) ||
		    ((uint8_t)*pos > 0x46 && (uint8_t)*pos < 0x61) ||
		    (uint8_t) * (pos + 1) < 0x30 || (uint8_t) * (pos + 1) > 0x66 ||
		    ((uint8_t) * (pos + 1) > 0x39 && (uint8_t) * (pos + 1) < 0x40) ||
		    ((uint8_t) * (pos + 1) > 0x46 && (uint8_t) * (pos + 1) < 0x61)) {
			return -3;
		}
		sscanf(pos, "%2hhx", &out[i]);
		pos += 2;
	}
	return 0;
}

int
convert_bin_to_hex(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	size_t len = MUL_WITH_OVERFLOW_CHECK(inlen, (size_t)2);
	len = MUL_WITH_OVERFLOW_CHECK(len, sizeof(char));
	len = ADD_WITH_OVERFLOW_CHECK(len, 1);
	if (len > outlen) {
		return -1;
	}

	for (size_t i = 0; i < inlen; ++i) {
		// remember snprintf additionally writes a '0' byte
		snprintf((char *)(out + i * 2), 3, "%.2x", in[i]);
	}

	return 0;
}

char *
convert_bin_to_hex_new(const uint8_t *bin, int len_bytes)
{
	size_t len_hex = MUL_WITH_OVERFLOW_CHECK(len_bytes, (size_t)2);
	len_hex = MUL_WITH_OVERFLOW_CHECK(len_hex, sizeof(char));
	len_hex = ADD_WITH_OVERFLOW_CHECK(len_hex, 1);
	char *hex = mem_alloc0(len_hex);

	for (int i = 0; i < len_bytes; i++) {
		// remember snprintf additionally writes a '0' byte
		snprintf(hex + (i * 2), 3, "%.2x", bin[i]);
	}

	return hex;
}
