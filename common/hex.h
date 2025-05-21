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

#ifndef HEX_H_
#define HEX_H_

int
convert_hex_to_bin(const char *in, size_t inlen, uint8_t *out, size_t outlen);

int
convert_bin_to_hex(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);

char *
convert_bin_to_hex_new(const uint8_t *bin, int len_bytes);

#endif // HEX_H_
