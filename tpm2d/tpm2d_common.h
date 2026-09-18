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
#ifndef _TPM2D_COMMON_H
#define _TPM2D_COMMON_H

#include <stddef.h>
#include <stdint.h>

typedef enum tpm2d_key_type {
	TPM2D_KEY_TYPE_STORAGE_U = 1,
	TPM2D_KEY_TYPE_STORAGE_R,
	TPM2D_KEY_TYPE_SIGNING_U,
	TPM2D_KEY_TYPE_SIGNING_R,
	TPM2D_KEY_TYPE_SIGNING_EK
} tpm2d_key_type_t;

/*****************************************************************************/
void
tpm2d_exit(void);

/**
 * Helper function to convert a binary buffer to an hex string
 *
 * This function allocates a new buffer containing the
 * resulting hex representation containing a terminating '\0'
 * of the binary buffer.
 *
 * @param bin binary buffer
 * @param length of the binary buffer
 */
char *
convert_bin_to_hex_new(const uint8_t *bin, int length);

/**
 * Helper function to convert a hex string into binary
 *
 * This function allocates a new buffer containing the
 * resulting binary representation of the string.
 *
 * @param hex_str buffer containing the hex string representation
 * @param out_length in this pointer the size of result is returned
 */
uint8_t *
convert_hex_to_bin_new(const char *hex_str, int *out_length);

#endif
