/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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

/**
 * @file nvmcrypt.h
 *
 * The nvmcrypt module implements the encryption for non-volatile memory
 * using the tpm's nvram as a secure key storage.
 */

#ifndef NVMCRYPT_H
#define NVMCRYPT_H

/**
 * Enum defining the error states of the key generation process
 */
typedef enum nvmcrypt_fde_state {
	FDE_OK = 1,
	FDE_AUTH_FAILED,
	FDE_KEYGEN_FAILED,
	FDE_NO_DEVICE,
	FDE_KEY_ACCESS_LOCKED,
	FDE_UNEXPECTED_ERROR
} nvmcrypt_fde_state_t;

/**
 * Setup an encrypted device mapping for a given block device
 * e.g. /dev/sda using the given password (which can be NULL)
 * will result in a /dev/mapper/sda blockdevice which is then
 * transparently de/encrypted with the stored encryption key in
 * the TPM.
 *
 * This function will check if the encryption key already exist
 * in the TPM's nvram and then use the fde_pw to auroize the
 * read access to the nvindex which contains the encryption key.
 * Otherwise it just creates a new random key, stores it the TPM's
 * nvram and binding the autorization to the given fde_pw.
 *
 *  @param device_path path to the real blockdevice
 *  @param fde_pw password which will authorize the access to the
 *  		real key stored inside an nvindex of the TPM.
 */
nvmcrypt_fde_state_t
nvmcrypt_dm_setup(const char* device_path, const char* fde_pw);

/**
 * This funktion locks the nvm key inside the TPM for further reading
 *
 * Internally the corresponding nvindex is locked. Returns the fdestate
 * after executing the command.
 *
 * @param fde_pw password which will authorize the access to the
 *  		real key stored inside an nvindex of the TPM.
 */
nvmcrypt_fde_state_t
nvmcrypt_dm_lock(const char *fde_pw);

#endif // NVMCRYPT_H
