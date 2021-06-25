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

#include "attestation.pb-c.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common/mem.h"
#include "common/macro.h"

#include "hash.h"

int
container_verify_runtime_measurements(MlContainerEntry **entries, size_t len,
				      hash_algo_t pcr_hash_algo, uint8_t *pcr_tpm)
{
	int hash_size = hash_algo_to_size(pcr_hash_algo);
	IF_FALSE_RETVAL_ERROR(hash_size > 0, -1);

	uint8_t pcr_calculated[hash_size];

	// Static PCRs are initialized with zero's
	memset(pcr_calculated, 0, hash_size);

	for (size_t i = 0; i < len; i++) {
		if (strcmp(entries[i]->template_hash_alg, hash_algo_to_string(pcr_hash_algo))) {
			ERROR("Failed to verify container runtime measurement list: Hash algos do not match");
			return -1;
		}

		INFO("Verifying container %s", entries[i]->filename);

		if (pcr_hash_algo == HASH_ALGO_SHA256) {
			SHA256_CTX c_256;
			SHA256_Init(&c_256);
			SHA256_Update(&c_256, pcr_calculated, SHA256_DIGEST_LENGTH);
			SHA256_Update(&c_256, entries[i]->data_hash.data, SHA256_DIGEST_LENGTH);
			SHA256_Final(pcr_calculated, &c_256);
		} else if (pcr_hash_algo == HASH_ALGO_SHA1) {
			SHA_CTX c;
			SHA1_Init(&c);
			SHA1_Update(&c, pcr_calculated, SHA_DIGEST_LENGTH);
			SHA1_Update(&c, entries[i]->data_hash.data, SHA_DIGEST_LENGTH);
			SHA1_Final(pcr_calculated, &c);
		}
	}

	if (memcmp(pcr_calculated, pcr_tpm, hash_size) != 0) {
		ERROR("Failed to verify the container TPM PCR");
		return -1;
	}

	INFO("Verify container TPM PCR SUCCESSFUL");
	WARN("Verify container signatures not yet implemented");

	return 0;
}