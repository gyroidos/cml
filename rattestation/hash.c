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
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "common/macro.h"

#include "hash.h"

int
hash_algo_to_size(hash_algo_t hash_algo)
{
	switch (hash_algo) {
	case HASH_ALGO_SHA1:
		return SHA_DIGEST_LENGTH;
	case HASH_ALGO_SHA256:
		return SHA256_DIGEST_LENGTH;
	default:
		ERROR("Hash algo not supported");
		return -1;
	}
	return -1;
}

hash_algo_t
size_to_hash_algo(int size)
{
	switch (size) {
	case 20:
		return HASH_ALGO_SHA1;
	case 32:
		return HASH_ALGO_SHA256;
	case 48:
		return HASH_ALGO_SHA384;
	default:
		return HASH_ALGO__LAST;
	}
	return HASH_ALGO__LAST;
}

const char *
hash_algo_to_string(hash_algo_t hash_algo)
{
	switch (hash_algo) {
	case HASH_ALGO_SHA1:
		return "sha1";
	case HASH_ALGO_SHA256:
		return "sha256";
	default:
		ERROR("Hash algo not supported");
		return NULL;
	}
	return NULL;
}

void
hash_sha1(uint8_t *digest, uint8_t *data, size_t len)
{
	ASSERT(digest);
	ASSERT(data);

	EVP_MD_CTX *c = EVP_MD_CTX_new();
	EVP_DigestInit(c, EVP_sha1());
	EVP_DigestUpdate(c, data, len);
	EVP_DigestFinal(c, digest, NULL);
	EVP_MD_CTX_free(c);
}

void
hash_sha256(uint8_t *digest, uint8_t *data, size_t len)
{
	ASSERT(digest);
	ASSERT(data);

	EVP_MD_CTX *c = EVP_MD_CTX_new();
	EVP_DigestInit(c, EVP_sha256());
	EVP_DigestUpdate(c, data, len);
	EVP_DigestFinal(c, digest, NULL);
	EVP_MD_CTX_free(c);
}

void
hash_extend(hash_algo_t hash_algo, uint8_t *pcr_value, uint8_t *pcr_extend)
{
	const EVP_MD *md;
	EVP_MD_CTX *c = EVP_MD_CTX_new();

	if (hash_algo == HASH_ALGO_SHA1) {
		md = EVP_sha1();
	} else if (hash_algo == HASH_ALGO_SHA256) {
		md = EVP_sha256();
	} else {
		printf("Error: Hash algo not supported\n");
		goto out;
	}

	EVP_DigestInit(c, md);
	EVP_DigestUpdate(c, pcr_value, hash_algo_to_size(hash_algo));
	EVP_DigestUpdate(c, pcr_extend, hash_algo_to_size(hash_algo));
	EVP_DigestFinal(c, pcr_value, NULL);

out:
	EVP_MD_CTX_free(c);
}
