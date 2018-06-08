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

#ifndef SMARTCARD_H
#define SMARTCARD_H

#include "container.h"

typedef struct smartcard smartcard_t;

/**
 * @param path The directory where smartcard-related data is stored.
 */
smartcard_t *
smartcard_new(const char *path);

int
smartcard_container_start_handler(smartcard_t* smartcard, container_t *container,
		const char *passwd);

/// *** CRYPTO *** ///
// FIXME stop the "smartcard" abuse for doing non-smartcard crypto ...

/**
 * Choice of supported hash algorithms.
 */
typedef enum smartcard_crypto_hashalgo {
	SHA1,
	SHA256,
	SHA512
} smartcard_crypto_hashalgo_t;

/**
 * Callback function for receiving the result of a hash operation.
 */
typedef void (*smartcard_crypto_hash_callback_t)(const char *hash_string, const char *hash_file,
		smartcard_crypto_hashalgo_t hash_algo, void *data);

/**
 * Requests the scd to hash the given file and report the hash to the given callback.
 *
 * @param file the file to hash
 * @param hashalgo the hash algorithm to use
 * @param cb the callback to receive the result
 * @param data custom data parameter to pass to the callback
 * @return 0 if the hash request was sent and the callback is expected to be called, -1 otherwise
 */
int
smartcard_crypto_hash_file(const char *file, smartcard_crypto_hashalgo_t hashalgo,
		smartcard_crypto_hash_callback_t cb, void *data);

/**
 * Requests the scd to hash the given file, wait for the result and directly return it.
 *
 * @param file the file to hash
 * @param hashalgo the hash algorithm to use
 * @return pointer to a newly allocated string with the hash value, or NULL on error
 */
char *
smartcard_crypto_hash_file_block_new(const char *file, smartcard_crypto_hashalgo_t hashalgo);


/**
 * Result of a signature verification.
 */
typedef enum smartcard_crypto_verify_result {
	VERIFY_GOOD = 0,
	VERIFY_ERROR,
	VERIFY_BAD_SIGNATURE,
	VERIFY_BAD_CERTIFICATE
} smartcard_crypto_verify_result_t;

/**
 * Callback function for receiving the result of a signature verification.
 */
typedef void (*smartcard_crypto_verify_callback_t)(smartcard_crypto_verify_result_t verify_result,
		const char *data_file, const char *sig_file, const char *cert_file,
		smartcard_crypto_hashalgo_t hash_algo, void *data);

/**
 * Requests the scd to verify the signature on the given datafile using the given certificate
 * and report the result to the given callback.
 *
 * @param datafile the file whose signature shall be verified
 * @param sigfile file with the signature on datafile
 * @param certfile certificate file (with public key) to verify the signature in sigfile on datafile
 * @param hash_algo the hash algorithm to use
 * @param cb the callback to receive the result
 * @param data custom data parameter to pass to the callback
 * @return 0 if the verification request was sent and the callback is expected to be called, -1 otherwise
 */
int
smartcard_crypto_verify_file(const char *datafile, const char *sigfile, const char *certfile,
		smartcard_crypto_hashalgo_t hashalgo, smartcard_crypto_verify_callback_t cb, void *data);

/**
 * Requests the scd to verify the signature on the given datafile using the given certificate,
 * wait for the result and directly return it.
 *
 * @param datafile the file whose signature shall be verified
 * @param sigfile file with the signature on datafile
 * @param certfile certificate file (with public key) to verify the signature in sigfile on datafile
 * @param hash_algo the hash algorithm to use
 * @return the result of the verification
 */
smartcard_crypto_verify_result_t
smartcard_crypto_verify_file_block(const char *datafile, const char *sigfile, const char *certfile,
		smartcard_crypto_hashalgo_t hashalgo);


#endif /* SMARTCARD_H */

