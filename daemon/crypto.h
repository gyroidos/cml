/*
 * This file is part of GyroidOS
 * Copyright(c) 2021 Fraunhofer AISEC
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

#ifndef CRYPTO_H
#define CRYPTO_H

#include "stdbool.h"
#include "common/str.h"

/**
 * Choice of supported hash algorithms.
 */
typedef enum crypto_hashalgo { SHA1, SHA256, SHA512 } crypto_hashalgo_t;

/**
 * Callback function for receiving the result of a hash operation. (file)
 */
typedef void (*crypto_hash_callback_t)(const char *hash_string, const char *hash_file,
				       crypto_hashalgo_t hash_algo, void *data);

/**
 * Callback function for receiving the result of a hash operation. (buffer)
 */
typedef void (*crypto_hash_buf_callback_t)(const char *hash_string, const unsigned char *hash_buf,
					   size_t hash_buf_len, crypto_hashalgo_t hash_algo,
					   void *data);

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
crypto_hash_file(const char *file, crypto_hashalgo_t hashalgo, crypto_hash_callback_t cb,
		 void *data);

/**
 * Requests the scd to hash the given buffer and report the hash to the given callback.
 *
 * @param buf the buffer to hash
 * @param buf_len the size of the buffer to hash
 * @param hashalgo the hash algorithm to use
 * @param cb the callback to receive the result
 * @param data custom data parameter to pass to the callback
 * @return 0 if the hash request was sent and the callback is expected to be called, -1 otherwise
 */
int
crypto_hash_buf(const unsigned char *buf, size_t buf_len, crypto_hashalgo_t hashalgo,
		crypto_hash_buf_callback_t cb, void *data);
/**
 * Requests the scd to hash the given file, wait for the result and directly return it.
 *
 * @param file the file to hash
 * @param hashalgo the hash algorithm to use
 * @return pointer to a newly allocated string with the hash value, or NULL on error
 */
char *
crypto_hash_file_block_new(const char *file, crypto_hashalgo_t hashalgo);

/**
 * Result CODE of a signature verification.
 */
typedef enum crypto_verify_result_code {
	VERIFY_GOOD = 0,
	VERIFY_ERROR,
	VERIFY_BAD_SIGNATURE,
	VERIFY_BAD_CERTIFICATE,
	VERIFY_LOCALLY_SIGNED
} crypto_verify_result_code_t;

/**
 * Result of a signature verification.
 * Contains the result code and the path of the CA used for the verification in case of a verification success.
 */
typedef struct crypto_verify_result {
	crypto_verify_result_code_t code;
	str_t *matched_ca;
} crypto_verify_result_t;

/**
 * Callback function for receiving the result of a signature verification (file)
 */
typedef void (*crypto_verify_callback_t)(crypto_verify_result_t verify_result,
					 const char *data_file, const char *sig_file,
					 const char *cert_file, crypto_hashalgo_t hash_algo,
					 void *data);
/**
 * Callback function for receiving the result of a signature verification (buffer)
 */
typedef void (*crypto_verify_buf_callback_t)(crypto_verify_result_t verify_result,
					     unsigned char *data_buf, size_t data_buf_len,
					     unsigned char *sig_buf, size_t sig_buf_len,
					     unsigned char *cert_buf, size_t cert_buf_len,
					     crypto_hashalgo_t hash_algo, void *data);

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
crypto_verify_file(const char *datafile, const char *sigfile, const char *certfile,
		   crypto_hashalgo_t hashalgo, crypto_verify_callback_t cb, void *data);

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
crypto_verify_result_t
crypto_verify_file_block(const char *datafile, const char *sigfile, const char *certfile,
			 crypto_hashalgo_t hashalgo);

/**
 * Requests the scd to verify the signature on the given data buffer using the given certificate
 * and report the result to the given callback.
 *
 * @param data the buffer whose signature shall be verified
 * @param data_len len of the data buffer
 * @param sig with the signature on data
 * @param sig_len len of the signature
 * @param cert buffer containing the certificate (with public key) to verify the signature in sig on data
 * @param cert_len len of the certificate
 * @param hash_algo the hash algorithm to use
 * @param cb the callback to receive the result
 * @param data custom data parameter to pass to the callback
 * @return 0 if the verification request was sent and the callback is expected to be called, -1 otherwise
 */
int
crypto_verify_buf(unsigned char *data_buf, size_t data_buf_len, unsigned char *sig_buf,
		  size_t sig_buf_len, unsigned char *cert_buf, size_t cert_buf_len,
		  crypto_hashalgo_t hashalgo, crypto_verify_buf_callback_t cb, void *data);

/**
 * Requests the scd to verify the signature on the given data buffer using the given certificate,
 * wait for the result and directly return it.
 *
 * @param data_buf the buffer whose signature shall be verified
 * @param data_buf_len len of the data buffer
 * @param sig_buf with the signature on data
 * @param sig_buf_len len of the signature
 * @param cert_buf buffer containing the certificate (with public key) to verify the signature in sig on data
 * @param cert_buf_len len of the certificate
 * @param hash_algo the hash algorithm to use
 * @return the result of the verification
 */
crypto_verify_result_t
crypto_verify_buf_block(unsigned char *data_buf, size_t data_buf_len, unsigned char *sig_buf,
			size_t sig_buf_len, unsigned char *cert_buf, size_t cert_buf_len,
			crypto_hashalgo_t hashalgo);
/**
 * Checks whether the certificate is not null, of sufficient length and
 * of correct PEM format.
 *
 * @param cert_buf buffer which holds the certificate
 * @param cert_buf_len the size of the cert
 * @return true on valid format; false otherwise
 */
bool
crypto_cert_has_valid_format(unsigned char *cert_buf, size_t cert_buf_len);

/**
 * Checks whether two given hashes match and returns the result
 *
 * @param hash_name The name of the hash algorithm used
 * @param hash_len The length if the given hashes
 * @param expected_hash The expected hash
 * @param hash The hash to verify
 * @return true on match; false otherwise
 */
bool
crypto_match_hash(size_t hash_len, const char *expected_hash, const char *hash);

/**
 * Pulls the device CSR from the tokens directory,
 * If a TPM is connected, the corresponding Private Key is stored inside the TPM,
 * otherwise it resides in a softtoken called device.key
 *
 * @param csr_len a pointer in which the size of the csr will be returned
 * @return the csr
 */
uint8_t *
crypto_pull_device_csr_new(size_t *csr_len);

/**
 * Pushes back the certificate (the sigend CSR). Which may
 * be used during ssl client auth, to identify the device in a backend.
 * responses are made to the client socket of corresponding control session.
 * Change the device cert during provisioning.
 * The request is sent asynchronously through lower communication layer.
 *
 * @param resp_fd client fd to control session which should be used for responses
 * @param cert a pointer to the buffer which holds the certificate
 * @param cert_len the size of the cert
 * @return 0 if the request was sent and the callback is expected to be called, -1 otherwise
 */
int
crypto_push_device_cert(int resp_fd, uint8_t *cert, size_t cert_len);

#endif /* CRYPTO_H */
