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

#ifndef P12UTIL_H
#define P12UTIL_H

#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

/**
 * reads a pkcs12 softtoken located in the file token_file, unlocked with the password passphrase,
 * whereas the private key is stored in pkey
 * @return returns -1 in case of an incorrect password, -2 for other failures and 0 for success
 */
int
ssl_read_pkcs12_token(const char *token_file, const char *passphrase, EVP_PKEY **pkey, X509 **cert,
		      STACK_OF(X509) * *ca);

/**
 * creates a certificate signing request and stores it in the file req_file.
 * If tpmkey is false, the private key is stored in the file specified by the write-out parameter
 * key_file and encrypted with the passphrase, which has to be a 0 terminated string.
 * If tpmkey is true, key_file is a read-in parameter designating the TPM-encrypted key file
 * that is going to be loaded into the TPM for creating the device key inside the tpm.
 * Setting tpmkey requires to initialize the OpenSSL stack with tpm use, see ssl_init
 * The common name (CN) is included in the certificate request.
 * @return returns 0 on succes, -1 in case of a failure. */
int
ssl_create_csr(const char *req_file, const char *key_file, const char *passphrase, const char *common_name,
	       const char *uid, bool tpmkey);

/**
 * This function wraps a (symmetric) key plain_key of length plain_key_len into a wrapped key wrapped_key
 * of length wrapped_key_len using a public key pkey (unwrap works with the corresp. private key). 
 * @return returns 0 on succes, -1 in case of a failure. */
int
ssl_wrap_key(EVP_PKEY *pkey, const unsigned char *plain_key, size_t plain_key_len, unsigned char **wrapped_key,
	     int *wrapped_key_len);

/**
 * This function unwraps a (symmetric) key wrapped_key of length wrapped_key_len into an unwrapped key
 * plain_key of length plain_key_len using the (private) key pkey.
 * @return returns 0 on succes, -1 in case of a failure. */
int
ssl_unwrap_key(EVP_PKEY *pkey, const unsigned char *wrapped_key, size_t wrapped_key_len, unsigned char **plain_key,
	       int *plain_key_len);

/**
 * this function verifies a certificate located in test_cert_file using
 * the root certificate in root_cert_file.
 * The parameter ignore_time specifies whether the fields notBefore and notAfter should be considered for the
 * verification result or not.
 * @return Returns 0 on success, -1 if the verification failed and -2 in case of
 * an unexpected verification error.
 */
int
ssl_verify_certificate(const char *test_cert_file, const char *root_cert_file, bool ignore_time);

/**
 * verifies a signature stored in signed_file with a certificate stored in cert_file. Thereby, the original
 * file located in signature_file is hashed with the hash algorithm hash_algo.
 * @return Returns 0 on success, -1 if the verification failed and -2 in case of
 * an unexpected verification error.
 */
int
ssl_verify_signature(const char *cert_file, const char *signature_file, const char *signed_file, const char *hash_algo);

/**
 * The file located in file_to_hash is hashed with the hash algorithm hash_algo.
 * @return The function reveals the hash  as return value and its length via the parameter calc_len.
 * In case of a failure, NULL is returned.
 */
unsigned char *
ssl_hash_file(const char *file_to_hash, unsigned int *calc_len, const char *hash_algo);

/**
 * creates a pkcs 12 softtoken located in the file token_file, locked with the password passphrase.
 * The corresponding (currently) self-signed certificate is stored in the file cert_file, if specified
 */
int
ssl_create_pkcs12_token(const char *token_file, const char *cert_file, const char *passphrase, const char *user_name);

/**
 * changes the passwphrase/pin of a pkcs 12 softtoken located in the file token_file,
 * locked with the old password oldpass. If oldpass is correct token will be unlocked,
 * newpass will be set as new password and the token is stored back in file token_file.
 */
int
ssl_newpass_pkcs12_token(const char *token_file, const char *oldpass, const char *newpass);
/**
 * create a self-signed certificate from a CSR
 * csr_file is an existing x509 CSR and cert_file is the desitination file
 * the key file for signing is in key_file.
 * If tpmkey is true, the key_file designates the file that is fed to the TPM for loading the TPM-key
 * used to sign the CSR. Setting tpmkey true requires to initialize the OpenSSL stack with the
 * OpenSSL TPM engine, see ssl_init
 * returns -1 on error, 0 on success
 */
int
ssl_self_sign_csr(const char *csr_file, const char *cert_file, const char *key_file, bool tpmkey);

/**
 * Initializes internal OpenSSL structures
 * use_tpm indicates whether the OpenSSL stack should be initialized using
 * the openssl-tpm-engine or not
 * returns -1 on error, 0 on success
 */
int
ssl_init(bool use_tpm);

/**
 * Frees internal OpenSSL structurs, run this once ati the end of program
 */
void
ssl_free(void);

#endif /* P12UTIL_H */
