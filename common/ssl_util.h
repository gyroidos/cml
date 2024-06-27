/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#ifndef P12UTIL_H
#define P12UTIL_H

#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/x509v3.h>

typedef enum { RSA_PSS_PADDING, RSA_SSA_PADDING } rsa_padding_t;

typedef EVP_CIPHER_CTX ssl_aes_ctx_t;

/**
 * reads a pkcs12 softtoken located in the file token_file, unlocked with the password passphrase,
 * whereas the private key is stored in pkey
 * @return returns -1 in case of an incorrect password, -2 for other failures and 0 for successs
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
 * @return returns 0 on success, -1 in case of a failure. */
int
ssl_create_csr(const char *req_file, const char *key_file, const char *passphrase,
	       const char *common_name, const char *uid, bool tpmkey, rsa_padding_t rsa_padding);

/**
 * extracts the uid filed from the cert or csr file
 * The ssl_create_csr() sets an extension similar to:
 *
 * X509v3 Subject Alternative Name:
 *   URI:UUID:83131c82-ec1d-49ff-943b-1af411858dd0
 *
 * This function returns just the UUID value after URI:UUID:
 *
 * @return returns uuid on success, NULL in case of a failure.
 */
char *
ssl_get_uid_from_cert_new(const char *file);

/**
 * This function wraps a (symmetric) key plain_key of length plain_key_len into a wrapped key wrapped_key
 * of length wrapped_key_len using a public key pkey (unwrap works with the corresp. private key).
 * @return returns 0 on success, -1 in case of a failure. */
int
ssl_wrap_key(EVP_PKEY *pkey, const unsigned char *plain_key, size_t plain_key_len,
	     unsigned char **wrapped_key, int *wrapped_key_len);

/**
 * This function unwraps a (symmetric) key wrapped_key of length wrapped_key_len into an unwrapped key
 * plain_key of length plain_key_len using the (private) key pkey.
 * @return returns 0 on success, -1 in case of a failure. */
int
ssl_unwrap_key(EVP_PKEY *pkey, const unsigned char *wrapped_key, size_t wrapped_key_len,
	       unsigned char **plain_key, int *plain_key_len);

/**
 * This function wraps a (symmetric) key plain_key of length plain_key_len into a wrapped key wrapped_key
 * of length wrapped_key_len using a symmetric key wr_key.
 * @return returns 0 on success, -1 in case of a failure. */
int
ssl_wrap_key_sym(const unsigned char *kek, const unsigned char *plain_key, size_t plain_key_len,
		 unsigned char **wrapped_key, int *wrapped_key_len);

/**
 * This function unwraps a (symmetric) key wrapped_key of length wrapped_key_len into an unwrapped key
 * plain_key of length plain_key_len using the symmetric wrapping key wr_key.
 * @return returns 0 on success, -1 in case of a failure. */
int
ssl_unwrap_key_sym(const unsigned char *kek, const unsigned char *wrapped_key,
		   size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len);

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
ssl_verify_signature(const char *cert_file, const char *signature_file, const char *signed_file,
		     const char *digest_algo);

/**
 * verifies a signature stored in sig_buf with a certificate stored in cert_buf. Thereby, the
 * data to be verified located in buf is hashed. Compared to
 * ssl_verify_signature, this method takes buffers instead of filenames.
 * @return Returns 0 on success, -1 if the verification failed and -2 in case of
 * an unexpected verification error.
 */
int
ssl_verify_signature_from_buf(uint8_t *cert_buf, size_t cert_len, const uint8_t *sig_buf,
			      size_t sig_len, const uint8_t *buf, size_t buf_len,
			      const char *digest_algo);

/**
 * verifies a signature stored in sig_buf with a certificate stored in cert_buf. Compared to
 * ssl_verify_from_signature, this function expects the data to be verified already to be hashed.
 * @return Returns 0 on success, -1 if the verification failed and -2 in case of
 * an unexpected verification error.
 */
int
ssl_verify_signature_from_digest(const char *cert_buf, size_t cert_len, const uint8_t *sig_buf,
				 size_t sig_len, const uint8_t *hash, size_t hash_len,
				 const char *digest_algo);

/**
 * The buffer located in buf_to_hash is hashed with the hash algorithm hash_algo.
 * @return The function reveals the hash  as return value and its length via the parameter calc_len.
 * In case of a failure, NULL is returned.
 */
unsigned char *
ssl_hash_buf(const unsigned char *buf_to_hash, unsigned int buf_len, unsigned int *calc_len,
	     const char *digest_algo);

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
ssl_create_pkcs12_token(const char *token_file, const char *cert_file, const char *passphrase,
			const char *user_name, rsa_padding_t rsa_padding);

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
 * @param use_tpm indicates whether the OpenSSL stack should be initialized using
 * the openssl-tpm-engine or not
 * @param tpm2d_primary_storage_key_pw optional tpm2d primary storage key password
 * @return -1 on error, 0 on success
 */
int
ssl_init(bool use_tpm, void *tpm2d_primary_storage_key_pw);

/**
 * Frees internal OpenSSL structurs, run this once ati the end of program
 */
void
ssl_free(void);

/**
 * Takes an ASN1_OBJECT as an input and returns the corresponding hash algorithm
 * as a string, if supported. NOTE: Only for signature algorithms, use
 * builtin openssl functions for digests
 * @param ASN1_OBJECT *obj pointer to an ASN1_OBJECT
 * @return string representation of the hash algorithm
 */
const char *
get_digest_name_by_sig_algo_obj(const ASN1_OBJECT *obj);

/**
 * Takes a plaintext buffer, encrypts it with AES-ECB and writes it to the output buffer.
 * Be careful using ECB mode without further measures!
 *
 * @param in The plaintext buffer to be encrypted
 * @param inlen The length of the plaintext buffer
 * @param out The resulting ciphertext buffer
 * @param outlen The length of the resulting ciphertext buffer
 * @param key The key to use for encryption
 * @param keylen The length of the key
 * @param pad Set to 1 for default PKCS padding, 0 for no padding (in this case, the length
 * 				of the input buffer must be a multiple of the cipher block size)
 * @return int 0 if successful, otherwise -1
 */
int
ssl_aes_ecb_encrypt(uint8_t *in, int inlen, uint8_t *out, int *outlen, uint8_t *key, int keylen,
		    int pad);

/**
 * Takes a ciphertext buffer, decrypts it with AES-ECB and writes it to the output buffer.
 * Be careful using ECB mode without further measures!
 *
 * @param in the ciphertext buffer to be decrypted
 * @param inlen The length of the ciphertext buffer
 * @param out The resulting plaintext buffer
 * @param outlen The length of the plaintext buffer
 * @param key The key to use for decryption
 * @param keylen The length of the key to use
 * @param pad
 * @param pad Set to 1 for default PKCS padding, 0 for no padding (in this case, the length
 * 				of the input buffer must be a multiple of the cipher block size)
 * @return int 0 if successful, otherwise -1
 */
int
ssl_aes_ecb_decrypt(uint8_t *in, int inlen, uint8_t *out, int *outlen, uint8_t *key, int keylen,
		    int pad);

/**
 * Initializes an AES context for encryption with AES-CTR
 *
 * @param key The key to use for encryption
 * @param keylen The length of the key
 * @param iv The IV to use for encryption
 * @param ivlen The length of the IV, must be the block size of the cipher
 * @return ssl_aes_ctx_t Pointer to the newly initialized context in case of success,
 * 			otherwise NULL. The pointer must be freed via ssl_aes_ctr_cree
 */
ssl_aes_ctx_t *
ssl_aes_ctr_init_encrypt(uint8_t *key, int keylen, uint8_t *iv, int ivlen);

/**
 * Initializes an AES context for decryption with AES-CTR
 *
 * @param key The key to use for decryption
 * @param keylen The length of the key
 * @param iv The IV to use for decryption
 * @param ivlen The length of the IV, must be the block size of the cipher
 * @return ssl_aes_ctx_t Pointer to the newly initialized context in case of success,
 * 			otherwise NULL. The pointer must be freed via ssl_aes_ctr_cree
 */
ssl_aes_ctx_t *
ssl_aes_ctr_init_decrypt(uint8_t *key, int keylen, uint8_t *iv, int ivlen);

/**
 * Encrypts an arbitrary length buffer in AES-CTR mode
 *
 * @param ctx The context to be used for encryption, must be initialized
 * 				with ssl_aes_ctr_init_encrypt
 * @param in The plaintext buffer to be encrypted
 * @param inlen The length of the plaintext buffer
 * @param out The resulting ciphertext buffer
 * @param outlen The length of the ciphertext buffer
 * @return int 0 if successful, otherwise -1
 */
int
ssl_aes_ctr_encrypt(ssl_aes_ctx_t *ctx, uint8_t *in, int inlen, uint8_t *out, int *outlen);

/**
 * Decrypts an arbitrary length buffer in AES-CTR mode
 *
 * @param ctx The context to be used for decryption, must be initialized
 * 				with ssl_aes_ctr_init_decrypt
 * @param in The ciphertext buffer to be decrypted
 * @param inlen The length of the ciphertext buffer
 * @param out The resulting plaintext buffer
 * @param outlen The length of the plaintext buffer
 * @return int 0 if successful, otherwise -1
 */
int
ssl_aes_ctr_decrypt(ssl_aes_ctx_t *ctx, uint8_t *in, int inlen, uint8_t *out, int *outlen);

/**
 * Frees an AES context
 *
 * @param ctx The context to be freed
 */
void
ssl_aes_ctr_free(ssl_aes_ctx_t *ctx);

#endif /* P12UTIL_H */
