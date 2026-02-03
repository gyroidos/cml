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

#include "scd.pb-c.h"

#include "crypto.h"
#include "cmld.h"

#include "common/event.h"
#include "common/file.h"
#include "common/hex.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"

#include <unistd.h>

// clang-format off
#ifndef CRYPTO_HWRNG_PATH
#define CRYPTO_HWRNG_PATH "/dev/hwrng"
#endif

#ifndef CRYPTO_RANDOM_PATH
#define CRYPTO_RANDOM_PATH "/dev/random"
#endif

// clang-format on
extern char *scd_sock_path; // defined in scd.c

static TokenToDaemon *
crypto_send_recv_block(const DaemonToToken *out)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET, scd_sock_path);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", scd_sock_path);
		return NULL;
	}

	TRACE("crypto_send_recv_block: connected to sock %d", sock);

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) < 0) {
		ERROR("Failed to send message to scd on sock %d", sock);
		close(sock);
		return NULL;
	}

	TokenToDaemon *msg = NULL;
	msg = (TokenToDaemon *)protobuf_recv_message(sock, &token_to_daemon__descriptor);
	close(sock);
	return msg;
}

bool
crypto_cert_has_valid_format(unsigned char *cert_buf, size_t cert_buf_len)
{
	const char *begin_cert_str = "-----BEGIN CERTIFICATE-----\n";
	const char *end_cert_str = "-----END CERTIFICATE-----\n";
	size_t begin_cert_str_len = strlen(begin_cert_str);
	size_t end_cert_str_len = strlen(end_cert_str);

	if (cert_buf == NULL || cert_buf_len == 0) {
		ERROR("Given certificate is empty.");
		return false;
	}
	if (cert_buf_len < end_cert_str_len + begin_cert_str_len) {
		ERROR("Invalid certificate length %zu.", cert_buf_len);
		return false;
	}
	if (memcmp(cert_buf, begin_cert_str, begin_cert_str_len)) {
		ERROR("Invalid certificate: begin string not found.");
		return false;
	}
	if (memcmp(cert_buf + sizeof(char) * (cert_buf_len - end_cert_str_len), end_cert_str,
		   end_cert_str_len)) {
		ERROR("Invalid certificate: end string not found.");
		return false;
	}
	return true;
}

static HashAlgo
crypto_hashalgo_to_proto(crypto_hashalgo_t hashalgo)
{
	switch (hashalgo) {
	case SHA1:
		return HASH_ALGO__SHA1;
	case SHA256:
		return HASH_ALGO__SHA256;
	case SHA512:
		return HASH_ALGO__SHA512;
	default:
		FATAL("Invalid crypto_hashalgo_t value: %d", hashalgo);
	}
}

static crypto_verify_result_t
crypto_verify_result_from_proto(TokenToDaemon__Code code)
{
	switch (code) {
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
		return VERIFY_GOOD;
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
		return VERIFY_ERROR;
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
		return VERIFY_BAD_SIGNATURE;
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
		return VERIFY_BAD_CERTIFICATE;
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
		return VERIFY_LOCALLY_SIGNED;
	default:
		FATAL("Cannot convert %d to valid crypto_verify_result_t value", code);
	}
}

typedef struct crypto_callback_task {
	crypto_hash_callback_t hash_complete;
	crypto_hash_buf_callback_t hash_buf_complete;
	crypto_verify_callback_t verify_complete;
	crypto_verify_buf_callback_t verify_buf_complete;
	void *data;
	char *hash_file;
	unsigned char *hash_buf;
	size_t hash_buf_len;
	crypto_hashalgo_t hash_algo;
	char *verify_data_file;
	char *verify_sig_file;
	char *verify_cert_file;
	unsigned char *verify_data_buf;
	unsigned char *verify_sig_buf;
	unsigned char *verify_cert_buf;
	size_t verify_data_buf_len;
	size_t verify_sig_buf_len;
	size_t verify_cert_buf_len;
} crypto_callback_task_t;

static crypto_callback_task_t *
crypto_callback_hash_task_new(crypto_hash_callback_t cb, void *data, const char *hash_file,
			      crypto_hashalgo_t hash_algo)
{
	crypto_callback_task_t *task = mem_new0(crypto_callback_task_t, 1);
	task->hash_complete = cb;
	task->data = data;
	task->hash_file = mem_strdup(hash_file);
	task->hash_algo = hash_algo;
	return task;
}

static crypto_callback_task_t *
crypto_callback_hash_buf_task_new(crypto_hash_buf_callback_t cb, void *data,
				  const unsigned char *hash_buf, size_t hash_buf_len,
				  crypto_hashalgo_t hash_algo)
{
	crypto_callback_task_t *task = mem_new0(crypto_callback_task_t, 1);
	task->hash_buf_complete = cb;
	task->data = data;
	task->hash_buf = mem_new0(unsigned char, hash_buf_len);
	memcpy(task->hash_buf, hash_buf, hash_buf_len);
	task->hash_buf_len = hash_buf_len;
	task->hash_algo = hash_algo;
	return task;
}

static crypto_callback_task_t *
crypto_callback_verify_task_new(crypto_verify_callback_t cb, void *data, const char *data_file,
				const char *sig_file, const char *cert_file,
				crypto_hashalgo_t hash_algo)
{
	crypto_callback_task_t *task = mem_new0(crypto_callback_task_t, 1);
	task->verify_complete = cb;
	task->data = data;
	task->hash_algo = hash_algo;
	task->verify_data_file = mem_strdup(data_file);
	task->verify_sig_file = mem_strdup(sig_file);
	task->verify_cert_file = mem_strdup(cert_file);
	return task;
}

static crypto_callback_task_t *
crypto_callback_verify_buf_task_new(crypto_verify_buf_callback_t cb, void *data,
				    const unsigned char *data_buf, size_t data_buf_len,
				    const unsigned char *sig_buf, size_t sig_buf_len,
				    const unsigned char *cert_buf, size_t cert_buf_len,
				    crypto_hashalgo_t hash_algo)
{
	crypto_callback_task_t *task = mem_new0(crypto_callback_task_t, 1);
	task->verify_buf_complete = cb;
	task->data = data;
	task->hash_algo = hash_algo;
	task->verify_data_buf = mem_new0(unsigned char, data_buf_len);
	task->verify_sig_buf = mem_new0(unsigned char, sig_buf_len);
	task->verify_cert_buf = mem_new0(unsigned char, cert_buf_len);
	memcpy(task->verify_data_buf, data_buf, data_buf_len);
	memcpy(task->verify_sig_buf, sig_buf, sig_buf_len);
	memcpy(task->verify_cert_buf, cert_buf, cert_buf_len);
	task->verify_data_buf_len = data_buf_len;
	task->verify_sig_buf_len = sig_buf_len;
	task->verify_cert_buf_len = cert_buf_len;
	return task;
}

static void
crypto_callback_task_free(crypto_callback_task_t *task)
{
	IF_NULL_RETURN(task);
	if (task->hash_file)
		mem_free0(task->hash_file);
	if (task->hash_buf)
		mem_free0(task->hash_buf);
	if (task->verify_data_file)
		mem_free0(task->verify_data_file);
	if (task->verify_sig_file)
		mem_free0(task->verify_sig_file);
	if (task->verify_cert_file)
		mem_free0(task->verify_cert_file);
	if (task->verify_data_buf)
		mem_free0(task->verify_data_buf);
	if (task->verify_sig_buf)
		mem_free0(task->verify_sig_buf);
	if (task->verify_cert_buf)
		mem_free0(task->verify_cert_buf);
	mem_free0(task);
}

static void
crypto_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	crypto_callback_task_t *task = data;
	ASSERT(task);

	TRACE("Received message crypto msg from SCD");

	// TODO outsource socket/fd/events handling
	if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting crypto_cb.");
			goto cleanup;
		}
		switch (msg->code) {
		// deal with CRYPTO_HASH_* cases
		case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK:
			TRACE("Received HASH_OK message, ");
			if (msg->has_hash_value) {
				char *hash = convert_bin_to_hex_new(msg->hash_value.data,
								    msg->hash_value.len);

				TRACE("Received hash for file %s: %s",
				      task->hash_file ? task->hash_file : "<empty>", hash);
				if (task->hash_complete)
					task->hash_complete(hash, task->hash_file, task->hash_algo,
							    task->data);
				if (task->hash_buf_complete)
					task->hash_buf_complete(hash, task->hash_buf,
								task->hash_buf_len, task->hash_algo,
								task->data);
				if (hash != NULL) {
					mem_free0(hash);
				}
				break;
			}
			ERROR("Missing hash_value in CRYPTO_HASH_OK response!"); // fallthrough
		case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR:
			task->hash_complete(NULL, task->hash_file, task->hash_algo, task->data);
			if (task->hash_complete)
				task->hash_complete(NULL, task->hash_file, task->hash_algo,
						    task->data);
			if (task->hash_buf_complete)
				task->hash_buf_complete(NULL, task->hash_buf, task->hash_buf_len,
							task->hash_algo, task->data);
			break;

		// deal with CRYPTO_VERIFY_* cases
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
			if (task->verify_complete) {
				task->verify_complete(crypto_verify_result_from_proto(msg->code),
						      task->verify_data_file, task->verify_sig_file,
						      task->verify_cert_file, task->hash_algo,
						      task->data);
			} else if (task->verify_buf_complete) {
				task->verify_buf_complete(
					crypto_verify_result_from_proto(msg->code),
					task->verify_data_buf, task->verify_data_buf_len,
					task->verify_sig_buf, task->verify_sig_buf_len,
					task->verify_cert_buf, task->verify_cert_buf_len,
					task->hash_algo, task->data);
			}
			break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);
	} else {
		ERROR("Failed to receive message: EVENT_IO_EXCEPT. Aborting crypto_cb");
	}
cleanup:
	event_remove_io(io);
	event_io_free(io);
	crypto_callback_task_free(task);
	close(fd);
}

static void
crypto_generic_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);

	int *resp_fd = data;

	if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting crypto generic callback.");
			goto cleanup;
		}
		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__DEVICE_PROV_ERROR:
			control_send_message(CONTROL_RESPONSE_DEVICE_PROVISIONING_ERROR, *resp_fd);
			break;
		case TOKEN_TO_DAEMON__CODE__DEVICE_CERT_ERROR:
			control_send_message(CONTROL_RESPONSE_DEVICE_CERT_ERROR, *resp_fd);
			break;
		case TOKEN_TO_DAEMON__CODE__DEVICE_CERT_OK:
			control_send_message(CONTROL_RESPONSE_DEVICE_CERT_OK, *resp_fd);
			break;
		case TOKEN_TO_DAEMON__CODE__CMD_UNKNOWN:
			control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, *resp_fd);
			break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);
	} else {
		ERROR("Failed to receive message: EVENT_IO_EXCEPT. Aborting crypto generic cb");
	}
cleanup:
	event_remove_io(io);
	event_io_free(io);
	mem_free0(resp_fd);
	close(fd);
}

static int
crypto_send_msg(const DaemonToToken *out, crypto_callback_task_t *task)
{
	ASSERT(out);
	ASSERT(task);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET | SOCK_NONBLOCK, scd_sock_path);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", scd_sock_path);
		return -1;
	}

	TRACE("crypto_send_msg: connected to sock %d", sock);
	event_io_t *event = event_io_new(sock, EVENT_IO_READ, crypto_cb, task);
	event_add_io(event);

	/*
	char *string = protobuf_c_text_to_string((ProtobufCMessage *) out, NULL);
	if (!string)
		string = mem_printf("%d", out->code);
	DEBUG("crypto_send_msg: sending crypto command {%s}", string);
	mem_free0(string);
	*/

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) < 0) {
		event_remove_io(event);
		event_io_free(event);
		return -1;
	}
	return 0;
}

static int
crypto_generic_send_msg(const DaemonToToken *out, int resp_fd)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET | SOCK_NONBLOCK, scd_sock_path);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s for crypto_generic",
			    scd_sock_path);
		return -1;
	}

	int *fd = mem_new0(int, 1);
	*fd = resp_fd;

	TRACE("crypto_generic_send_msg: connected to sock %d", sock);
	event_io_t *event = event_io_new(sock, EVENT_IO_READ, crypto_generic_cb, fd);
	event_add_io(event);

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) < 0) {
		event_remove_io(event);
		event_io_free(event);
		mem_free0(fd);
		return -1;
	}
	return 0;
}

int
crypto_hash_file(const char *file, crypto_hashalgo_t hashalgo, crypto_hash_callback_t cb,
		 void *data)
{
	ASSERT(file);
	ASSERT(cb);

	crypto_callback_task_t *task = crypto_callback_hash_task_new(cb, data, file, hashalgo);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);
	out.hash_file = task->hash_file;

	TRACE("Requesting scd to hash file at %s", task->hash_file);

	if (crypto_send_msg(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

int
crypto_hash_buf(const unsigned char *buf, size_t buf_len, crypto_hashalgo_t hashalgo,
		crypto_hash_buf_callback_t cb, void *data)
{
	ASSERT(buf);
	ASSERT(cb);

	crypto_callback_task_t *task =
		crypto_callback_hash_buf_task_new(cb, data, buf, buf_len, hashalgo);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_BUF;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);
	out.has_hash_buf = true;
	out.hash_buf.data = task->hash_buf;
	out.hash_buf.len = task->hash_buf_len;

	TRACE("Requesting scd to hash buf of len %zu", task->hash_buf_len);

	if (crypto_send_msg(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

int
crypto_verify_file(const char *datafile, const char *sigfile, const char *certfile,
		   crypto_hashalgo_t hashalgo, crypto_verify_callback_t cb, void *data)
{
	ASSERT(datafile);
	ASSERT(sigfile);
	ASSERT(certfile);
	ASSERT(cb);

	crypto_callback_task_t *task =
		crypto_callback_verify_task_new(cb, data, datafile, sigfile, certfile, hashalgo);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE;
	out.verify_data_file = task->verify_data_file;
	out.verify_sig_file = task->verify_sig_file;
	out.verify_cert_file = task->verify_cert_file;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);

	// disable certificate time check if not yet provisioned
	out.has_verify_ignore_time = true;
	out.verify_ignore_time = !cmld_is_device_provisioned() && !cmld_is_hostedmode_active();

	if (crypto_send_msg(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

int
crypto_verify_buf(unsigned char *data_buf, size_t data_buf_len, unsigned char *sig_buf,
		  size_t sig_buf_len, unsigned char *cert_buf, size_t cert_buf_len,
		  crypto_hashalgo_t hashalgo, crypto_verify_buf_callback_t cb, void *data)
{
	ASSERT(data_buf);
	ASSERT(sig_buf);
	ASSERT(cert_buf);
	ASSERT(cb);

	crypto_callback_task_t *task =
		crypto_callback_verify_buf_task_new(cb, data, data_buf, data_buf_len, sig_buf,
						    sig_buf_len, cert_buf, cert_buf_len, hashalgo);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_BUF;
	out.has_verify_data_buf = true;
	out.verify_data_buf.data = data_buf;
	out.verify_data_buf.len = data_buf_len;
	out.has_verify_sig_buf = true;
	out.verify_sig_buf.data = sig_buf;
	out.verify_sig_buf.len = sig_buf_len;
	out.has_verify_cert_buf = true;
	out.verify_cert_buf.data = cert_buf;
	out.verify_cert_buf.len = cert_buf_len;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);

	// disable certificate time check if not yet provisioned
	out.has_verify_ignore_time = true;
	out.verify_ignore_time = !cmld_is_device_provisioned() && !cmld_is_hostedmode_active();

	if (crypto_send_msg(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

char *
crypto_hash_file_block_new(const char *file, crypto_hashalgo_t hashalgo)
{
	ASSERT(file);
	char *ret = NULL;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);
	out.hash_file = mem_strdup(file);

	TokenToDaemon *msg = crypto_send_recv_block(&out);
	mem_free0(out.hash_file);

	IF_NULL_RETVAL(msg, NULL);

	switch (msg->code) {
	// deal with CRYPTO_HASH_* cases
	case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK:
		if (msg->has_hash_value) {
			ret = convert_bin_to_hex_new(msg->hash_value.data, msg->hash_value.len);
		} else {
			ERROR("Missing hash_value in CRYPTO_HASH_OK response for file %s", file);
		}
		break;
	case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR:
		ERROR("Hashing file %s failed!", file);
		break;
	default:
		ERROR("Invalid TokenToDaemon command %d when hashing file %s", msg->code, file);
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return ret;
}

crypto_verify_result_t
crypto_verify_file_block(const char *datafile, const char *sigfile, const char *certfile,
			 crypto_hashalgo_t hashalgo)
{
	ASSERT(datafile);
	ASSERT(sigfile);
	ASSERT(certfile);

	crypto_verify_result_t ret = VERIFY_ERROR;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE;
	out.verify_data_file = mem_strdup(datafile);
	out.verify_sig_file = mem_strdup(sigfile);
	out.verify_cert_file = mem_strdup(certfile);
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);

	// disable certificate time check if not yet provisioned
	out.has_verify_ignore_time = true;
	out.verify_ignore_time = !cmld_is_device_provisioned() && !cmld_is_hostedmode_active();

	TokenToDaemon *msg = crypto_send_recv_block(&out);
	mem_free0(out.verify_data_file);
	mem_free0(out.verify_sig_file);
	mem_free0(out.verify_cert_file);

	IF_NULL_RETVAL(msg, VERIFY_ERROR);

	switch (msg->code) {
	// deal with CRYPTO_VERIFY_* cases
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
		ret = crypto_verify_result_from_proto(msg->code);
		break;
	default:
		ERROR("Invalid TokenToDaemon command %d when verifying file %s with signature %s and certificate %s",
		      msg->code, datafile, sigfile, certfile);
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return ret;
}

crypto_verify_result_t
crypto_verify_buf_block(unsigned char *data_buf, size_t data_buf_len, unsigned char *sig_buf,
			size_t sig_buf_len, unsigned char *cert_buf, size_t cert_buf_len,
			crypto_hashalgo_t hashalgo)
{
	ASSERT(data_buf);
	ASSERT(sig_buf);
	ASSERT(cert_buf);

	crypto_verify_result_t ret = VERIFY_ERROR;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_BUF;
	out.has_verify_data_buf = true;
	out.verify_data_buf.data = data_buf;
	out.verify_data_buf.len = data_buf_len;
	out.has_verify_sig_buf = true;
	out.verify_sig_buf.data = sig_buf;
	out.verify_sig_buf.len = sig_buf_len;
	out.has_verify_cert_buf = true;
	out.verify_cert_buf.data = cert_buf;
	out.verify_cert_buf.len = cert_buf_len;
	out.has_hash_algo = true;
	out.hash_algo = crypto_hashalgo_to_proto(hashalgo);

	// disable certificate time check if not yet provisioned
	out.has_verify_ignore_time = true;
	out.verify_ignore_time = !cmld_is_device_provisioned() && !cmld_is_hostedmode_active();

	TokenToDaemon *msg = crypto_send_recv_block(&out);
	IF_NULL_RETVAL(msg, VERIFY_ERROR);

	switch (msg->code) {
	// deal with CRYPTO_VERIFY_* cases
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
		ret = crypto_verify_result_from_proto(msg->code);
		break;
	default:
		ERROR("Invalid TokenToDaemon command %d when verifying buffer", msg->code);
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return ret;
}

bool
crypto_match_hash(size_t hash_len, const char *expected_hash, const char *hash)
{
	if (!hash) {
		ERROR("Empty hash value");
		return false;
	}
	if (!expected_hash) {
		ERROR("Reference hash value for image is missing");
		return false;
	}

	//TODO harden against hash algorithms with NULL bytes in digest
	size_t len = strlen(expected_hash);
	if (len != 2 * hash_len) {
		TRACE("Invalid hash length %zu/2, expected %zu/2 bytes", len, 2 * hash_len);
		return false;
	}
	if (strncasecmp(expected_hash, hash, len + 1)) {
		DEBUG("Hash mismatch");
		return false;
	}
	TRACE("Hashes match");
	return true;
}

uint8_t *
crypto_pull_device_csr_new(size_t *csr_len)
{
	ASSERT(csr_len);
	uint8_t *csr = NULL;
	*csr_len = 0;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__PULL_DEVICE_CSR;

	TokenToDaemon *msg = crypto_send_recv_block(&out);
	IF_NULL_RETVAL(msg, NULL);

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__DEVICE_CSR:
		if (msg->has_device_csr) {
			csr = mem_new0(uint8_t, msg->device_csr.len);
			memcpy(csr, msg->device_csr.data, msg->device_csr.len);
			*csr_len = msg->device_csr.len;
		} else {
			ERROR("Missing csr in response to PULL_DEVICE_CSR");
		}
		break;
	case TOKEN_TO_DAEMON__CODE__DEVICE_CSR_ERROR:
		ERROR("Error on reading csr in SCD");
		break;
	case TOKEN_TO_DAEMON__CODE__DEVICE_PROV_ERROR:
		ERROR("Device not in provsioning mode!");
		break;
	default:
		ERROR("Invalid TokenToDaemon command %d when pulling csr!", msg->code);
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return csr;
}

int
crypto_push_device_cert(int resp_fd, uint8_t *cert, size_t cert_len)
{
	if (!crypto_cert_has_valid_format(cert, cert_len)) {
		WARN("PUSH_DEVICE_CERT with invalid certificate");
		goto error;
	}

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__PUSH_DEVICE_CERT;
	out.has_device_cert = true;
	out.device_cert.data = cert;
	out.device_cert.len = cert_len;

	IF_TRUE_GOTO_ERROR(crypto_generic_send_msg(&out, resp_fd) == -1, error);

	return 0;
error:
	control_send_message(CONTROL_RESPONSE_DEVICE_CERT_ERROR, resp_fd);
	return -1;
}

int
crypto_random_get_bytes(unsigned char *buf, size_t len)
{
	const char *rnd = CRYPTO_HWRNG_PATH;
	const char *sw = CRYPTO_RANDOM_PATH;

	int bytes_read = file_read(rnd, (char *)buf, len);
	if (bytes_read > 0 && (size_t)bytes_read == len) {
		return bytes_read;
	} else {
		if (!file_exists(sw)) {
			ERROR("Failed to retrieve random numbers. Neither random number generator %s or %s could be accessed!",
			      rnd, sw);
			return -1;
		}
		WARN("Could not access %s, falling back to %s. Check if device provides a hardware random number generator.",
		     rnd, sw);
		return file_read(sw, (char *)buf, len);
	}
}
