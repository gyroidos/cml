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

#include "smartcard.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/scd.pb-c.h"
#else
#include "scd.pb-c.h"
#endif

#include "cmld.h"
#include "hardware.h"
#include "control.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/protobuf.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// clang-format off
#define SCD_CONTROL_SOCKET SOCK_PATH(scd-control)
// clang-format on

// TODO: centrally define key length in container or other module?
#define TOKEN_KEY_LEN 64
#define TOKEN_MAX_WRAPPED_KEY_LEN 4096

struct smartcard {
	int sock;
	char *path;
};

typedef struct smartcard_startdata {
	smartcard_t *smartcard;
	container_t *container;
	control_t *control;
} smartcard_startdata_t;

static char *
bytes_to_string_new(unsigned char *data, size_t len)
{
	IF_NULL_RETVAL(data, NULL);
	char *str = mem_alloc(2 * len + 1);
	for (size_t i = 0; i < len; i++)
		snprintf(str + 2 * i, 3, "%02x", data[i]);
	return str;
}

static void
smartcard_start_container_internal(smartcard_startdata_t *startdata, unsigned char *key, int keylen)
{
	int resp_fd = control_get_client_sock(startdata->control);
	// backward compatibility: convert binary key to ascii (to have it converted back later)
	char *ascii_key = bytes_to_string_new(key, keylen);
	//DEBUG("SCD: Container key (len=%d): %s", keylen, ascii_key);
	DEBUG("SCD: %s: Starting...", container_get_name(startdata->container));
	if (-1 == cmld_container_start(startdata->container, ascii_key))
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, resp_fd);
	else
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_OK, resp_fd);
	mem_free(ascii_key);
}

static void
smartcard_cb_start_container(int fd, unsigned events, event_io_t *io, void *data)
{
	smartcard_startdata_t *startdata = data;
	int resp_fd = control_get_client_sock(startdata->control);
	bool done = false;

	if (events & EVENT_IO_EXCEPT) {
		ERROR("Container start failed");

		event_remove_io(io);
		mem_free(io);
		mem_free(startdata);
		return;
	} else if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

		if (!msg) {
			ERROR("Failed to receive message althoug EVENT_IO_READ was set. Aborting container start.");

			event_remove_io(io);
			mem_free(io);
			mem_free(startdata);
			return;
		}

		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__LOCK_FAILED: {
			WARN("Locking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED, resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
			WARN("Unlocking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED,
					     resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
			WARN("Unlocking the token failed (wrong PIN/passphrase).");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG,
					     resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
			WARN("Unlocking the token failed (locked till reboot).");
			control_send_message(CONTROL_RESPONSE_DEVICE_LOCKED_TILL_REBOOT, resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
			char *keyfile =
				mem_printf("%s/%s.key", startdata->smartcard->path,
					   uuid_string(container_get_uuid(startdata->container)));
			if (file_exists(keyfile)) {
				DEBUG("Using key for container %s from existing key file %s",
				      container_get_name(startdata->container), keyfile);
				unsigned char key[TOKEN_MAX_WRAPPED_KEY_LEN];
				int keylen = file_read(keyfile, (char *)key, sizeof(key));
				// unwrap via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__UNWRAP_KEY;
				out.has_wrapped_key = true;
				out.wrapped_key.len = keylen;
				out.wrapped_key.data = key;
				protobuf_send_message(startdata->smartcard->sock,
						      (ProtobufCMessage *)&out);
			} else {
				DEBUG("No previous key found for container %s. Generating new key.",
				      container_get_name(startdata->container));
				if (!file_is_dir(startdata->smartcard->path) &&
				    mkdir(startdata->smartcard->path, 00755) < 0) {
					DEBUG_ERRNO("Could not mkdir %s",
						    startdata->smartcard->path);
					done = true;
					break;
				}
				unsigned char key[TOKEN_KEY_LEN];
				int keylen = hardware_get_random(key, sizeof(key));
				DEBUG("SCD: keylen=%d, sizeof(key)=%zu", keylen, sizeof(key));
				if (keylen != sizeof(key)) {
					ERROR("Failed to generate key for container, due to RNG Error!");
					break;
				}
				// start container
				smartcard_start_container_internal(startdata, key, keylen);
				// wrap key via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__WRAP_KEY;
				out.has_unwrapped_key = true;
				out.unwrapped_key.len = keylen;
				out.unwrapped_key.data = key;
				protobuf_send_message(startdata->smartcard->sock,
						      (ProtobufCMessage *)&out);
			}
			mem_free(keyfile);
		} break;
		case TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY: {
			// lock token via scd
			DaemonToToken out = DAEMON_TO_TOKEN__INIT;
			out.code = DAEMON_TO_TOKEN__CODE__LOCK;
			protobuf_send_message(startdata->smartcard->sock, (ProtobufCMessage *)&out);
			// start container
			if (!msg->has_unwrapped_key) {
				WARN("Expected derived key, but none was returned!");
				break;
			}
			smartcard_start_container_internal(startdata, msg->unwrapped_key.data,
							   msg->unwrapped_key.len);
		} break;
		case TOKEN_TO_DAEMON__CODE__WRAPPED_KEY: {
			// lock token via scd
			DaemonToToken out = DAEMON_TO_TOKEN__INIT;
			out.code = DAEMON_TO_TOKEN__CODE__LOCK;
			protobuf_send_message(startdata->smartcard->sock, (ProtobufCMessage *)&out);
			// save wrapped key
			if (!msg->has_wrapped_key) {
				WARN("Expected wrapped key, but none was returned!");
				break;
			}
			ASSERT(msg->wrapped_key.len < TOKEN_MAX_WRAPPED_KEY_LEN);
			char *keyfile =
				mem_printf("%s/%s.key", startdata->smartcard->path,
					   uuid_string(container_get_uuid(startdata->container)));
			// save wrapped key to file
			int bytes_written = file_write(keyfile, (char *)msg->wrapped_key.data,
						       msg->wrapped_key.len);
			if (bytes_written != (int)msg->wrapped_key.len) {
				ERROR("Failed to store key for container %s to %s!",
				      container_get_name(startdata->container), keyfile);
			}
			mem_free(keyfile);
		} break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			done = true;
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);

		if (done) {
			event_remove_io(io);
			mem_free(io);
			mem_free(startdata);
		}
	}
}

int
smartcard_container_start_handler(smartcard_t *smartcard, control_t *control,
				  container_t *container, const char *passwd)
{
	ASSERT(smartcard);
	ASSERT(control);
	ASSERT(container);
	ASSERT(passwd);

	int pw_size = strlen(passwd);
	DEBUG("SCD: Passwd form UI: %s, size: %d", passwd, pw_size);

	// register callback handler
	smartcard_startdata_t *startdata = mem_alloc(sizeof(smartcard_startdata_t));
	startdata->smartcard = smartcard;
	startdata->container = container;
	startdata->control = control;

	// TODO register timer if socket does not respond
	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ,
					 smartcard_cb_start_container, startdata);
	event_add_io(event);
	DEBUG("SCD: Registered start container callback for key from scd");
	// unlock token
	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__UNLOCK;
	out.token_pin = mem_strdup(passwd);
	protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_free(out.token_pin);

	return 0;
}

static void
smartcard_cb_generic(int fd, unsigned events, event_io_t *io, void *data)
{
	control_t *control = data;
	int resp_fd = control_get_client_sock(control);

	if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
			WARN("Unlocking the token failed (locked till reboot).");
			control_send_message(CONTROL_RESPONSE_DEVICE_LOCKED_TILL_REBOOT, resp_fd);
		} break;
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_SUCCESSFUL: {
			control_send_message(CONTROL_RESPONSE_DEVICE_CHANGE_PIN_SUCCESSFUL,
					     resp_fd);
		} break;
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_FAILED: {
			control_send_message(CONTROL_RESPONSE_DEVICE_CHANGE_PIN_FAILED, resp_fd);
		} break;
		case TOKEN_TO_DAEMON__CODE__DEVICE_PROV_ERROR: {
			control_send_message(CONTROL_RESPONSE_DEVICE_PROVISIONING_ERROR, resp_fd);
		} break;
		case TOKEN_TO_DAEMON__CODE__DEVICE_CERT_ERROR: {
			control_send_message(CONTROL_RESPONSE_DEVICE_CERT_ERROR, resp_fd);
		} break;
		case TOKEN_TO_DAEMON__CODE__DEVICE_CERT_OK: {
			control_send_message(CONTROL_RESPONSE_DEVICE_CERT_OK, resp_fd);
		} break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);

		event_remove_io(io);
		mem_free(io);
	}
}

int
smartcard_change_pin(smartcard_t *smartcard, control_t *control, const char *passwd,
		     const char *newpasswd)
{
	ASSERT(smartcard);
	ASSERT(control);

	int ret = -1;
	int pw_size = strlen(passwd);
	int newpw_size = strlen(newpasswd);
	DEBUG("SCD: Passwd form UI: %s, size: %d", passwd, pw_size);
	DEBUG("SCD: New Passwd form UI: %s, size: %d", newpasswd, newpw_size);

	event_io_t *event =
		event_io_new(smartcard->sock, EVENT_IO_READ, smartcard_cb_generic, control);
	event_add_io(event);
	DEBUG("SCD: Registered generic container callback for scd");

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CHANGE_PIN;
	out.token_pin = mem_strdup(passwd);
	out.token_newpin = mem_strdup(newpasswd);
	ret = protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_free(out.token_pin);
	mem_free(out.token_newpin);

	return (ret > 0) ? 0 : -1;
}

smartcard_t *
smartcard_new(const char *path)
{
	ASSERT(path);
	smartcard_t *smartcard = mem_alloc(sizeof(smartcard_t));
	smartcard->path = mem_strdup(path);
	smartcard->sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
	return smartcard;
}

void
smartcard_free(smartcard_t *smartcard)
{
	IF_NULL_RETURN(smartcard);
	// TODO properly cleanup
	mem_free(smartcard->path);
	mem_free(smartcard);
}

/// *** CRYPTO *** ///

static HashAlgo
smartcard_hashalgo_to_proto(smartcard_crypto_hashalgo_t hashalgo)
{
	switch (hashalgo) {
	case SHA1:
		return HASH_ALGO__SHA1;
	case SHA256:
		return HASH_ALGO__SHA256;
	case SHA512:
		return HASH_ALGO__SHA512;
	default:
		FATAL("Invalid smartcard_hashalgo_t value: %d", hashalgo);
	}
}

static smartcard_crypto_verify_result_t
smartcard_crypto_verify_result_from_proto(TokenToDaemon__Code code)
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
		FATAL("Cannot convert %d to valid smartcard_verify_result_t value", code);
	}
}

typedef struct crypto_callback_task {
	smartcard_crypto_hash_callback_t hash_complete;
	smartcard_crypto_verify_callback_t verify_complete;
	void *data;
	char *hash_file;
	smartcard_crypto_hashalgo_t hash_algo;
	char *verify_data_file;
	char *verify_sig_file;
	char *verify_cert_file;
} crypto_callback_task_t;

static crypto_callback_task_t *
crypto_callback_hash_task_new(smartcard_crypto_hash_callback_t cb, void *data,
			      const char *hash_file, smartcard_crypto_hashalgo_t hash_algo)
{
	crypto_callback_task_t *task = mem_new0(crypto_callback_task_t, 1);
	task->hash_complete = cb;
	task->data = data;
	task->hash_file = mem_strdup(hash_file);
	task->hash_algo = hash_algo;
	return task;
}

static crypto_callback_task_t *
crypto_callback_verify_task_new(smartcard_crypto_verify_callback_t cb, void *data,
				const char *data_file, const char *sig_file, const char *cert_file,
				smartcard_crypto_hashalgo_t hash_algo)
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

static void
crypto_callback_task_free(crypto_callback_task_t *task)
{
	IF_NULL_RETURN(task);
	mem_free(task->hash_file);
	mem_free(task->verify_data_file);
	mem_free(task->verify_sig_file);
	mem_free(task->verify_cert_file);
}

static void
smartcard_cb_crypto(int fd, unsigned events, event_io_t *io, void *data)
{
	crypto_callback_task_t *task = data;
	ASSERT(task);

	// TODO outsource socket/fd/events handling
	if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		switch (msg->code) {
		// deal with CRYPTO_HASH_* cases
		case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK:
			if (msg->has_hash_value) {
				char *hash = bytes_to_string_new(msg->hash_value.data,
								 msg->hash_value.len);
				task->hash_complete(hash, task->hash_file, task->hash_algo,
						    task->data);
				mem_free(hash);
				break;
			}
			ERROR("Missing hash_value in CRYPTO_HASH_OK response!"); // fallthrough
		case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR:
			task->hash_complete(NULL, task->hash_file, task->hash_algo, task->data);
			break;

		// deal with CRYPTO_VERIFY_* cases
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
		case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
			task->verify_complete(smartcard_crypto_verify_result_from_proto(msg->code),
					      task->verify_data_file, task->verify_sig_file,
					      task->verify_cert_file, task->hash_algo, task->data);
			break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);
	} else if (events & EVENT_IO_EXCEPT) {
		WARN("Got EVENT_IO_EXCEPT in smartcard_cb_crypto().");
		// TODO
	} else {
		WARN("Got other event %x in smartcard_cb_crypto(), ignoring.", events);
		return; // do nothing (i.e. do not free resources) for other kinds of events
	}

	event_remove_io(io);
	event_io_free(io);
	crypto_callback_task_free(task);
	close(fd);
}

static int
smartcard_send_crypto(const DaemonToToken *out, crypto_callback_task_t *task)
{
	ASSERT(out);
	ASSERT(task);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET | SOCK_NONBLOCK, SCD_CONTROL_SOCKET);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s for crypto",
			    SCD_CONTROL_SOCKET);
		return -1;
	}

	DEBUG("smartcard_send_crypto: connected to sock %d", sock);
	event_io_t *event = event_io_new(sock, EVENT_IO_READ, smartcard_cb_crypto, task);
	event_add_io(event);

	/*
	char *string = protobuf_c_text_to_string((ProtobufCMessage *) out, NULL);
	if (!string)
		string = mem_printf("%d", out->code);
	DEBUG("smartcard_send_crypto: sending crypto command {%s}", string);
	mem_free(string);
	*/

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) < 0) {
		event_remove_io(event);
		event_io_free(event);
		return -1;
	}
	return 0;
}

int
smartcard_crypto_hash_file(const char *file, smartcard_crypto_hashalgo_t hashalgo,
			   smartcard_crypto_hash_callback_t cb, void *data)
{
	ASSERT(file);
	ASSERT(cb);

	crypto_callback_task_t *task = crypto_callback_hash_task_new(cb, data, file, hashalgo);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE;
	out.has_hash_algo = true;
	out.hash_algo = smartcard_hashalgo_to_proto(hashalgo);
	out.hash_file = task->hash_file;
	if (smartcard_send_crypto(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

int
smartcard_crypto_verify_file(const char *datafile, const char *sigfile, const char *certfile,
			     smartcard_crypto_hashalgo_t hashalgo,
			     smartcard_crypto_verify_callback_t cb, void *data)
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
	out.hash_algo = smartcard_hashalgo_to_proto(hashalgo);
	if (smartcard_send_crypto(&out, task) < 0) {
		crypto_callback_task_free(task);
		return -1;
	}
	return 0;
}

static TokenToDaemon *
smartcard_send_recv_block(const DaemonToToken *out)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", SCD_CONTROL_SOCKET);
		return NULL;
	}

	DEBUG("smartcard_send_recv_block: connected to sock %d", sock);

	/*
	char *string = protobuf_c_text_to_string((ProtobufCMessage *) out, NULL);
	if (!string)
		string = mem_printf("%d", out->code);
	DEBUG("smartcard_send_crypto: sending crypto command {%s}", string);
	mem_free(string);
	*/

	if (protobuf_send_message(sock, (ProtobufCMessage *)out) <= 0) {
		ERROR("Failed to send message to scd on sock %d", sock);
		close(sock);
		return NULL;
	}

	TokenToDaemon *msg = NULL;
	msg = (TokenToDaemon *)protobuf_recv_message(sock, &token_to_daemon__descriptor);
	close(sock);
	return msg;
}

char *
smartcard_crypto_hash_file_block_new(const char *file, smartcard_crypto_hashalgo_t hashalgo)
{
	ASSERT(file);
	char *ret = NULL;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE;
	out.has_hash_algo = true;
	out.hash_algo = smartcard_hashalgo_to_proto(hashalgo);
	out.hash_file = mem_strdup(file);

	TokenToDaemon *msg = smartcard_send_recv_block(&out);
	mem_free(out.hash_file);

	IF_NULL_RETVAL(msg, NULL);

	switch (msg->code) {
	// deal with CRYPTO_HASH_* cases
	case TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK:
		if (msg->has_hash_value) {
			ret = bytes_to_string_new(msg->hash_value.data, msg->hash_value.len);
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

smartcard_crypto_verify_result_t
smartcard_crypto_verify_file_block(const char *datafile, const char *sigfile, const char *certfile,
				   smartcard_crypto_hashalgo_t hashalgo)
{
	ASSERT(datafile);
	ASSERT(sigfile);
	ASSERT(certfile);

	smartcard_crypto_verify_result_t ret = VERIFY_ERROR;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE;
	out.verify_data_file = mem_strdup(datafile);
	out.verify_sig_file = mem_strdup(sigfile);
	out.verify_cert_file = mem_strdup(certfile);
	out.has_hash_algo = true;
	out.hash_algo = smartcard_hashalgo_to_proto(hashalgo);

	TokenToDaemon *msg = smartcard_send_recv_block(&out);
	mem_free(out.verify_data_file);
	mem_free(out.verify_sig_file);
	mem_free(out.verify_cert_file);
	mem_free(out.hash_file);

	IF_NULL_RETVAL(msg, VERIFY_ERROR);

	switch (msg->code) {
	// deal with CRYPTO_VERIFY_* cases
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE:
	case TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED:
		ret = smartcard_crypto_verify_result_from_proto(msg->code);
		break;
	default:
		ERROR("Invalid TokenToDaemon command %d when verifying file %s with signature %s and certificate %s",
		      msg->code, datafile, sigfile, certfile);
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return ret;
}

uint8_t *
smartcard_pull_csr_new(size_t *csr_len)
{
	ASSERT(csr_len);
	uint8_t *csr = NULL;
	*csr_len = 0;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__PULL_DEVICE_CSR;

	TokenToDaemon *msg = smartcard_send_recv_block(&out);
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

void
smartcard_push_cert(smartcard_t *smartcard, control_t *control, uint8_t *cert, size_t cert_len)
{
	const char *begin_cert_str = "-----BEGIN CERTIFICATE-----";
	const char *end_cert_str = "-----END CERTIFICATE-----";

	if (cert == NULL || cert_len == 0) {
		WARN("PUSH_DEVICE_CERT without certificate");
		goto error;
	}
	// Sanity check file is a certificate
	size_t end_offset = cert_len - strlen(end_cert_str) - 1;
	if (strncmp((char *)cert, begin_cert_str, strlen(begin_cert_str)) != 0 ||
	    strncmp((char *)cert + end_offset, end_cert_str, strlen(end_cert_str)) != 0) {
		ERROR("Sanity check failed. provided data is not an encoded certificate");
		goto error;
	}
	event_io_t *event =
		event_io_new(smartcard->sock, EVENT_IO_READ, smartcard_cb_generic, control);
	event_add_io(event);
	DEBUG("SCD: Registered generic callback for scd (push_cert)");

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__PUSH_DEVICE_CERT;
	out.has_device_cert = true;
	out.device_cert.data = cert;
	out.device_cert.len = cert_len;

	if (protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out) > 0)
		return;
error:
	control_send_message(CONTROL_RESPONSE_DEVICE_CERT_ERROR, control_get_client_sock(control));
}
