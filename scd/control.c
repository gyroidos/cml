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

#include "control.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/scd/scd.pb-c.h"
#else
#include "scd.pb-c.h"
#endif

#include "softtoken.h"
#include "ssl_util.h"
#include "scd.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/list.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/protobuf.h"

#include <unistd.h>

#include <google/protobuf-c/protobuf-c-text.h>

// maximum no. of connections waiting to be accepted on the listening socket
#define SCD_CONTROL_SOCK_LISTEN_BACKLOG 8
#define KEY_LENGTH_BYTES 64

struct scd_control {
	int sock; // listen socket fd
};

UNUSED static list_t *control_list = NULL;

/* keep in sync with offered algorithms by protobuf */
static char *
switch_proto_hash_algo(int hash_algo)
{
	char *ret = NULL;
	switch (hash_algo) {
	case HASH_ALGO__SHA1: {
		ret = "SHA1";
	} break;
	case HASH_ALGO__SHA256: {
		ret = "SHA256";
	} break;
	case HASH_ALGO__SHA512: {
		ret = "SHA512";
	} break;
	default:
		ERROR("No valid hash algorithm specified");
		break;
	}
	return ret;
}

struct verify_cert_ca_cb_data {
	const char *cert_file;
	bool verified;
};

static int
scd_control_verify_cert_ca_cb(const char *path, const char *file, void *data)
{
	int ret = 0;
	struct verify_cert_ca_cb_data *cb_data = data;
	char *ca_file = mem_printf("%s/%s", path, file);

	if (ssl_verify_certificate(cb_data->cert_file, ca_file, true) != 0) {
		ERROR("Error during certificate validation using ca: %s", ca_file);
		cb_data->verified = false;
		ret = 1;
	} else {
		INFO("Certificate validation succeeded using ca: %s", ca_file);
		cb_data->verified = true;
		// break dir_foreach
		ret = -1;
	}
	mem_free(ca_file);
	return ret;
}

static TokenToDaemon__Code
scd_control_handle_verify(const DaemonToToken *msg)
{
	int ret;
	TokenToDaemon__Code out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR;
	char *hash_algo = switch_proto_hash_algo(msg->hash_algo);
	IF_NULL_RETVAL(hash_algo, out_code);

	bool verified = false;
	// At first, we explicitly assume that the file to be verified is a software update file,
	// and we thus use the software signing root CA.
	if ((ret = ssl_verify_certificate(msg->verify_cert_file, SSIG_ROOT_CERT, true)) == 0) {
		verified = true;
	} else {
		// Try all CA files in trusted CA store
		struct verify_cert_ca_cb_data cb_data = { .cert_file = msg->verify_cert_file, .verified = false };

		dir_foreach(TRUSTED_CA_STORE, scd_control_verify_cert_ca_cb, &cb_data);
		if (cb_data.verified) {
			verified = true;
			ret = 0;
		} else if (ret == -1) {
			ERROR("Certificate not a valid ssig cert");
			out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE;
		} else {
			ERROR("Error during certificate validation");
			out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR;
		}
	}
	IF_TRUE_GOTO(verified, do_signature);

	// Retry with Local CA
	if ((ret = ssl_verify_certificate(msg->verify_cert_file, LOCALCA_ROOT_CERT, true)) == 0) {
		goto do_signature;
	} else if (ret == -1) {
		ERROR("Certificate not a valid local ssig cert");
		out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_CERTIFICATE;
	} else {
		ERROR("Error during certificate validation");
		out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR;
	}
	return out_code;

do_signature:
	if ((ret = ssl_verify_signature(msg->verify_cert_file, msg->verify_sig_file, msg->verify_data_file,
					hash_algo)) == 0) {
		out_code = (verified) ? TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_GOOD :
					TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_LOCALLY_SIGNED;
	} else if (ret == -1) {
		ERROR("Signature invalid");
		out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_BAD_SIGNATURE;
	} else {
		ERROR("Error during signature validation");
		out_code = TOKEN_TO_DAEMON__CODE__CRYPTO_VERIFY_ERROR;
	}
	return out_code;
}

static void
scd_control_handle_message(const DaemonToToken *msg, int fd)
{
	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text = protobuf_c_text_to_string((ProtobufCMessage *)msg, NULL);
		TRACE("Handling DaemonToToken message:\n%s", msg_text ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	switch (msg->code) {
	case DAEMON_TO_TOKEN__CODE__UNLOCK: {
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED;

		softtoken_t *token = scd_get_token();
		if (!token) {
			ERROR("No token loaded, unlock failed");
		} else if (!msg->token_pin) {
			ERROR("Token passphrase not specified");
		} else if (softtoken_is_locked_till_reboot(token)) {
			out.code = TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT;
		} else {
			int ret = softtoken_unlock(token, msg->token_pin);
			if (ret == 0)
				out.code = TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL;
			else if (ret == -2) {
				if (softtoken_is_locked_till_reboot(token))
					out.code = TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT;
				else
					out.code = TOKEN_TO_DAEMON__CODE__PASSWD_WRONG;
			} else
				out.code = TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED;
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case DAEMON_TO_TOKEN__CODE__LOCK: {
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__LOCK_FAILED;

		softtoken_t *token = scd_get_token();
		if (!token) {
			ERROR("No token loaded, lock failed");
		} else if (softtoken_lock(token) == 0) {
			out.code = TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL;
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case DAEMON_TO_TOKEN__CODE__WRAP_KEY: {
		int wrapped_key_len;
		unsigned char *wrapped_key;
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__WRAPPED_KEY;

		softtoken_t *token = scd_get_token();
		if (!token) {
			ERROR("No token loaded, wrap failed");
		} else if (softtoken_is_locked(token)) {
			ERROR("Token is locked. Unlock first.");
		} else if (!msg->has_unwrapped_key) {
			ERROR("Unwrapped key not specified.");
		} else if (softtoken_wrap_key(token, msg->unwrapped_key.data, msg->unwrapped_key.len, &wrapped_key,
					      &wrapped_key_len) == 0) {
			out.has_wrapped_key = true;
			out.wrapped_key.len = wrapped_key_len;
			out.wrapped_key.data = wrapped_key;
		} else {
			ERROR("Key wrapping failed");
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
		if (out.has_wrapped_key)
			mem_free(wrapped_key);
	} break;
	case DAEMON_TO_TOKEN__CODE__UNWRAP_KEY: {
		int unwrapped_key_len;
		unsigned char *unwrapped_key;
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY;

		softtoken_t *token = scd_get_token();
		if (!token) {
			ERROR("No token loaded, unwrap failed");
		} else if (softtoken_is_locked(token)) {
			ERROR("Token is locked. Unlock first.");
		} else if (!msg->has_wrapped_key) {
			ERROR("Wrapped key not specified.");
		} else if (softtoken_unwrap_key(token, msg->wrapped_key.data, msg->wrapped_key.len, &unwrapped_key,
						&unwrapped_key_len) == 0) {
			out.has_unwrapped_key = true;
			out.unwrapped_key.len = unwrapped_key_len;
			out.unwrapped_key.data = unwrapped_key;
		} else {
			ERROR("Key unwrapping failed");
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
		if (out.has_unwrapped_key)
			mem_free(unwrapped_key);
	} break;
	case DAEMON_TO_TOKEN__CODE__CHANGE_PIN: {
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__CHANGE_PIN_FAILED;

		softtoken_t *token = scd_get_token();
		if (!token) {
			ERROR("No token loaded, change pass failed");
		} else if (!msg->token_pin) {
			ERROR("Token passphrase not specified");
		} else if (softtoken_is_locked_till_reboot(token)) {
			out.code = TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT;
		} else {
			int ret = softtoken_change_passphrase(token, msg->token_pin, msg->token_newpin);
			if (ret == 0)
				out.code = TOKEN_TO_DAEMON__CODE__CHANGE_PIN_SUCCESSFUL;
			else
				out.code = TOKEN_TO_DAEMON__CODE__CHANGE_PIN_FAILED;
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case DAEMON_TO_TOKEN__CODE__PULL_DEVICE_CSR: {
		uint8_t *csr = NULL;
		int csr_len = 0;
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		if (!scd_in_provisioning_mode()) {
			out.code = TOKEN_TO_DAEMON__CODE__DEVICE_PROV_ERROR;
		} else {
			csr_len = file_size(DEVICE_CSR_FILE);
			// we set maximum read length one byte grater than file_size
			// since file_read sets '\0' char at the end of the buffer
			csr = file_read_new(DEVICE_CSR_FILE, csr_len + 1);
			if (csr_len < 0 || csr == NULL) {
				out.code = TOKEN_TO_DAEMON__CODE__DEVICE_CSR_ERROR;
			} else {
				out.code = TOKEN_TO_DAEMON__CODE__DEVICE_CSR;
				out.has_device_csr = true;
				out.device_csr.len = csr_len;
				out.device_csr.data = csr;
			}
		}
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
		INFO("csr: %p", csr);
		if (csr)
			mem_free(csr);
	} break;
	case DAEMON_TO_TOKEN__CODE__PUSH_DEVICE_CERT: {
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		if (!scd_in_provisioning_mode()) {
			out.code = TOKEN_TO_DAEMON__CODE__DEVICE_PROV_ERROR;
		} else if (!msg->has_device_cert) {
			ERROR("No device_cert in msg!");
			out.code = TOKEN_TO_DAEMON__CODE__DEVICE_CERT_ERROR;
		} else if (-1 == file_write(DEVICE_CERT_FILE, msg->device_cert.data, msg->device_cert.len)) {
			ERROR("writing device cert to file :%s", DEVICE_CERT_FILE);
			out.code = TOKEN_TO_DAEMON__CODE__DEVICE_CERT_ERROR;
		} else {
			out.code = TOKEN_TO_DAEMON__CODE__DEVICE_CERT_OK;
		}
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case DAEMON_TO_TOKEN__CODE__CRYPTO_HASH_FILE: {
		unsigned int hash_len;
		char *hash_algo;
		unsigned char *hash = NULL;
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_ERROR;

		hash_algo = switch_proto_hash_algo(msg->hash_algo);

		if (hash_algo) {
			if ((hash = ssl_hash_file(msg->hash_file, &hash_len, hash_algo)) == NULL) {
				ERROR("Hashing file failed");
			} else {
				out.has_hash_value = true;
				out.hash_value.len = hash_len;
				out.hash_value.data = hash;
				out.code = TOKEN_TO_DAEMON__CODE__CRYPTO_HASH_OK;
			}
		}

		protobuf_send_message(fd, (ProtobufCMessage *)&out);
		if (hash)
			mem_free(hash);
	} break;
	case DAEMON_TO_TOKEN__CODE__CRYPTO_VERIFY_FILE: {
		TokenToDaemon out = TOKEN_TO_DAEMON__INIT;
		out.code = scd_control_handle_verify(msg);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	default:
		WARN("DaemonToToken command %d unknown or not implemented yet", msg->code);
		break;
	}
}

/**
 * Event callback for incoming data that a ControllerToDaemon message.
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd	    file descriptor of the client connection
 *		    from which the incoming message is read
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this scd_control_t struct
 */
static void
scd_control_cb_recv_message(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	if (events & EVENT_IO_READ) {
		DaemonToToken *msg = (DaemonToToken *)protobuf_recv_message(fd, &daemon_to_token__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		scd_control_handle_message(msg, fd);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled control connection %d", fd);
	}
	if (events & EVENT_IO_EXCEPT) {
		INFO("Control client closed connection; disconnecting control socket.");
		goto connection_err;
	}
	return;

connection_err:
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
	return;
}
/**
 * Event callback for accepting incoming connections on the listening socket.
 *
 * @param fd	    file descriptor of the listening socket
 *		    from which incoming connectionis should be accepted
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this scd_control_t struct
  */
static void
scd_control_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	scd_control_t *control = data;
	ASSERT(control);
	ASSERT(control->sock == fd);

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept control connection");
		return;
	}
	DEBUG("Accepted control connection %d", cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, scd_control_cb_recv_message, control);
	event_add_io(event);
}

scd_control_t *
scd_control_new(const char *path)
{
	int sock = sock_unix_create_and_bind(SOCK_SEQPACKET | SOCK_NONBLOCK, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	if (listen(sock, SCD_CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	scd_control_t *scd_control = mem_new0(scd_control_t, 1);
	scd_control->sock = sock;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, scd_control_cb_accept, scd_control);
	event_add_io(event);

	return scd_control;
}
