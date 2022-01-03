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

#define MOD_NAME "c_smartcard"

#include "scd.pb-c.h"

#include "hardware.h"
#include "cmld.h"
#include "control.h"
#include "audit.h"
#include "scd_shared.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/proc.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <unistd.h>

// clang-format off
#define SCD_CONTROL_SOCKET SOCK_PATH(scd-control)
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(tokencontrol)
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

// TODO: centrally define key length in container or other module?
#define TOKEN_KEY_LEN 96 // actual encryption key + hmac key
#define TOKEN_MAX_WRAPPED_KEY_LEN 4096

#define MAX_PAIR_SEC_LEN 8
#define PAIR_SEC_FILE_NAME "device_pairing_secret"

#define TOKEN_IS_PAIRED_FILE_NAME "token_is_paired"

typedef struct c_smartcard {
	int sock;
	const char *path;
	container_t *container;
} c_smartcard_t;

typedef struct c_smartcard_cbdata {
	c_smartcard_t *smartcard;
	int resp_fd;
} c_smartcard_cbdata_t;

static char *
bytes_to_string_new(unsigned char *data, size_t len)
{
	IF_NULL_RETVAL(data, NULL);
	IF_TRUE_RETVAL(len == 0, NULL);
	size_t len_chunk = MUL_WITH_OVERFLOW_CHECK(len, (size_t)2);
	len_chunk = ADD_WITH_OVERFLOW_CHECK(len_chunk, 1);

	char *str = mem_alloc(len_chunk);
	for (size_t i = 0; i < len; i++)
		snprintf(str + 2 * i, 3, "%02x", data[i]);
	return str;
}

static TokenType
c_smartcard_tokentype_to_proto(container_token_type_t tokentype)
{
	switch (tokentype) {
	case CONTAINER_TOKEN_TYPE_NONE:
		return TOKEN_TYPE__NONE;
	case CONTAINER_TOKEN_TYPE_SOFT:
		return TOKEN_TYPE__SOFT;
	case CONTAINER_TOKEN_TYPE_USB:
		return TOKEN_TYPE__USB;
	default:
		FATAL("Invalid container_token_type_t value : %d", tokentype);
	}
}

/**
 * Gets the device pairing secret.
 * TODO: the secret should be protected inside a TPM
 */
static int
c_smartcard_get_pairing_secret(c_smartcard_t *smartcard, unsigned char *buf, int buf_len)
{
	ASSERT(smartcard);
	ASSERT(buf);

	TRACE("Retrieving pairing secret");

	int bytes_read, bytes_written;
	char *pair_sec_file = mem_printf("%s/%s", smartcard->path, PAIR_SEC_FILE_NAME);

	if (file_exists(pair_sec_file)) {
		bytes_read = file_read(pair_sec_file, (char *)buf, buf_len);
	} else {
		DEBUG("No pairing secret has been persisted yet. Creating new one");
		bytes_read = hardware_get_random(buf, buf_len);
		if (bytes_read != buf_len) {
			ERROR("Failed to get random pairing secret");
			bytes_read = -1;
			goto out;
		} else {
			if (mkdir(smartcard->path, 0755) < 0 && errno != EEXIST) {
				ERROR_ERRNO("Could not mkdir %s", smartcard->path);
				bytes_read = -1;
				goto out;
			}

			bytes_written = file_write(pair_sec_file, (char *)buf, buf_len);

			if (bytes_written != bytes_read) {
				ERROR("Failed to write paring secret to file, bytes written: %d",
				      bytes_written);
				bytes_read = -1;
				goto out;
			}
		}
	}

out:
	mem_free0(pair_sec_file);
	return bytes_read;
}

static TokenToDaemon *
c_smartcard_send_recv_block(const DaemonToToken *out)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", SCD_CONTROL_SOCKET);
		return NULL;
	}

	DEBUG("c_smartcard_send_recv_block: connected to sock %d", sock);

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

/**
 * Returns the path to a container specific flag file, that indicates, that the
 * token has been provisioned with a platform bound authentication code
 */
static char *
c_smartcard_token_paired_file_new(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);
	return mem_printf("%s/%s", container_get_images_dir(smartcard->container),
			  TOKEN_IS_PAIRED_FILE_NAME);
}

/**
 * checks whether the token associated to @param container has been provisioned
 * with a device bound authentication code yet.
 * TODO: this should actually query the SCD. Functionality in SCD not yet implemented.
 */
static bool
c_smartcard_container_token_is_provisioned(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	bool ret;

	char *token_init_file = c_smartcard_token_paired_file_new(smartcard);

	ret = file_exists(token_init_file);

	mem_free0(token_init_file);
	return ret;
}

static void
c_smartcard_start_container_internal(c_smartcard_cbdata_t *cbdata)
{
	ASSERT(cbdata);

	c_smartcard_t *smartcard = cbdata->smartcard;
	int resp_fd = cbdata->resp_fd;

	if (NULL == container_get_key(smartcard->container)) {
		FATAL("No container key is set.");
	}

	// backward compatibility: convert binary key to ascii (to have it converted back later)
	DEBUG("SCD:Container  %s: Starting...", container_get_name(smartcard->container));
	if (-1 == cmld_container_start(smartcard->container))
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, resp_fd);
	else
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_OK, resp_fd);
}

static void
c_smartcard_stop_container_internal(c_smartcard_cbdata_t *cbdata)
{
	ASSERT(cbdata);

	c_smartcard_t *smartcard = cbdata->smartcard;
	int resp_fd = cbdata->resp_fd;

	int res = cmld_container_stop(smartcard->container);

	// TODO if the modules cannot be stopped successfully, the container is killed. The return
	// value in this case is CONTAINER_ERROR, even if the container was killed. This is
	// ignored atm and just STOP_OK is returned. How should we treat this?
	if (res == -1) {
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_FAILED_NOT_RUNNING, resp_fd);
	} else {
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_OK, resp_fd);
	}
}

static void
c_smartcard_cb_start_container(int fd, unsigned events, event_io_t *io, void *data)
{
	c_smartcard_cbdata_t *cbdata = data;
	ASSERT(cbdata);

	c_smartcard_t *smartcard = cbdata->smartcard;
	int resp_fd = cbdata->resp_fd;

	bool done = false;

	if (events & EVENT_IO_EXCEPT) {
		ERROR("Container start failed");

		event_remove_io(io);
		event_io_free(io);
		mem_free0(cbdata);
		return;
	} else if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting container start.");

			event_remove_io(io);
			event_io_free(io);
			mem_free0(cbdata);
			return;
		}

		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__LOCK_FAILED: {
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "lock",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			WARN("Locking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED, resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
			if (container_get_key(smartcard->container))
				c_smartcard_start_container_internal(cbdata);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unlock",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			WARN("Unlocking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED,
					     resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
			WARN("Unlocking the token failed (wrong PIN/passphrase).");
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unlock-wrong-pin",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG,
					     resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
			WARN("Unlocking the token failed (locked till reboot).");
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "locked-until-reboot",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT,
					     resp_fd);
			done = true;
		} break;

		/*
		 * This case handles key unwrapping as part of TSF.CML.CompartmentDataStorage.
		 */
		case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "unlock-successful",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			char *keyfile =
				mem_printf("%s/%s.key", smartcard->path,
					   uuid_string(container_get_uuid(smartcard->container)));
			if (file_exists(keyfile)) {
				DEBUG("Using key for container %s from existing key file %s",
				      container_get_name(smartcard->container), keyfile);
				unsigned char key[TOKEN_MAX_WRAPPED_KEY_LEN];
				int keylen = file_read(keyfile, (char *)key, sizeof(key));
				DEBUG("Length of existing key: %d", keylen);
				if (keylen < 0) {
					audit_log_event(container_get_uuid(smartcard->container),
							FSA, CMLD, TOKEN_MGMT, "read-wrapped-key",
							uuid_string(container_get_uuid(
								smartcard->container)),
							0);
					ERROR("Failed to read key from file for container!");
					break;
				}

				audit_log_event(
					container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "read-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				// unwrap via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__UNWRAP_KEY;
				out.has_wrapped_key = true;
				out.wrapped_key.len = keylen;
				out.wrapped_key.data = key;
				out.container_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				out.has_token_type = true;
				out.token_type = c_smartcard_tokentype_to_proto(
					container_get_token_type(smartcard->container));

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);

				//delete wrapped key from RAM
				mem_memset0(key, sizeof(key));
				mem_free0(out.container_uuid);
				mem_free0(out.token_uuid);
			} else {
				DEBUG("No previous key found for container %s. Generating new key.",
				      container_get_name(smartcard->container));
				if (!file_is_dir(smartcard->path) &&
				    mkdir(smartcard->path, 00755) < 0) {
					DEBUG_ERRNO("Could not mkdir %s", smartcard->path);
					done = true;
					break;
				}
				unsigned char key[TOKEN_KEY_LEN];
				int keylen = hardware_get_random(key, sizeof(key));
				DEBUG("SCD: keylen=%d, sizeof(key)=%zu", keylen, sizeof(key));
				if (keylen != sizeof(key)) {
					audit_log_event(container_get_uuid(smartcard->container),
							FSA, CMLD, TOKEN_MGMT,
							"gen-container-key-rng-error",
							uuid_string(container_get_uuid(
								smartcard->container)),
							0);
					ERROR("Failed to generate key for container, due to RNG Error!");
					break;
				}
				audit_log_event(
					container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "gen-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				// set the key
				char *ascii_key = bytes_to_string_new(key, keylen);
				container_set_key(smartcard->container, ascii_key);
				// delete key from RAM
				mem_memset0(ascii_key, strlen(ascii_key));
				mem_free0(ascii_key);
				// wrap key via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__WRAP_KEY;
				out.has_unwrapped_key = true;
				out.unwrapped_key.len = keylen;
				out.unwrapped_key.data = key;
				out.container_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				out.has_token_type = true;
				out.token_type = c_smartcard_tokentype_to_proto(
					container_get_token_type(smartcard->container));

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(smartcard->container)));

				protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);

				// delete key from RAM
				mem_memset0(key, sizeof(key));
				mem_free0(out.container_uuid);
				mem_free0(out.token_uuid);
			}
			mem_free0(keyfile);
		} break;
		/*
		 * This case handles key unwrapping as part of TSF.CML.CompartmentDataStorage.
		 */
		case TOKEN_TO_DAEMON__CODE__UNWRAPPED_KEY: {
			// lock token via scd
			DaemonToToken out = DAEMON_TO_TOKEN__INIT;
			out.code = DAEMON_TO_TOKEN__CODE__LOCK;

			out.has_token_type = true;
			out.token_type = c_smartcard_tokentype_to_proto(
				container_get_token_type(smartcard->container));

			out.token_uuid =
				mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

			protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
			mem_free0(out.token_uuid);
			if (!msg->has_unwrapped_key) {
				WARN("Expected derived key, but none was returned!");
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL,
						     resp_fd);
				break;
			}
			// set the key
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			TRACE("Successfully retrieved unwrapped key from SCD");
			char *ascii_key = bytes_to_string_new(msg->unwrapped_key.data,
							      msg->unwrapped_key.len);
			container_set_key(smartcard->container, ascii_key);
			//delete key from RAM
			mem_memset0(ascii_key, strlen(ascii_key));
			mem_memset0(msg->unwrapped_key.data, msg->unwrapped_key.len);
			mem_free0(ascii_key);
		} break;
		case TOKEN_TO_DAEMON__CODE__WRAPPED_KEY: {
			// lock token via scd
			DaemonToToken out = DAEMON_TO_TOKEN__INIT;
			out.code = DAEMON_TO_TOKEN__CODE__LOCK;

			out.has_token_type = true;
			out.token_type = c_smartcard_tokentype_to_proto(
				container_get_token_type(smartcard->container));

			out.token_uuid =
				mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

			protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
			mem_free0(out.token_uuid);
			// save wrapped key
			if (!msg->has_wrapped_key) {
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				WARN("Expected wrapped key, but none was returned!");
				break;
			}
			ASSERT(msg->wrapped_key.len < TOKEN_MAX_WRAPPED_KEY_LEN);
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			char *keyfile =
				mem_printf("%s/%s.key", smartcard->path,
					   uuid_string(container_get_uuid(smartcard->container)));
			// save wrapped key to file
			int bytes_written = file_write(keyfile, (char *)msg->wrapped_key.data,
						       msg->wrapped_key.len);
			if (bytes_written != (int)msg->wrapped_key.len) {
				audit_log_event(
					container_get_uuid(smartcard->container), FSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
				ERROR("Failed to store key for container %s to %s!",
				      container_get_name(smartcard->container), keyfile);
			}
			audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			TRACE("Stored wrapped key on disk successfully");
			// delete wrapped key from RAM
			mem_memset0(msg->wrapped_key.data, msg->wrapped_key.len);
			mem_free0(keyfile);
		} break;
		default:
			ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
			done = true;
			break;
		}
		protobuf_free_message((ProtobufCMessage *)msg);

		if (done) {
			event_remove_io(io);
			event_io_free(io);
			mem_free0(cbdata);
		}
	}
}

static void
c_smartcard_cb_stop_container(int fd, unsigned events, event_io_t *io, void *data)
{
	c_smartcard_cbdata_t *cbdata = data;
	ASSERT(cbdata);

	c_smartcard_t *smartcard = cbdata->smartcard;
	int resp_fd = cbdata->resp_fd;

	IF_TRUE_GOTO(events & EVENT_IO_EXCEPT, exit);

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	// use protobuf for communication with scd
	TokenToDaemon *msg =
		(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

	if (!msg) {
		ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting container stop.");
		goto exit;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__LOCK_FAILED: {
		WARN("Locking the token failed.");
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_LOCK_FAILED, resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
		c_smartcard_stop_container_internal(cbdata);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
		WARN("Unlocking the token failed.");
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_UNLOCK_FAILED, resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
		WARN("Unlocking the token failed (wrong PIN/passphrase).");
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_PASSWD_WRONG, resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
		WARN("Unlocking the token failed (locked till reboot).");
		control_send_message(CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT, resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
		// lock token via scd
		DaemonToToken out = DAEMON_TO_TOKEN__INIT;
		out.code = DAEMON_TO_TOKEN__CODE__LOCK;

		out.has_token_type = true;
		out.token_type = c_smartcard_tokentype_to_proto(
			container_get_token_type(smartcard->container));

		out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

		protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
		mem_free0(out.token_uuid);
	} break;
	default:
		ERROR("TokenToDaemon command %d unknown or not implemented yet", msg->code);
		goto exit;
	}
	protobuf_free_message((ProtobufCMessage *)msg);
	return;

exit:
	event_remove_io(io);
	event_io_free(io);
	mem_free0(cbdata);
	return;
}

static int
c_smartcard_token_unlock_handler(c_smartcard_t *smartcard, int resp_fd, const char *passwd,
				 void (*cb)(int fd, unsigned events, event_io_t *io, void *data))
{
	ASSERT(smartcard);
	ASSERT(passwd);

	c_smartcard_cbdata_t *cbdata = mem_alloc(sizeof(c_smartcard_cbdata_t));
	if (!cbdata) {
		ERROR("Could not allocate memory for callback data");
		return -1;
	}
	cbdata->smartcard = smartcard;
	cbdata->resp_fd = resp_fd;

	int pair_sec_len;

	if (!container_get_token_is_init(smartcard->container)) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"token-uninitialized",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		ERROR("The token that is associated with the container has not been initialized!");
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNINITIALIZED, resp_fd);
		goto err;
	}

	if (!container_get_token_is_linked_to_device(smartcard->container)) {
		ERROR("The token that is associated with this container must be paired to the device first");
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"token-not-paired",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNPAIRED, resp_fd);
		goto err;
	}

	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	pair_sec_len = c_smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (pair_sec_len < 0) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		ERROR("Could not retrieve pairing secret");
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, resp_fd);
		goto err;
	}
	audit_log_event(container_get_uuid(smartcard->container), SSA, CMLD, TOKEN_MGMT,
			"read-pairing-secret",
			uuid_string(container_get_uuid(smartcard->container)), 0);

	// TODO register timer if socket does not respond
	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ, cb, cbdata);

	event_add_io(event);
	DEBUG("SCD: Registered control container callback for key from scd");
	// unlock token
	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__UNLOCK;
	out.token_pin = mem_strdup(passwd);
	out.has_pairing_secret = true;
	out.pairing_secret.len = pair_sec_len;
	out.pairing_secret.data = mem_memcpy(pair_sec, sizeof(pair_sec));
	out.has_token_type = true;
	out.token_type =
		c_smartcard_tokentype_to_proto(container_get_token_type(smartcard->container));

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text;

		size_t msg_len =
			protobuf_string_from_message(&msg_text, (ProtobufCMessage *)&out, NULL);

		TRACE("Sending DaemonToToken message:\n%s", msg_len > 0 ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_memset0(out.token_pin, strlen(out.token_pin));
	mem_free0(out.token_pin);
	mem_free0(out.pairing_secret.data);
	mem_free0(out.token_uuid);
	return 0;

err:
	mem_free0(cbdata);
	return -1;
}

static void
c_smartcard_cb_container_change_pin(int fd, unsigned events, event_io_t *io, void *data)
{
	c_smartcard_cbdata_t *cbdata = data;
	ASSERT(cbdata);

	c_smartcard_t *smartcard = cbdata->smartcard;
	int resp_fd = cbdata->resp_fd;

	int rc = -1;
	bool command_state = false;

	if (events & EVENT_IO_READ) {
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard change_pin callback.");
			event_remove_io(io);
			event_io_free(io);
			audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD,
					CONTAINER_MGMT, "container-change-pin",
					uuid_string(container_get_uuid(smartcard->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED, resp_fd);
			mem_free0(cbdata);
			return;
		}
		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_SUCCESSFUL: {
			command_state = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__CHANGE_PIN_FAILED: {
			command_state = false;
		} break;
		case TOKEN_TO_DAEMON__CODE__PROVISION_PIN_SUCCESSFUL: {
			char *path = c_smartcard_token_paired_file_new(smartcard);
			rc = file_touch(path);
			if (rc != 0) { //should never happen
				ERROR("Could not write file %s to flag that container %s's token has been initialized\n \
						This may leave the system in an inconsistent state!",
				      path, uuid_string(container_get_uuid(smartcard->container)));
				container_set_token_is_linked_to_device(smartcard->container,
									false);
				command_state = false;
			} else {
				container_set_token_is_linked_to_device(smartcard->container, true);
				command_state = true;
			}
			mem_free0(path);
		} break;
		case TOKEN_TO_DAEMON__CODE__PROVISION_PIN_FAILED: {
			container_set_token_is_linked_to_device(smartcard->container, false);
			command_state = false;
		} break;
		default:
			ERROR("TokenToDaemon command %d not expected as answer to change_pin",
			      msg->code);
			command_state = false;
		}

		audit_log_event(container_get_uuid(smartcard->container), command_state ? SSA : FSA,
				CMLD, CONTAINER_MGMT, "container-change-pin",
				uuid_string(container_get_uuid(smartcard->container)), 0);
		control_send_message(command_state ?
					     CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_SUCCESSFUL :
					     CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED,
				     resp_fd);

		protobuf_free_message((ProtobufCMessage *)msg);
		event_remove_io(io);
		event_io_free(io);
		mem_free0(cbdata);
	} else {
		ERROR("Failed to receive message: EVENT_IO_EXCEPT. Aborting smartcard change_pin.");
		event_remove_io(io);
		event_io_free(io);
		mem_free0(cbdata);
	}
}

static int
c_smartcard_change_pin(void *smartcardp, int resp_fd, const char *passwd, const char *newpasswd)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);
	ASSERT(passwd);
	ASSERT(newpasswd);

	int ret = -1;
	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	bool is_provisioning;

	c_smartcard_cbdata_t *cbdata = mem_alloc0(sizeof(c_smartcard_cbdata_t));
	if (!cbdata) {
		ERROR("Could not allocate memory for cbdata");
		return -1;
	}
	cbdata->smartcard = smartcard;
	cbdata->resp_fd = resp_fd;

	DEBUG("SCD: Received new password from UI");

	ret = c_smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (ret < 0) {
		audit_log_event(container_get_uuid(smartcard->container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret", uuid_string(container_get_uuid(smartcard->container)),
				0);
		ERROR("Could not retrieve pairing secret, ret code : %d", ret);
		control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED, resp_fd);
		mem_free0(cbdata);
		return -1;
	}

	is_provisioning = !c_smartcard_container_token_is_provisioned(smartcard);

	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ,
					 c_smartcard_cb_container_change_pin, cbdata);
	event_add_io(event);
	DEBUG("SCD: Registered smartcard_cb_container_change_pin container callback for scd");

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = is_provisioning ? DAEMON_TO_TOKEN__CODE__PROVISION_PIN :
				     DAEMON_TO_TOKEN__CODE__CHANGE_PIN;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(smartcard->container)));

	out.has_token_type = true;
	out.token_type =
		c_smartcard_tokentype_to_proto(container_get_token_type(smartcard->container));

	out.token_pin = mem_strdup(passwd);
	out.token_newpin = mem_strdup(newpasswd);

	out.has_pairing_secret = true;
	out.pairing_secret.len = sizeof(pair_sec);
	out.pairing_secret.data = mem_memcpy(pair_sec, sizeof(pair_sec));

	ret = protobuf_send_message(smartcard->sock, (ProtobufCMessage *)&out);
	mem_memset0(out.token_pin, strlen(out.token_pin));
	mem_memset0(out.token_newpin, strlen(out.token_newpin));
	mem_memset0(pair_sec, sizeof(pair_sec));
	mem_free0(out.token_pin);
	mem_free0(out.token_newpin);
	mem_free0(out.pairing_secret.data);
	mem_free0(out.token_uuid);

	return (ret > 0) ? 0 : -1;
}

static int
c_smartcard_update_token_state(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	/* TODO: query SCD whether a token has been initialized.
	 * requires modifications to SCD
	 */
	// container_set_token_is_init(container, smartcard_container_token_is_init(container));

	container_set_token_is_linked_to_device(
		smartcard->container, c_smartcard_container_token_is_provisioned(smartcard));

	DEBUG("Updated Token state: %d",
	      container_get_token_is_linked_to_device(smartcard->container));

	return 0;
}

/**
 * we cannot queue several events with the same fd.
 * therefore, we use a blocking method to query the scd to initialize a token.
 */
static int
c_smartcard_scd_token_add_block(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);
	container_t *container = smartcard->container;

	TRACE("CML: request SCD to add the token associated to %s to its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	int rc = -1;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_ADD;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(container_get_token_type(container));

	if (out.token_type == TOKEN_TYPE__USB) {
		out.usbtoken_serial = container_get_usbtoken_serial(container);
		if (NULL == out.usbtoken_serial) {
			ERROR("Could not retrive serial of usbtoken reader. Abort token init...");
			goto err;
		}
	}

	TokenToDaemon *msg = c_smartcard_send_recv_block(&out);
	if (!msg) {
		ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard_scd_token_block_new.");
		goto err;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__TOKEN_ADD_SUCCESSFUL: {
		TRACE("CMLD: smartcard_scd_token_block_new: token in scd created successfully");
		container_set_token_uuid(container, out.token_uuid);
		container_set_token_is_init(container, true);
		rc = 0;
	} break;
	case TOKEN_TO_DAEMON__CODE__TOKEN_ADD_FAILED: {
		container_set_token_is_init(container, false);
		ERROR("Creating scd token structure failed");
	} break;
	default:
		container_set_token_is_init(container, false);
		ERROR("TokenToDaemon command %d not expected as answer to change_pin", msg->code);
	}

	protobuf_free_message((ProtobufCMessage *)msg);

err:
	mem_free0(out.token_uuid);
	return rc;
}

static int
c_smartcard_scd_token_remove_block(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);
	container_t *container = smartcard->container;

	TRACE("CML: request scd to remove the token associated to %s from its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_REMOVE;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = c_smartcard_tokentype_to_proto(container_get_token_type(container));

	TokenToDaemon *msg = c_smartcard_send_recv_block(&out);
	if (!msg) {
		ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard_scd_token_block_new.");
		mem_free0(out.token_uuid);
		return -1;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__TOKEN_REMOVE_SUCCESSFUL: {
		TRACE("CMLD: smartcard_scd_token_block_remove: token in scd removed successfully");
		container_set_token_is_init(container, false);
	} break;
	case TOKEN_TO_DAEMON__CODE__TOKEN_REMOVE_FAILED: {
		ERROR("Removing scd token structure failed");
	} break;
	default:
		ERROR("TokenToDaemon command %d not expected as answer to change_pin", msg->code);
	}

	mem_free0(out.token_uuid);
	protobuf_free_message((ProtobufCMessage *)msg);
	return 0;
}

static int
c_smartcard_remove_keyfile(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	int rc = -1;

	char *keyfile = mem_printf("%s/%s.key", smartcard->path,
				   uuid_string(container_get_uuid(smartcard->container)));

	if (!file_exists(keyfile)) {
		DEBUG("No keyfile found for container %s (uuid=%s).",
		      container_get_name(smartcard->container),
		      uuid_string(container_get_uuid(smartcard->container)));
		rc = 0;
		goto out;
	}

	if (0 != remove(keyfile)) {
		ERROR_ERRNO("Failed to remove keyfile");
		goto out;
	}

	rc = 0;

out:
	mem_free0(keyfile);
	return rc;
}

static int
c_smartcard_container_start(void *smartcardp, int resp_fd, const char *passwd)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	return c_smartcard_token_unlock_handler(smartcard, resp_fd, passwd, c_smartcard_cb_start_container);
}

static int
c_smartcard_container_stop(void *smartcardp, int resp_fd, const char *passwd)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	return c_smartcard_token_unlock_handler(smartcard, resp_fd, passwd, c_smartcard_cb_stop_container);
}

static void *
c_smartcard_new(container_t *container)
{
	ASSERT(container);

	c_smartcard_t *smartcard = mem_new0(c_smartcard_t, 1);
	smartcard->container = container;
	smartcard->path = cmld_get_wrapped_keys_dir();

	smartcard->sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
	if (smartcard->sock < 0) {
		mem_free0(smartcard);
		ERROR("Failed to connect to scd");
		return NULL;
	}
	return smartcard;
}

static int
c_smartcard_stop(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	return close(smartcard->sock);
}

static void
c_smartcard_free(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	IF_NULL_RETURN(smartcard);
	mem_free0(smartcard);
}

static int
c_smartcard_container_destroy(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	int ret = 0;
	char *path = c_smartcard_token_paired_file_new(smartcard);
	if (file_exists(path)) {
		ret = unlink(path);
		if (ret != 0) {
			ERROR_ERRNO("Failed to remove file %s", path);
		}
	}
	mem_free0(path);
	return ret;
}

static int
c_smartcard_bind_token(c_smartcard_t *smartcard)
{
	ASSERT(smartcard);

	if (CONTAINER_TOKEN_TYPE_USB != container_get_token_type(smartcard->container)) {
		DEBUG("Token type is not USB, not binding relay socket");
		return 0;
	}

	int ret = -1;
	uid_t uid = container_get_uid(smartcard->container);

	char *src_path = mem_printf("%s/%s.sock", SCD_TOKENCONTROL_SOCKET,
				    uuid_string(container_get_uuid(smartcard->container)));
	char *dest_dir = mem_printf("%s/dev/tokens", container_get_rootdir(smartcard->container));
	char *dest_path = mem_printf("%s/token.sock", dest_dir);

	DEBUG("Binding token socket to %s", dest_path);

	if (!file_exists(dest_dir)) {
		if (dir_mkdir_p(dest_dir, 0755)) {
			ERROR_ERRNO("Failed to create containing directory for %s", dest_path);
			goto err;
		}

		if (chown(dest_dir, uid, uid)) {
			ERROR("Failed to chown token directory at %s to %d", dest_path, uid);
			goto err;
		} else {
			DEBUG("Successfully chowned token directory at %s to %d", dest_path, uid);
		}
	} else if (!file_is_dir(dest_dir)) {
		ERROR("Token path %s exists and is no directory", dest_dir);
		goto err;
	}

	if (file_touch(dest_path)) {
		ERROR_ERRNO("Failed to prepare target file for bind mount at %s", dest_path);
		goto err;
	}

	DEBUG("Binding token socket from %s to %s", src_path, dest_path);
	if (mount(src_path, dest_path, NULL, MS_BIND, NULL)) {
		ERROR_ERRNO("Failed to bind socket from %s to %s", src_path, dest_path);
		goto err;
	} else {
		DEBUG("Successfully bound token socket to %s", dest_path);
	}

	if (chown(dest_path, uid, uid)) {
		ERROR("Failed to chown token socket at %s to %d", dest_path, uid);
		goto err;
	} else {
		DEBUG("Successfully chowned token socket at %s to %d", dest_path, uid);
	}

	ret = 0;

err:
	mem_free0(src_path);
	mem_free0(dest_dir);
	mem_free0(dest_path);

	return ret;
}

/**
 * Start-pre-exec hook.
 *
 * @param smartcardp The generic smartcard object of the associated container.
 * @return 0 on success, -CONTAINER_ERROR_SMARTCARD on error.
 */
static int
c_smartcard_start_pre_exec(void *smartcardp)
{
	c_smartcard_t *smartcard = smartcardp;
	ASSERT(smartcard);

	if (c_smartcard_bind_token(smartcard) < 0) {
		ERROR("Failed to bind token to container");
		return -CONTAINER_ERROR_SERVICE;
	}

	return 0;
}

static container_module_t c_smartcard_module = {
	.name = MOD_NAME,
	.container_new = c_smartcard_new,
	.container_free = c_smartcard_free,
	.container_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_smartcard_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = c_smartcard_stop,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_smartcard_init(void)
{
	// register this module in container.c
	container_register_module(&c_smartcard_module);

	// register relevant handlers implemented by this module
	container_register_start_with_smartcard_handler(MOD_NAME, c_smartcard_container_start);
	container_register_stop_with_smartcard_handler(MOD_NAME, c_smartcard_container_stop);
	container_register_scd_token_add_block_handler(MOD_NAME, c_smartcard_scd_token_add_block);
	container_register_scd_token_remove_block_handler(MOD_NAME,
							  c_smartcard_scd_token_remove_block);
	container_register_scd_release_pairing_handler(MOD_NAME, c_smartcard_container_destroy);
	container_register_update_token_state_handler(MOD_NAME, c_smartcard_update_token_state);
	container_register_change_pin_handler(MOD_NAME, c_smartcard_change_pin);
	container_register_remove_keyfile_handler(MOD_NAME, c_smartcard_remove_keyfile);
}
