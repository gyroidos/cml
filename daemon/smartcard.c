/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#include "scd.pb-c.h"

#include "smartcard.h"
#include "hardware.h"
#include "control.h"
#include "audit.h"
#include "scd_shared.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/proc.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

// clang-format off
#define SCD_CONTROL_SOCKET SOCK_PATH(scd-control)
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

struct smartcard {
	int sock;
	char *path;
	pid_t scd_pid;
};

typedef struct smartcard_startdata {
	smartcard_t *smartcard;
	container_t *container;
	int resp_fd;
} smartcard_startdata_t;

typedef struct smartcard_scdtoken_data {
	smartcard_t *smartcard;
	container_t *container;
	char *token_uuid;
} smartcard_scdtoken_data_t;

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
smartcard_tokentype_to_proto(container_token_type_t tokentype)
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
smartcard_get_pairing_secret(smartcard_t *smartcard, unsigned char *buf, int buf_len)
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
smartcard_send_recv_block(const DaemonToToken *out)
{
	ASSERT(out);

	int sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
	if (sock < 0) {
		ERROR_ERRNO("Failed to connect to scd control socket %s", SCD_CONTROL_SOCKET);
		return NULL;
	}

	DEBUG("smartcard_send_recv_block: connected to sock %d", sock);

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
smartcard_token_paired_file_new(const container_t *container)
{
	return mem_printf("%s/%s", container_get_images_dir(container), TOKEN_IS_PAIRED_FILE_NAME);
}

/**
 * checks whether the token associated to @param container has been provisioned
 * with a device bound authentication code yet.
 * TODO: this should actually query the SCD. Functionality in SCD not yet implemented.
 */
bool
smartcard_container_token_is_provisioned(const container_t *container)
{
	ASSERT(container);

	bool ret;

	char *token_init_file = smartcard_token_paired_file_new(container);

	ret = file_exists(token_init_file);

	mem_free0(token_init_file);
	return ret;
}

static void
smartcard_start_container_internal(smartcard_startdata_t *startdata)
{
	ASSERT(startdata);

	if (NULL == container_get_key(startdata->container)) {
		FATAL("No container key is set.");
	}

	// backward compatibility: convert binary key to ascii (to have it converted back later)
	DEBUG("SCD:Container  %s: Starting...", container_get_name(startdata->container));
	if (-1 == cmld_container_start(startdata->container))
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL,
				     startdata->resp_fd);
	else
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_OK, startdata->resp_fd);
}

static void
smartcard_stop_container_internal(smartcard_startdata_t *startdata)
{
	ASSERT(startdata);

	int res = cmld_container_stop(startdata->container);

	// TODO if the modules cannot be stopped successfully, the container is killed. The return
	// value in this case is CONTAINER_ERROR, even if the container was killed. This is
	// ignored atm and just STOP_OK is returned. How should we treat this?
	if (res == -1) {
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_FAILED_NOT_RUNNING,
				     startdata->resp_fd);
	} else {
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_OK, startdata->resp_fd);
	}
}

static void
smartcard_cb_start_container(int fd, unsigned events, event_io_t *io, void *data)
{
	smartcard_startdata_t *startdata = data;
	bool done = false;

	if (events & EVENT_IO_EXCEPT) {
		ERROR("Container start failed");

		event_remove_io(io);
		event_io_free(io);
		mem_free0(startdata);
		return;
	} else if (events & EVENT_IO_READ) {
		// use protobuf for communication with scd
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting container start.");

			event_remove_io(io);
			event_io_free(io);
			mem_free0(startdata);
			return;
		}

		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__LOCK_FAILED: {
			audit_log_event(container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "lock",
					uuid_string(container_get_uuid(startdata->container)), 0);
			WARN("Locking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED,
					     startdata->resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
			if (container_get_key(startdata->container))
				smartcard_start_container_internal(startdata);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
			audit_log_event(container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "unlock",
					uuid_string(container_get_uuid(startdata->container)), 0);
			WARN("Unlocking the token failed.");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED,
					     startdata->resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
			WARN("Unlocking the token failed (wrong PIN/passphrase).");
			audit_log_event(container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "unlock-wrong-pin",
					uuid_string(container_get_uuid(startdata->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG,
					     startdata->resp_fd);
			done = true;
		} break;
		case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
			WARN("Unlocking the token failed (locked till reboot).");
			audit_log_event(container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "locked-until-reboot",
					uuid_string(container_get_uuid(startdata->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT,
					     startdata->resp_fd);
			done = true;
		} break;

		/*
		 * This case handles key unwrapping as part of TSF.CML.CompartmentDataStorage.
		 */
		case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
			audit_log_event(container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "unlock-successful",
					uuid_string(container_get_uuid(startdata->container)), 0);
			char *keyfile =
				mem_printf("%s/%s.key", startdata->smartcard->path,
					   uuid_string(container_get_uuid(startdata->container)));
			if (file_exists(keyfile)) {
				DEBUG("Using key for container %s from existing key file %s",
				      container_get_name(startdata->container), keyfile);
				unsigned char key[TOKEN_MAX_WRAPPED_KEY_LEN];
				int keylen = file_read(keyfile, (char *)key, sizeof(key));
				DEBUG("Length of existing key: %d", keylen);
				if (keylen < TOKEN_KEY_LEN) {
					audit_log_event(container_get_uuid(startdata->container),
							FSA, CMLD, TOKEN_MGMT, "read-wrapped-key",
							uuid_string(container_get_uuid(
								startdata->container)),
							0);
					ERROR("Failed to read key from file for container!");
					break;
				}

				audit_log_event(
					container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "read-wrapped-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
				// unwrap via scd
				DaemonToToken out = DAEMON_TO_TOKEN__INIT;
				out.code = DAEMON_TO_TOKEN__CODE__UNWRAP_KEY;
				out.has_wrapped_key = true;
				out.wrapped_key.len = keylen;
				out.wrapped_key.data = key;
				out.container_uuid = mem_strdup(
					uuid_string(container_get_uuid(startdata->container)));

				out.has_token_type = true;
				out.token_type = smartcard_tokentype_to_proto(
					container_get_token_type(startdata->container));

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(startdata->container)));

				protobuf_send_message(startdata->smartcard->sock,
						      (ProtobufCMessage *)&out);

				//delete wrapped key from RAM
				mem_memset0(key, sizeof(key));
				mem_free0(out.container_uuid);
				mem_free0(out.token_uuid);
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
					audit_log_event(container_get_uuid(startdata->container),
							FSA, CMLD, TOKEN_MGMT,
							"gen-container-key-rng-error",
							uuid_string(container_get_uuid(
								startdata->container)),
							0);
					ERROR("Failed to generate key for container, due to RNG Error!");
					break;
				}
				audit_log_event(
					container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "gen-container-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
				// set the key
				char *ascii_key = bytes_to_string_new(key, keylen);
				container_set_key(startdata->container, ascii_key);
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
					uuid_string(container_get_uuid(startdata->container)));

				out.has_token_type = true;
				out.token_type = smartcard_tokentype_to_proto(
					container_get_token_type(startdata->container));

				out.token_uuid = mem_strdup(
					uuid_string(container_get_uuid(startdata->container)));

				protobuf_send_message(startdata->smartcard->sock,
						      (ProtobufCMessage *)&out);

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
			out.token_type = smartcard_tokentype_to_proto(
				container_get_token_type(startdata->container));

			out.token_uuid =
				mem_strdup(uuid_string(container_get_uuid(startdata->container)));

			protobuf_send_message(startdata->smartcard->sock, (ProtobufCMessage *)&out);
			mem_free0(out.token_uuid);
			if (!msg->has_unwrapped_key) {
				WARN("Expected derived key, but none was returned!");
				audit_log_event(
					container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
				control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL,
						     startdata->resp_fd);
				break;
			}
			// set the key
			audit_log_event(container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "unwrap-container-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
			TRACE("Successfully retrieved unwrapped key from SCD");
			char *ascii_key = bytes_to_string_new(msg->unwrapped_key.data,
							      msg->unwrapped_key.len);
			container_set_key(startdata->container, ascii_key);
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
			out.token_type = smartcard_tokentype_to_proto(
				container_get_token_type(startdata->container));

			out.token_uuid =
				mem_strdup(uuid_string(container_get_uuid(startdata->container)));

			protobuf_send_message(startdata->smartcard->sock, (ProtobufCMessage *)&out);
			mem_free0(out.token_uuid);
			// save wrapped key
			if (!msg->has_wrapped_key) {
				audit_log_event(
					container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
				WARN("Expected wrapped key, but none was returned!");
				break;
			}
			ASSERT(msg->wrapped_key.len < TOKEN_MAX_WRAPPED_KEY_LEN);
			audit_log_event(container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "wrap-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
			char *keyfile =
				mem_printf("%s/%s.key", startdata->smartcard->path,
					   uuid_string(container_get_uuid(startdata->container)));
			// save wrapped key to file
			int bytes_written = file_write(keyfile, (char *)msg->wrapped_key.data,
						       msg->wrapped_key.len);
			if (bytes_written != (int)msg->wrapped_key.len) {
				audit_log_event(
					container_get_uuid(startdata->container), FSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
				ERROR("Failed to store key for container %s to %s!",
				      container_get_name(startdata->container), keyfile);
			}
			audit_log_event(container_get_uuid(startdata->container), SSA, CMLD,
					TOKEN_MGMT, "store-wrapped-key",
					uuid_string(container_get_uuid(startdata->container)), 0);
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
			mem_free0(startdata);
		}
	}
}

static void
smartcard_cb_stop_container(int fd, unsigned events, event_io_t *io, void *data)
{
	smartcard_startdata_t *startdata = data;

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
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_LOCK_FAILED,
				     startdata->resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__LOCK_SUCCESSFUL: {
		smartcard_stop_container_internal(startdata);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__UNLOCK_FAILED: {
		WARN("Unlocking the token failed.");
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_UNLOCK_FAILED,
				     startdata->resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__PASSWD_WRONG: {
		WARN("Unlocking the token failed (wrong PIN/passphrase).");
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_PASSWD_WRONG,
				     startdata->resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__LOCKED_TILL_REBOOT: {
		WARN("Unlocking the token failed (locked till reboot).");
		control_send_message(CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT,
				     startdata->resp_fd);
		goto exit;
	} break;
	case TOKEN_TO_DAEMON__CODE__UNLOCK_SUCCESSFUL: {
		// lock token via scd
		DaemonToToken out = DAEMON_TO_TOKEN__INIT;
		out.code = DAEMON_TO_TOKEN__CODE__LOCK;

		out.has_token_type = true;
		out.token_type = smartcard_tokentype_to_proto(
			container_get_token_type(startdata->container));

		out.token_uuid = mem_strdup(uuid_string(container_get_uuid(startdata->container)));

		protobuf_send_message(startdata->smartcard->sock, (ProtobufCMessage *)&out);
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
	mem_free0(startdata);
	return;
}

int
smartcard_container_ctrl_handler(smartcard_t *smartcard, container_t *container, int resp_fd,
				 const char *passwd, cmld_container_ctrl_t container_ctrl)
{
	ASSERT(smartcard);
	ASSERT(container);
	ASSERT(passwd);

	smartcard_startdata_t *startdata = mem_alloc(sizeof(smartcard_startdata_t));
	if (!startdata) {
		ERROR("Could not allocate memory for startdata");
		return -1;
	}
	startdata->smartcard = smartcard;
	startdata->container = container;
	startdata->resp_fd = resp_fd;

	int pair_sec_len;

	if (!container_get_token_is_init(container)) {
		audit_log_event(container_get_uuid(startdata->container), FSA, CMLD, TOKEN_MGMT,
				"token-uninitialized",
				uuid_string(container_get_uuid(startdata->container)), 0);
		ERROR("The token that is associated with the container has not been initialized!");
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNINITIALIZED, resp_fd);
		goto err;
	}

	if (!container_get_token_is_linked_to_device(container)) {
		ERROR("The token that is associated with this container must be paired to the device first");
		audit_log_event(container_get_uuid(startdata->container), FSA, CMLD, TOKEN_MGMT,
				"token-not-paired",
				uuid_string(container_get_uuid(startdata->container)), 0);
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNPAIRED, resp_fd);
		goto err;
	}

	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	pair_sec_len = smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (pair_sec_len < 0) {
		audit_log_event(container_get_uuid(startdata->container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret",
				uuid_string(container_get_uuid(startdata->container)), 0);
		ERROR("Could not retrieve pairing secret");
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, resp_fd);
		goto err;
	}
	audit_log_event(container_get_uuid(startdata->container), SSA, CMLD, TOKEN_MGMT,
			"read-pairing-secret",
			uuid_string(container_get_uuid(startdata->container)), 0);

	// TODO register timer if socket does not respond
	event_io_t *event = NULL;
	if (container_ctrl == CMLD_CONTAINER_CTRL_START) {
		event = event_io_new(smartcard->sock, EVENT_IO_READ, smartcard_cb_start_container,
				     startdata);
	} else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP) {
		event = event_io_new(smartcard->sock, EVENT_IO_READ, smartcard_cb_stop_container,
				     startdata);
	} else {
		ERROR("Unknown container control command %u", container_ctrl);
		control_send_message(CONTROL_RESPONSE_CONTAINER_CTRL_EINTERNAL, resp_fd);
		goto err;
	}
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
		smartcard_tokentype_to_proto(container_get_token_type(startdata->container));

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(startdata->container)));

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
	mem_free0(startdata);
	return -1;
}

static void
smartcard_cb_container_change_pin(int fd, unsigned events, event_io_t *io, void *data)
{
	smartcard_startdata_t *startdata = data;
	int rc = -1;
	bool command_state = false;

	if (events & EVENT_IO_READ) {
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
		if (!msg) {
			ERROR("Failed to receive message although EVENT_IO_READ was set. Aborting smartcard change_pin callback.");
			event_remove_io(io);
			event_io_free(io);
			audit_log_event(container_get_uuid(startdata->container), FSA, CMLD,
					CONTAINER_MGMT, "container-change-pin",
					uuid_string(container_get_uuid(startdata->container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED,
					     startdata->resp_fd);
			mem_free0(startdata);
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
			char *path = smartcard_token_paired_file_new(startdata->container);
			rc = file_touch(path);
			if (rc != 0) { //should never happen
				ERROR("Could not write file %s to flag that container %s's token has been initialized\n \
						This may leave the system in an inconsistent state!",
				      path, uuid_string(container_get_uuid(startdata->container)));
				container_set_token_is_linked_to_device(startdata->container,
									false);
				command_state = false;
			} else {
				container_set_token_is_linked_to_device(startdata->container, true);
				command_state = true;
			}
			mem_free0(path);
		} break;
		case TOKEN_TO_DAEMON__CODE__PROVISION_PIN_FAILED: {
			container_set_token_is_linked_to_device(startdata->container, false);
			command_state = false;
		} break;
		default:
			ERROR("TokenToDaemon command %d not expected as answer to change_pin",
			      msg->code);
			command_state = false;
		}

		audit_log_event(container_get_uuid(startdata->container), command_state ? SSA : FSA,
				CMLD, CONTAINER_MGMT, "container-change-pin",
				uuid_string(container_get_uuid(startdata->container)), 0);
		control_send_message(command_state ?
					     CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_SUCCESSFUL :
					     CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED,
				     startdata->resp_fd);

		protobuf_free_message((ProtobufCMessage *)msg);
		event_remove_io(io);
		event_io_free(io);
		mem_free0(startdata);
	} else {
		ERROR("Failed to receive message: EVENT_IO_EXCEPT. Aborting smartcard change_pin.");
		event_remove_io(io);
		event_io_free(io);
		mem_free0(startdata);
	}
}

int
smartcard_container_change_pin(smartcard_t *smartcard, container_t *container, int resp_fd,
			       const char *passwd, const char *newpasswd)
{
	ASSERT(smartcard);
	ASSERT(container);
	ASSERT(passwd);
	ASSERT(newpasswd);

	int ret = -1;
	unsigned char pair_sec[MAX_PAIR_SEC_LEN];
	bool is_provisioning;

	smartcard_startdata_t *startdata = mem_alloc0(sizeof(smartcard_startdata_t));
	if (!startdata) {
		ERROR("Could not allocate memory for startdata");
		return -1;
	}
	startdata->smartcard = smartcard;
	startdata->container = container;
	startdata->resp_fd = resp_fd;

	DEBUG("SCD: Received new password from UI");

	ret = smartcard_get_pairing_secret(smartcard, pair_sec, sizeof(pair_sec));
	if (ret < 0) {
		audit_log_event(container_get_uuid(container), FSA, CMLD, TOKEN_MGMT,
				"read-pairing-secret", uuid_string(container_get_uuid(container)),
				0);
		ERROR("Could not retrieve pairing secret, ret code : %d", ret);
		control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED, resp_fd);
		mem_free0(startdata);
		return -1;
	}

	is_provisioning = !smartcard_container_token_is_provisioned(container);

	event_io_t *event = event_io_new(smartcard->sock, EVENT_IO_READ,
					 smartcard_cb_container_change_pin, startdata);
	event_add_io(event);
	DEBUG("SCD: Registered smartcard_cb_container_change_pin container callback for scd");

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = is_provisioning ? DAEMON_TO_TOKEN__CODE__PROVISION_PIN :
				     DAEMON_TO_TOKEN__CODE__CHANGE_PIN;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(startdata->container)));

	out.has_token_type = true;
	out.token_type =
		smartcard_tokentype_to_proto(container_get_token_type(startdata->container));

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

int
smartcard_update_token_state(container_t *container)
{
	ASSERT(container);

	/* TODO: query SCD whether a token has been initialized.
	 * requires modifications to SCD
	 */
	// container_set_token_is_init(container, smartcard_container_token_is_init(container));

	container_set_token_is_linked_to_device(
		container, smartcard_container_token_is_provisioned(container));

	DEBUG("Updated Token state: %d", container_get_token_is_linked_to_device(container));

	return 0;
}

/**
 * we cannot queue several events with the same fd.
 * therefore, we use a blocking method to query the scd to initialize a token.
 */
int
smartcard_scd_token_add_block(container_t *container)
{
	TRACE("CML: request SCD to add the token associated to %s to its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	int rc = -1;

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_ADD;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = smartcard_tokentype_to_proto(container_get_token_type(container));

	if (out.token_type == TOKEN_TYPE__USB) {
		out.usbtoken_serial = container_get_usbtoken_serial(container);
		if (NULL == out.usbtoken_serial) {
			ERROR("Could not retrive serial of usbtoken reader. Abort token init...");
			goto err;
		}
	}

	TokenToDaemon *msg = smartcard_send_recv_block(&out);
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

int
smartcard_scd_token_remove_block(container_t *container)
{
	TRACE("CML: request scd to remove the token associated to %s from its list",
	      uuid_string(container_get_uuid(container)));
	ASSERT(container);

	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__TOKEN_REMOVE;

	out.token_uuid = mem_strdup(uuid_string(container_get_uuid(container)));

	out.has_token_type = true;
	out.token_type = smartcard_tokentype_to_proto(container_get_token_type(container));

	TokenToDaemon *msg = smartcard_send_recv_block(&out);
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

int
smartcard_remove_keyfile(smartcard_t *smartcard, const container_t *container)
{
	ASSERT(smartcard);
	ASSERT(container);

	int rc = -1;

	char *keyfile = mem_printf("%s/%s.key", smartcard->path,
				   uuid_string(container_get_uuid(container)));

	if (!file_exists(keyfile)) {
		DEBUG("No keyfile found for container %s (uuid=%s).", container_get_name(container),
		      uuid_string(container_get_uuid(container)));
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

static pid_t
fork_and_exec_scd(void)
{
	TRACE("Starting scd..");

	int status;
	pid_t pid = fork();
	char *const param_list[] = { SCD_BINARY_NAME, NULL };

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", SCD_BINARY_NAME);
		return -1;
	case 0:
		execvp((const char *)param_list[0], param_list);
		FATAL_ERRNO("Could not execvp %s", SCD_BINARY_NAME);
		return -1;
	default:
		// Just check if the child is alive but do not wait
		if (waitpid(pid, &status, WNOHANG) != 0) {
			ERROR("Failed to start %s", SCD_BINARY_NAME);
			return -1;
		}
		return pid;
	}
	return -1;
}

smartcard_t *
smartcard_new(const char *path)
{
	ASSERT(path);

	// if device.cert is not present, start scd to initialize device (provisioning mode)
	if (!file_exists(DEVICE_CERT_FILE)) {
		INFO("Starting scd in Provisioning / Installing Mode");
		// Start the SCD in provisioning mode
		const char *const args[] = { SCD_BINARY_NAME, NULL };
		IF_FALSE_RETVAL_TRACE(proc_fork_and_execvp(args) == 0, NULL);
	}

	smartcard_t *smartcard = mem_alloc(sizeof(smartcard_t));
	smartcard->path = mem_strdup(path);

	// Start SCD and wait for control interface
	if (!cmld_is_hostedmode_active()) {
		smartcard->scd_pid = fork_and_exec_scd();
	}

	IF_TRUE_RETVAL_TRACE(smartcard->scd_pid == -1, NULL);

	size_t retries = 0;
	do {
		NANOSLEEP(0, 500000000)
		smartcard->sock = sock_unix_create_and_connect(SOCK_SEQPACKET, SCD_CONTROL_SOCKET);
		retries++;
		TRACE("Retry %zu connecting to scd", retries);
	} while (smartcard->sock < 0 && retries < 10);

	if (smartcard->sock < 0) {
		mem_free0(smartcard);
		ERROR("Failed to connect to scd");
		return NULL;
	}

	// allow access from namespaced child before chroot and execv of init
	if (chmod(SCD_CONTROL_SOCKET, 00777))
		WARN("could not change access rights for scd control socket");

	return smartcard;
}

static void
smartcard_scd_stop(smartcard_t *smartcard)
{
	DEBUG("Stopping %s process with pid=%d!", SCD_BINARY_NAME, smartcard->scd_pid);
	kill(smartcard->scd_pid, SIGTERM);
}

void
smartcard_free(smartcard_t *smartcard)
{
	IF_NULL_RETURN(smartcard);

	smartcard_scd_stop(smartcard);

	mem_free0(smartcard->path);
	mem_free0(smartcard);
}

int
smartcard_release_pairing(container_t *container)
{
	int ret = 0;
	char *path = smartcard_token_paired_file_new(container);
	if (file_exists(path)) {
		ret = unlink(path);
		if (ret != 0) {
			ERROR_ERRNO("Failed to remove file %s", path);
		}
	}
	mem_free0(path);
	return ret;
}
