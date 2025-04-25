/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include "control.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/tpm2d/tpm2d.pb-c.h"
#else
#include "tpm2d.pb-c.h"
#endif

#include "tpm2d.h"
#include "nvmcrypt.h"
#include "ml.h"
#include "ek.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/list.h"
#include "common/file.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"

#include <google/protobuf-c/protobuf-c-text.h>

// maximum no. of connections waiting to be accepted on the listening socket
#define TPM2D_CONTROL_SOCK_LISTEN_BACKLOG 8

struct tpm2d_control {
	int sock; // listen socket fd
};

UNUSED static list_t *control_list = NULL;

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
static TpmToController__GenericResponse
tpm2d_control_resp_to_proto(control_generic_response_t resp)
{
	switch (resp) {
	case CMD_OK:
		return TPM_TO_CONTROLLER__GENERIC_RESPONSE__CMD_OK;
	case CMD_FAILED:
		return TPM_TO_CONTROLLER__GENERIC_RESPONSE__CMD_FAILED;
	default:
		FATAL("Unhandled value for control_generic_response_t: %d", resp);
	}
}

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
static TpmToController__FdeResponse
tpm2d_control_fdestate_to_proto(nvmcrypt_fde_state_t state)
{
	switch (state) {
	case FDE_OK:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_OK;
	case FDE_AUTH_FAILED:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_AUTH_FAILED;
	case FDE_KEYGEN_FAILED:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_KEYGEN_FAILED;
	case FDE_NO_DEVICE:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_NO_DEVICE;
	case FDE_KEY_ACCESS_LOCKED:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_KEY_ACCESS_LOCKED;
	case FDE_RESET:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_RESET;
	case FDE_UNEXPECTED_ERROR:
		return TPM_TO_CONTROLLER__FDE_RESPONSE__FDE_UNEXPECTED_ERROR;
	default:
		FATAL("Unhandled value for nvmcrypt_fde_state_t: %d", state);
	}
}

static TPM_ALG_ID
tpm2d_control_get_algid_from_proto(HashAlgLen hash_alg_len)
{
	INFO("Get algid for hash_len: %d", hash_alg_len);

	switch (hash_alg_len) {
	case HASH_ALG_LEN__SHA1:
		return TPM_ALG_SHA1;
	case HASH_ALG_LEN__SHA256:
		return TPM_ALG_SHA256;
	case HASH_ALG_LEN__SHA384:
		return TPM_ALG_SHA384;
	default:
		ERROR("Unsupported value for HashAlgLen: %d", hash_alg_len);
		return TPM_ALG_NULL;
	}
}

static int
tpm2d_control_get_fdekeylen_from_proto(ControllerToTpm__FdeKeyType type)
{
	switch (type) {
	case CONTROLLER_TO_TPM__FDE_KEY_TYPE__XTS_AES128:
		return 32;
	case CONTROLLER_TO_TPM__FDE_KEY_TYPE__XTS_AES192:
		return 48;
	case CONTROLLER_TO_TPM__FDE_KEY_TYPE__XTS_AES256:
		return 64;
	default:
		WARN("Unsupported value for FdeKeyType: %d, using default (XTS-AES256)", type);
		return 64;
	}
}

static void
tpm2d_control_handle_message(const ControllerToTpm *msg, int fd, tpm2d_control_t *control)
{
	ASSERT(control);

	TRACE("Handle message from client fd=%d", fd);

	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text;
		size_t msg_len =
			protobuf_string_from_message(&msg_text, (ProtobufCMessage *)msg, NULL);
		TRACE("Handling ControllerToTpm message:\n%s", msg_len > 0 ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	tss2_init();

	switch (msg->code) {
	case CONTROLLER_TO_TPM__CODE__DMCRYPT_SETUP: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__FDE_RESPONSE;
		out.has_fde_response = true;
		nvmcrypt_fde_state_t state = nvmcrypt_dm_setup(msg->dmcrypt_device, msg->password);
		out.fde_response = tpm2d_control_fdestate_to_proto(state);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case CONTROLLER_TO_TPM__CODE__EXIT: {
		INFO("Received EXIT command!");
		tpm2d_exit();
	} break;
	case CONTROLLER_TO_TPM__CODE__RANDOM_REQ: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__RANDOM_RESPONSE;
		uint8_t *rand = tpm2_getrandom_new(msg->rand_size);
		char *rand_hex = convert_bin_to_hex_new(rand, msg->rand_size);
		out.rand_data = rand_hex;
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
		if (rand)
			mem_free0(rand);
		if (rand_hex)
			mem_free0(rand_hex);
	} break;
	case CONTROLLER_TO_TPM__CODE__CLEAR: {
		INFO("Received Clear command!");
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__GENERIC_RESPONSE;
		out.has_response = true;
		int ret = tpm2_clear(msg->password);
		ret |= tpm2_dictionaryattacklockreset(msg->password);
		out.response = tpm2d_control_resp_to_proto(ret ? CMD_FAILED : CMD_OK);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case CONTROLLER_TO_TPM__CODE__DMCRYPT_LOCK: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__FDE_RESPONSE;
		out.has_fde_response = true;
		nvmcrypt_fde_state_t state = nvmcrypt_dm_lock(msg->password);
		out.fde_response = tpm2d_control_fdestate_to_proto(state);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case CONTROLLER_TO_TPM__CODE__CHANGE_OWNER_PWD: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__GENERIC_RESPONSE;
		out.has_response = true;
		int ret = tpm2_hierarchychangeauth(TPM_RH_OWNER, msg->password, msg->password_new);
		out.response = tpm2d_control_resp_to_proto(ret ? CMD_FAILED : CMD_OK);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case CONTROLLER_TO_TPM__CODE__DMCRYPT_RESET: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__FDE_RESPONSE;
		out.has_fde_response = true;
		nvmcrypt_fde_state_t state = nvmcrypt_dm_reset(msg->password);
		out.fde_response = tpm2d_control_fdestate_to_proto(state);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	case CONTROLLER_TO_TPM__CODE__ML_APPEND: {
		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__GENERIC_RESPONSE;
		out.has_response = true;
		int ret = ml_measurement_list_append(
			msg->ml_filename, tpm2d_control_get_algid_from_proto(msg->ml_hashalg),
			msg->ml_datahash.data, msg->ml_datahash.len);
		out.response = tpm2d_control_resp_to_proto(ret ? CMD_FAILED : CMD_OK);
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
	} break;
	default:
		WARN("ControllerToTpm command %d unknown or not implemented yet", msg->code);
		break;
	}
	tss2_destroy();
}

/**
 * Event callback for incoming data that a ControllerToTpm message.
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd	    file descriptor of the client connection
 *		    from which the incoming message is read
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this tpm2d_control_t struct
 */
static void
tpm2d_control_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_control_t *control = data;
	ASSERT(control);

	if (events & EVENT_IO_READ) {
		ControllerToTpm *msg = (ControllerToTpm *)protobuf_recv_message(
			fd, &controller_to_tpm__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		tpm2d_control_handle_message(msg, fd, control);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled control connection %d", fd);
	}
	if (events & EVENT_IO_EXCEPT) {
		INFO("Client closed connection; disconnecting control socket.");
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
 * @param data	    pointer to this tpm2d_control_t struct
  */
static void
tpm2d_control_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_control_t *control = data;
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

	event_io_t *event =
		event_io_new(cfd, EVENT_IO_READ, tpm2d_control_cb_recv_message, control);
	event_add_io(event);
}

static event_io_t *event;

tpm2d_control_t *
tpm2d_control_new(const char *path)
{
	int sock = sock_unix_create_and_bind(SOCK_STREAM | SOCK_NONBLOCK, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	if (listen(sock, TPM2D_CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	tpm2d_control_t *tpm2d_control = mem_new0(tpm2d_control_t, 1);
	tpm2d_control->sock = sock;

	event = event_io_new(sock, EVENT_IO_READ, tpm2d_control_cb_accept, tpm2d_control);
	event_add_io(event);

	return tpm2d_control;
}

void
tpm2d_control_free(tpm2d_control_t *control)
{
	event_remove_io(event);
	event_io_free(event);
	mem_free0(control);
}
