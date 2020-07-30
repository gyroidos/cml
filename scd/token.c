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

#include "token.h"

#include "tokencontrol.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/uuid.h"
#include "common/protobuf.h"
#include "common/list.h"
#include "file.h"

// clang-format off
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(token-control)
// clang-format on

#define SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG 8 //TODO

typedef struct scd_tokencontrol {
	int sock;
	// need to keep track of registered events and active sockets for deallocation
	list_t *events;
	list_t *sockets;
} tctrl_t;

struct scd_token_data {
	union {
		softtoken_t *softtoken;
		usbtoken_t *usbtoken;
	} int_token;

	scd_tokentype_t type;
	uuid_t *token_uuid;
	tctrl_t *tctrl;
};

static void
scd_tokencontrol_handle_message(const ContainerToToken *msg, int fd, void *data)
{
	ASSERT(msg);
	ASSERT(data);

	scd_token_t *t = (scd_tokencontrol_t *)(data);
	tctrl_t *tctrl = token->tctrl;

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

	// TODO: need to ensure that the token has not been freed in the meantime!!
	// BUT HOW?! Cannot set the token pointer to NULL with the current architecture and mem_free implementation :/
	if (tctrl->sock <= 0) {
		ERROR("Cannot handle tokencontrol message; socket is not available");
		goto err;
	}

	switch (msg->code) {
	case GET_ATR:
		//TODO: implement get_atr function (might just be requestICC, should be clarified with Andreas)
		int rc = t->get_atr(t);
		break;

		break;
	case UNLOCK_TOKEN:
		//TODO: implement reset function  that uses cached auth token
		int rc = t->reset(t);
		break;

	case SEND_APDU:
		//TODO: implement relay_apdu function
		int rc = t->relay_apdu(t, msg->apdu.data, msg->apdu.len);
		break;

	default:
		WARN("ContainerToToken command %d unknown or not implemented yet", msg->code);
	}

err:
	TokenToContainer out = TOKEN_TO_DAEMON__INIT;
	out.code = TOKEN_TO_Container__CODE__ERR_INVALID;
	protobuf_send_message(fd, (ProtobufCMessage *)&out);

close_fd:
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
	return;
}

/**
 * Event callback for incoming data that a ContainerToToken message.
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
scd_control_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	if (events & EVENT_IO_READ) {
		ContainerToToken *msg = (ContainerToToken *)protobuf_recv_message(
			fd, &cotnainer_to_token__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		scd_tokencontrol_handle_message(msg, fd, data);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled control connection %d", fd);
	}
	if (events & EVENT_IO_EXCEPT) {
		INFO("TokenControl client closed connection; disconnecting socket.");
		goto connection_err;
	}
	return;

connection_err:
	scd_token_t *token = (scd_token_t *)(data);

	token->scd_tokencontrol->events = list_unlink(token->scd_tokencontrol->events, io);
	event_remove_io(io);
	event_io_free(io);

	token->scd_tokencontrol->socekts = list_unlink(token->scd_tokencontrol->sockets, fd);
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
scd_tokencontrol_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept tokencontrol connection");
		return;
	}
	DEBUG("Accepted control tokenconnection %d", cfd);
	list_append(token->scd_tokencontrol->sockets, cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event =
		event_io_new(cfd, EVENT_IO_READ, scd_tokencontrol_cb_recv_message, data);

	list_append(token->scd_tokencontrol->events, event);

	event_add_io(event);
}

static int
scd_tokencontrol_new(const char *path, scd_token_t *token)
{
	int sock = sock_unix_create_and_bind(SOCK_SEQPACKET | SOCK_NONBLOCK, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return -1;
	}
	if (listen(sock, SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		close(sock);
		return -1;
	}

	token->scd_tokencontrol = mem_new0(struct scd_tokencontrol, 1);
	if (NULL == token->scd_tokencontrol) {
		// TODO
		ERROR("");
		goto err;
	}
	token->scd_tokencontrol->sock = sock;
	list_append(token->scd_tokencontrol->sockets, cfd);

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, scd_tokencontrol_cb_accept, token);
	list_append(token->scd_tokencontrol->events, event);
	event_add_io(event);

	return 0;
}

static void
wrapped_remove_event_io(void *elem)
{
	ASSERT(elem);
	event_io_t *e = elem;
	event_remove_io(e);
	event_io_free(e);
}

static void
wrapped_close_socket(void *elem)
{
	ASSERT(elem);
	int fd = *elem;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
}

static void
scd_tokencontrol_free(scd_token_t *token)
{
	ASSERT(token);

	list_foreach(token->scd_tokencontrol->events, wrapped_remove_event_io);
	list_foreach(token->scd_tokencontrol->events, wrapped_close_socket);
	token->scd_tokencontrol.sock = -1;
}

/*** internal helper functions ***/

int
int_lock_st(scd_token_t *token)
{
	return softtoken_lock(token->token_data->int_token.softtoken);
}

int
int_unlock_st(scd_token_t *token, char *passwd, UNUSED unsigned char *pairing_secret,
	      UNUSED size_t pairing_sec_len)
{
	return softtoken_unlock(token->token_data->int_token.softtoken, passwd);
}

bool
int_is_locked_st(scd_token_t *token)
{
	return softtoken_is_locked(token->token_data->int_token.softtoken);
}

bool
int_is_locked_till_reboot_st(scd_token_t *token)
{
	return softtoken_is_locked_till_reboot(token->token_data->int_token.softtoken);
}

int
int_wrap_st(scd_token_t *token, UNUSED char *label, unsigned char *plain_key, size_t plain_key_len,
	    unsigned char **wrapped_key, int *wrapped_key_len)
{
	return softtoken_wrap_key(token->token_data->int_token.softtoken, plain_key, plain_key_len,
				  wrapped_key, wrapped_key_len);
}

int
int_unwrap_st(scd_token_t *token, UNUSED char *label, unsigned char *wrapped_key,
	      size_t wrapped_key_len, unsigned char **plain_key, int *plain_key_len)
{
	return softtoken_unwrap_key(token->token_data->int_token.softtoken, wrapped_key,
				    wrapped_key_len, plain_key, plain_key_len);
}

int
int_change_pw_st(scd_token_t *token, const char *oldpass, const char *newpass,
		 UNUSED unsigned char *pairing_secret, UNUSED size_t pairing_sec_len,
		 UNUSED bool is_provisioning)
{
	return softtoken_change_passphrase(token->token_data->int_token.softtoken, oldpass,
					   newpass);
}

int
int_send_apdu_st(scd_token_t *token, unsigned char *apdu, size_t apdu_len)
{
	ERROR("send_apdu() no meaningful to softtoken. Aborting ...");
	return -1;
}

int
int_reset_auth_st(scd_token_t *token)
{
	ERROR("reset_auth() no meaningful to softtoken. Aborting ...");
	return -1;
}

#ifdef ENABLESCHSM

int
int_lock_usb(scd_token_t *token)
{
	return usbtoken_lock(token->token_data->int_token.usbtoken);
}

int
int_unlock_usb(scd_token_t *token, char *passwd, unsigned char *pairing_secret,
	       size_t pairing_sec_len)
{
	TRACE("SCD: int_usb_unlock");
	return usbtoken_unlock(token->token_data->int_token.usbtoken, passwd, pairing_secret,
			       pairing_sec_len);
}

bool
int_is_locked_usb(scd_token_t *token)
{
	return usbtoken_is_locked(token->token_data->int_token.usbtoken);
}

bool
int_is_locked_till_reboot_usb(scd_token_t *token)
{
	return usbtoken_is_locked_till_reboot(token->token_data->int_token.usbtoken);
}

int
int_wrap_usb(scd_token_t *token, char *label, unsigned char *plain_key, size_t plain_key_len,
	     unsigned char **wrapped_key, int *wrapped_key_len)
{
	return usbtoken_wrap_key(token->token_data->int_token.usbtoken, (unsigned char *)label,
				 strlen(label), plain_key, plain_key_len, wrapped_key,
				 wrapped_key_len);
}

int
int_unwrap_usb(scd_token_t *token, char *label, unsigned char *wrapped_key, size_t wrapped_key_len,
	       unsigned char **plain_key, int *plain_key_len)
{
	return usbtoken_unwrap_key(token->token_data->int_token.usbtoken, (unsigned char *)label,
				   strlen(label), wrapped_key, wrapped_key_len, plain_key,
				   plain_key_len);
}

int
int_change_pw_usb(scd_token_t *token, const char *oldpass, const char *newpass,
		  unsigned char *pairing_secret, size_t pairing_sec_len, bool is_provisioning)
{
	return usbtoken_change_passphrase(token->token_data->int_token.usbtoken, oldpass, newpass,
					  pairing_secret, pairing_sec_len, is_provisioning);
}

int
int_send_apdu_usb(scd_token_t *token, unsigned char *apdu, size_t apdu_len, unsigned char *brsp,
		  size_t brsp_len)
{
	return usbtoken_send_apdu(token->token_data->int_token.usbtoken, apdu, apu_len, brsp,
				  brsp_len);
}

int
int_reset_auth_usb(scd_token_t *token)
{
	return usbtoken_reset_auth(token->token_data->int_token.usbtoken);
}
#endif // ENABLESCHSM

scd_token_t *
token_new(const token_constr_data_t *constr_data)
{
	ASSERT(constr_data);

	scd_token_t *new_token;
	char *token_file = NULL;

	new_token = mem_new0(scd_token_t, 1);
	if (!new_token) {
		ERROR("Could not allocate new scd_token_t");
		return NULL;
	}

	new_token->token_data = mem_new(scd_token_data_t, 1);
	if (!new_token->token_data) {
		ERROR("Could not allocate memory for token_data_t");
		goto err;
	}

	new_token->token_data->token_uuid = uuid_new(constr_data->uuid);
	if (!new_token->token_data->token_uuid) {
		ERROR("Could not allocate memory for token_uuid");
		goto err;
	}

	switch (constr_data->type) {
	case (NONE): {
		WARN("Create scd_token with internal type 'NONE' selected. No token will be created.");
		goto err;
	}
	case (SOFT): {
		DEBUG("Create scd_token with internal type 'SOFT'");

		ASSERT(constr_data->uuid);
		ASSERT(constr_data->init_str.softtoken_dir);

		token_file = mem_printf("%s/%s%s", constr_data->init_str.softtoken_dir,
					constr_data->uuid, STOKEN_DEFAULT_EXT);
		if (!file_exists(token_file)) {
			if (softtoken_create_p12(token_file, STOKEN_DEFAULT_PASS,
						 constr_data->uuid) != 0) {
				ERROR("Could not create new softtoken file");
				mem_free(token_file);
				goto err;
			}
		}
		new_token->token_data->int_token.softtoken = softtoken_new_from_p12(token_file);
		if (!new_token->token_data->int_token.softtoken) {
			ERROR("Creation of softtoken failed");
			mem_free(token_file);
			goto err;
		}
		mem_free(token_file);

		new_token->token_data->type = SOFT;
		new_token->lock = int_lock_st;
		new_token->unlock = int_unlock_st;
		new_token->is_locked = int_is_locked_st;
		new_token->is_locked_till_reboot = int_is_locked_till_reboot_st;
		new_token->wrap_key = int_wrap_st;
		new_token->unwrap_key = int_unwrap_st;
		new_token->change_passphrase = int_change_pw_st;
		break;
	}
#ifdef ENABLESCHSM
	case (USB): {
		DEBUG("Create scd_token with internal type 'USB'");

		ASSERT(constr_data->uuid);
		ASSERT(constr_data->init_str.usbtoken_serial);

		new_token->token_data->int_token.usbtoken =
			usbtoken_new(constr_data->init_str.usbtoken_serial);
		if (!new_token->token_data->int_token.usbtoken) {
			ERROR("Creation of usbtoken failed");
			goto err;
		}

		char *path = mem_printf("%s%s", SCD_TOKENCONTROL_SOCKET, constr_data->uuid);
		if (0 !=
		    scd_tokencontrol_new(SCD_TOKENCONTROL_SOCKET + constr_data->uuid, new_token)) {
			ERROR("Could not create tokencontrol socket for token %s",
			      constr_data->uuid);
		}
		mem_free(path);

		new_token->token_data->type = USB;
		new_token->lock = int_lock_usb;
		new_token->unlock = int_unlock_usb;
		new_token->is_locked = int_is_locked_usb;
		new_token->is_locked_till_reboot = int_is_locked_till_reboot_usb;
		new_token->wrap_key = int_wrap_usb;
		new_token->unwrap_key = int_unwrap_usb;
		new_token->change_passphrase = int_change_pw_usb;
		new_token->reset_auth = int_reset_auth_usb;
		new_token->get_atr = int_get_atr_usb;
		break;
	}
#endif // ENABLESCHSM
	default:
		ERROR("Unrecognized token type");
		goto err;
	}

	return new_token;

err:
	if (new_token->token_data->token_uuid)
		uuid_free(new_token->token_data->token_uuid);
	if (new_token->token_data)
		mem_free(new_token->token_data);
	if (new_token)
		mem_free(new_token);

	return NULL;
}

scd_tokentype_t
token_get_type(scd_token_t *token)
{
	ASSERT(token);
	ASSERT(token->token_data);
	return token->token_data->type;
}

uuid_t *
token_get_uuid(scd_token_t *token)
{
	ASSERT(token);
	ASSERT(token->token_data);
	return token->token_data->token_uuid;
}

void
token_free(scd_token_t *token)
{
	IF_NULL_RETURN(token);

	scd_tokencontrol_free(token);

	if (token->token_data) {
		switch (token->token_data->type) {
		case (NONE):
			break;
		case (SOFT):
			TRACE("Removing softtoken %s", uuid_string(token->token_data->token_uuid));
			softtoken_remove_p12(token->token_data->int_token.softtoken);
			softtoken_free(token->token_data->int_token.softtoken);
			break;
#ifdef ENABLESCHSM
		case (USB):
			usbtoken_free(token->token_data->int_token.usbtoken);
			break;
#endif // ENABLESCHSM
		default:
			ERROR("Failed to determine token type. Cannot clean up");
			return;
		}

		if (token->token_data->token_uuid)
			uuid_free(token->token_data->token_uuid);
		mem_free(token->token_data);
	}
	mem_free(token);
}
