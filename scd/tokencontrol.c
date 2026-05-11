#include "token.h"
#include "tokencontrol.h"

#include "tokencontrol.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/uuid.h"
#include "common/protobuf.h"
#include "common/str.h"
#include "common/fd.h"
#include "common/file.h"
#include "unistd.h"

#define SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG 1

struct tokencontrol {
	token_t *token; // backpointer to parent token struct
	int cfd;
	int lsock;
	char *lsock_path;
	list_t *events;
};

static void
wrapped_remove_event_io(void *elem)
{
	TRACE("Remove tokencontrol event from event_loop");
	ASSERT(elem);
	event_io_t *e = elem;
	event_remove_io(e);
	event_io_free(e);
}

static void
tokencontrol_cb_accept(int fd, unsigned events, UNUSED event_io_t *io, void *data);

static void
tokencontrol_handle_message(const ContainerToToken *msg, int fd, void *data)
{
	ASSERT(msg);
	ASSERT(data);

	DEBUG("tokencontrol_handle_message");

	tctrl_t *tctrl = (tctrl_t *)data;
	int len = 0;
	unsigned char *brsp = NULL;

	IF_NULL_GOTO_WARN(msg, err);
	IF_NULL_GOTO_ERROR(tctrl, err);

	TokenToContainer out = TOKEN_TO_CONTAINER__INIT;
	brsp = mem_alloc0(MAX_APDU_BUF_LEN);

	switch (msg->command) {
	case CONTAINER_TO_TOKEN__COMMAND__GET_ATR:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__GET_ATR msg");
		len = token_get_atr(tctrl->token, brsp, MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("GET_ATR failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	case CONTAINER_TO_TOKEN__COMMAND__UNLOCK_TOKEN:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__UNLOCK_TOKEN");
		len = token_reset_auth(tctrl->token, brsp, MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("GET_ATR failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	case CONTAINER_TO_TOKEN__COMMAND__SEND_APDU:
		DEBUG("Handle CONTAINER_TO_TOKEN__COMMAND__SEND_APDU msg");
#ifdef DEBUG_BUILD
		str_t *dump = str_hexdump_new(msg->apdu.data, msg->apdu.len);
		TRACE("Got APDU with with len: %zu, data: %s", msg->apdu.len, str_buffer(dump));
		str_free(dump, true);
#endif
		len = token_send_apdu(tctrl->token, msg->apdu.data, msg->apdu.len, brsp,
				      MAX_APDU_BUF_LEN);
		if (len < 0) {
			WARN("SEND_APDU failed wit code %d", len);
			goto err;
		}
		goto out;
		break;

	default:
		WARN("ContainerToToken command %d unknown or not implemented yet", msg->command);
	}

err:
	/* TODO: distinguish error soruces and set return code accordingly */
	out.return_code = TOKEN_TO_CONTAINER__CODE__ERR_INVALID;
	if ((protobuf_send_message(fd, (ProtobufCMessage *)&out)) < 0) {
		ERROR("Could not send protobuf response on socker %d", fd);
	}
	goto close_fd;

close_fd:
	mem_free0(brsp);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
	return;

out:
	out.return_code = TOKEN_TO_CONTAINER__CODE__OK;
	out.has_response = true;
	out.response.len = len;
	out.response.data = brsp;

#ifdef DEBUG_BUILD
	str_t *dump = str_hexdump_new(brsp, len);
	TRACE("Returning apdu with len: %zu, data: %s", out.response.len, str_buffer(dump));
	str_free(dump, true);
#endif

	if ((protobuf_send_message(fd, (ProtobufCMessage *)&out)) < 0) {
		ERROR("Could not send protobuf response on socket %d", fd);
	}
	mem_free0(brsp);
}

/**
 * Event callback for incoming data that a ContainerToToken message.
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd		file descriptor of the client connection
 *					from which the incoming message is read
 * @param events	event flags
 * @param io		pointer to associated event_io_t struct
 * @param data		pointer to this control_t struct
 */
static void
tokencontrol_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	tctrl_t *tctrl = (tctrl_t *)(data);

	DEBUG("tokencontrol_cb_recv_message");

	if (events & EVENT_IO_READ) {
		ContainerToToken *msg = (ContainerToToken *)protobuf_recv_message(
			fd, &container_to_token__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		tokencontrol_handle_message(msg, fd, data);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled control connection %d", fd);
	} else if (events & EVENT_IO_EXCEPT) {
		INFO("TokenControl client closed connection; disconnecting socket.");
		goto connection_err;
	} else {
		ERROR("Unexpected event");
		goto connection_err;
	}

	return;

connection_err:
	tctrl->events = list_remove(tctrl->events, io);
	event_remove_io(io);
	event_io_free(io);

	tctrl->cfd = -1;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");

	// accept new connection for respective token
	event_io_t *event =
		event_io_new(tctrl->lsock, EVENT_IO_READ, tokencontrol_cb_accept, tctrl);
	tctrl->events = list_append(tctrl->events, event);
	event_add_io(event);

	return;
}

/**
 * Event callback for accepting incoming connections on the listening socket.
 *
 * @param fd		file descriptor of the listening socket
 *					from which incoming connections should be accepted
 * @param events	event flags
 * @param io		pointer to associated event_io_t struct
 * @param data		pointer to this control_t struct
  */
static void
tokencontrol_cb_accept(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	tctrl_t *tctrl = (tctrl_t *)data;

	if (events & EVENT_IO_READ) {
		tctrl->cfd = accept(fd, NULL, 0);
		if (-1 == tctrl->cfd) {
			WARN("Could not accept tokencontrol connection");
			return;
		}
		DEBUG("Accepted tokencontrol connection %d", tctrl->cfd);

		fd_make_non_blocking(tctrl->cfd);

		DEBUG("Made tokenctrl_cfd non-blocking");

		// only accept one connection per socket at a time
		tctrl->events = list_remove(tctrl->events, io);

		wrapped_remove_event_io(io);

		event_io_t *event =
			event_io_new(tctrl->cfd, EVENT_IO_READ, tokencontrol_cb_recv_message, data);

		tctrl->events = list_append(tctrl->events, event);

		event_add_io(event);
	} else if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
	} else {
		ERROR("Unexpected event");
	}
	return;
}

tctrl_t *
tokencontrol_new(const token_t *token)
{
	ASSERT(token);

	TRACE("tokencontrol_new");

	tctrl_t *tctrl = mem_new0(tctrl_t, 1);
	IF_NULL_GOTO_ERROR(tctrl, err);
	tctrl->cfd = -1; // preset to signal unconnected client

	tctrl->lsock_path = mem_printf("%s/%s.sock", SCD_TOKENCONTROL_SOCKET,
				       uuid_string(token_get_uuid(token)));
	IF_NULL_GOTO_ERROR(tctrl->lsock_path, err_tctrl);

	tctrl->lsock = sock_unix_create_and_bind(SOCK_STREAM | SOCK_NONBLOCK, tctrl->lsock_path);
	if (tctrl->lsock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		goto err_lsock;
	}
	if (listen(tctrl->lsock, SCD_TOKENCONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		close(tctrl->lsock);
		goto err_lsock;
	}

	event_io_t *event =
		event_io_new(tctrl->lsock, EVENT_IO_READ, tokencontrol_cb_accept, tctrl);
	tctrl->events = list_append(tctrl->events, event);
	event_add_io(event);

	return tctrl;

err_lsock:
	mem_free0(tctrl->lsock_path);
err_tctrl:
	mem_free0(tctrl);
err:
	return NULL;
}

void
tokencontrol_free(tctrl_t *tctrl)
{
	ASSERT(tctrl);

	list_foreach(tctrl->events, wrapped_remove_event_io);

	if (tctrl->cfd != -1) {
		TRACE("Closing accepted tokencontrol socket for token %s",
		      uuid_string(token_get_uuid(tctrl->token)));
		TRACE("Closing tokencontrol fd: %d", tctrl->cfd);
		if (sock_unix_close(tctrl->cfd) != 0) {
			WARN("Could not close accepted tokencontrol socket");
		}
	}
	TRACE("Closing listening tokencontrol socket");
	if (sock_unix_close_and_unlink(tctrl->lsock, tctrl->lsock_path) != 0) {
		WARN_ERRNO("Could not close listening tokencontrol socket for token %s",
			   uuid_string(token_get_uuid(tctrl->token)));
	}
	mem_free0(tctrl->lsock_path);

	mem_free0(tctrl);
}