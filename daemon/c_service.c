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

#include "c_service.h"
#include "c_service.pb-c.h"

#include "container.h"
#include "audit.h"

#include "common/event.h"
#include "common/fd.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"

#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

// clang-format off
#define C_SERVICE_SOCKET SOCK_PATH(service)
// clang-format on

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

struct c_service {
	container_t *container; // weak reference
	int sock;
	int sock_connected;
	event_io_t *event_io_sock;
	event_io_t *event_io_sock_connected;
};

static int
c_service_send_container_cfg_name_proto(c_service_t *service)
{
	ASSERT(service);
	int ret = -1;

	INFO("Sending container config name %s to container %s",
	     container_get_name(service->container), container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_NAME;

	message_proto.container_cfg_name = mem_strdup(container_get_name(service->container));

	ret = protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);

	mem_free(message_proto.container_cfg_name);
	return ret;
}

static int
c_service_send_container_cfg_dns_proto(c_service_t *service)
{
	ASSERT(service);
	int ret = -1;

	INFO("Sending container config dns %s to container %s",
	     container_get_dns_server(service->container),
	     container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_DNS;

	message_proto.container_cfg_dns = mem_strdup(container_get_dns_server(service->container));

	ret = protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);

	mem_free(message_proto.container_cfg_dns);
	return ret;
}

/**
 * Processes the received protobuf message and calls the relevant callback
 * functions on the associated container.
 */
static void
c_service_handle_received_message(c_service_t *service, const ServiceToCmldMessage *message)
{
	//int wallpaper_len;

	if (!message) {
		WARN("ServiceToCmldMessage is NULL, ignoring");
		return;
	}

	TRACE("Received message code from Trustme Service: %d", message->code);
	switch (message->code) {
	case SERVICE_TO_CMLD_MESSAGE__CODE__BOOT_COMPLETED:
		container_set_state(service->container, CONTAINER_STATE_RUNNING);
		break;

	case SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_NAME_REQ:
		INFO("Received a reqest for the container name from container %s",
		     container_get_description(service->container));
		if (c_service_send_container_cfg_name_proto(service))
			INFO("sent reply to conatiner");
		break;

	case SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_DNS_REQ:
		INFO("Received a reqest for the container name from container %s",
		     container_get_description(service->container));
		if (c_service_send_container_cfg_dns_proto(service))
			INFO("sent reply to conatiner");
		break;

	case SERVICE_TO_CMLD_MESSAGE__CODE__EXEC_CAP_SYSTIME_PRIV: {
		// construct an NULL terminated argv buffer for execve
		size_t argv_len = ADD_WITH_OVERFLOW_CHECK(message->n_captime_exec_param, (size_t)2);
		char **argv = mem_new0(char *, argv_len);
		argv[0] = message->captime_exec_path;
		for (size_t i = 0; i < message->n_captime_exec_param; ++i) {
			argv[i + 1] = message->captime_exec_param[i];
			TRACE("argv[%zu]: %s", i, argv[i + 1]);
		}
		if (container_exec_cap_systime(service->container, argv))
			WARN("Exec of '%s' failed/permission denied!", message->captime_exec_path);
		break;
	}

	case SERVICE_TO_CMLD_MESSAGE__CODE__AUDIT_ACK: {
		INFO("Got ACK from Container %s",
		     uuid_string(container_get_uuid(service->container)));

		if (0 > container_audit_process_ack(service->container, message->audit_ack)) {
			ERROR("Failed to process audit ACK from container %s",
			      uuid_string(container_get_uuid(service->container)));
		}
		break;
	}

	default:
		WARN("Received unknown message code from Trustme Service: %d", message->code);
		return;
	}
}

/**
 * Invoked whenever the TrustmeService writes (a protobuf ServiceToCmldMessage)
 * to the _connected_ socket.
 */
static void
c_service_cb_receive_message(int fd, unsigned events, event_io_t *io, void *data)
{
	TRACE("Callback c_service_cb_receive_message has been invoked");

	c_service_t *service = data;

	if (events & EVENT_IO_READ) {
		ServiceToCmldMessage *message = (ServiceToCmldMessage *)protobuf_recv_message(
			fd, &service_to_cmld_message__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(message, connection_err);

		c_service_handle_received_message(service, message);
		protobuf_c_message_free_unpacked((ProtobufCMessage *)message, NULL);
	}

	// also check EXCEPT flag
	if (events & EVENT_IO_EXCEPT) {
		WARN("Exception on connected socket to TrustmeService; "
		     "closing socket and deregistering c_service_cb_receive_message");
		goto connection_err;
	}
	return;

connection_err:
	event_remove_io(io);
	event_io_free(io);
	service->event_io_sock_connected = NULL;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected service socket");
	service->sock_connected = -1;
	return;
}

/**
 * Invoked when the TrustmeService (initially) connects to the predefined UNIX socket.
 */
static void
c_service_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	TRACE("Callback c_service_cb_accept has been invoked");

	c_service_t *service = data;

	if (events & EVENT_IO_EXCEPT)
		goto error;

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	if ((service->sock_connected = sock_unix_accept(fd)) < 0)
		goto error;

	TRACE("Accepted connection %d from %s", service->sock_connected,
	      container_get_description(service->container));

	service->event_io_sock_connected = event_io_new(service->sock_connected, EVENT_IO_READ,
							&c_service_cb_receive_message, service);
	event_add_io(service->event_io_sock_connected);

	// We leave service->sock open so the TrustmeService could connect
	// again in the future in case service->sock_connected gets closed.

	return;

error:
	WARN("Exception on socket while waiting for TrustmeService to connect; closing socket and deregistering c_service_cb_accept");
	event_remove_io(io);
	event_io_free(io);
	service->event_io_sock = NULL;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close service socket");
	service->sock = -1;
	return;
}

c_service_t *
c_service_new(container_t *container)
{
	ASSERT(container);

	c_service_t *service = mem_new0(c_service_t, 1);
	service->container = container;
	service->sock = -1;
	service->sock_connected = -1;
	service->event_io_sock = NULL;
	service->event_io_sock_connected = NULL;

	return service;
}

void
c_service_cleanup(c_service_t *service)
{
	ASSERT(service);

	if (service->sock_connected > 0) {
		if (close(service->sock_connected) < 0) {
			WARN_ERRNO("Failed to close connected service socket");
		}
		service->sock_connected = -1;
	}
	if (service->sock > 0) {
		if (close(service->sock) < 0) {
			WARN_ERRNO("Failed to close service socket");
		}
		service->sock = -1;
	}
	if (service->event_io_sock_connected) {
		event_remove_io(service->event_io_sock_connected);
		event_io_free(service->event_io_sock_connected);
		service->event_io_sock_connected = NULL;
	}
	if (service->event_io_sock) {
		event_remove_io(service->event_io_sock);
		event_io_free(service->event_io_sock);
		service->event_io_sock = NULL;
	}
}

int
c_service_stop(c_service_t *service)
{
	ASSERT(service);

	INFO("Send container stop command to TrustmeService");

	return c_service_send_message(service, C_SERVICE_MESSAGE_SHUTDOWN);
}

void
c_service_free(c_service_t *service)
{
	ASSERT(service);

	c_service_cleanup(service);
	mem_free(service);
}

int
c_service_start_pre_clone(c_service_t *service)
{
	ASSERT(service);

	service->sock = sock_unix_create(SOCK_STREAM);

	return service->sock;
}

int
c_service_start_child(c_service_t *service)
{
	ASSERT(service);

	return sock_unix_bind(service->sock, C_SERVICE_SOCKET);
}

int
c_service_start_pre_exec(c_service_t *service)
{
	ASSERT(service);

	if (sock_unix_listen(service->sock) < 0)
		return -1;

	// Now wait for initial connect from TrustmeService to socket.
	service->event_io_sock =
		event_io_new(service->sock, EVENT_IO_READ, &c_service_cb_accept, service);
	event_add_io(service->event_io_sock);

	return 0;
}

/**
 * Helper function that generates and sends a protobuf message to the Trustme Service.
 */
static int
c_service_send_message_proto(c_service_t *service, unsigned int code)
{
	ASSERT(service);

	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = code;

	int ret =
		protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);

	return ret;
}

int
c_service_audit_send_record(c_service_t *service, const uint8_t *buf, uint32_t buf_len)
{
	ASSERT(service);

	TRACE("Trying to send packed audit record of size %u to container %s", buf_len,
	      uuid_string(container_get_uuid(service->container)));

	if (-1 == protobuf_send_message_packed(service->sock_connected, buf, buf_len)) {
		ERROR("Failed to send packed audit record to container %s",
		      uuid_string(container_get_uuid(service->container)));
		return -1;
	}

	return 0;
}

int
c_service_audit_notify(c_service_t *service, uint64_t remaining_storage)
{
	TRACE("Notifying container %s about stored audit events, remaining storage: %" PRIu64,
	      uuid_string(container_get_uuid(service->container)), remaining_storage);
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_NOTIFY;

	message_proto.audit_remaining_storage = remaining_storage;

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);
}

int
c_service_send_message(c_service_t *service, c_service_message_t message)
{
	DEBUG("Sending message");
	ASSERT(service);

	if (service->sock_connected < 0) {
		WARN("Trying to send message `%d' to Trustme Service but socket is not connected. "
		     "We ignore this for now because the Trustme Service is probably still booting...",
		     message);
		// TODO in the future, we should maybe buffer 'message' and try to resend
		// it once the Trustme Service has connected.

		// If we want to shut the container down, return -1
		// to have it killed immediately, not waiting for the timeout
		if (message == C_SERVICE_MESSAGE_SHUTDOWN)
			return -1;

		return 0;
	}

	int ret = -1;
	switch (message) {
	case C_SERVICE_MESSAGE_SHUTDOWN:
		ret = c_service_send_message_proto(service,
						   CMLD_TO_SERVICE_MESSAGE__CODE__SHUTDOWN);
		break;

	case C_SERVICE_MESSAGE_AUDIT_COMPLETE:

		TRACE("Notifying container %s that all stored audit events were delivered",
		      uuid_string(container_get_uuid(service->container)));
		ret = c_service_send_message_proto(service,
						   CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_COMPLETE);
		break;

	default:
		WARN("Unknown message `%d' (not sent)", message);
		return -1;
	}

	if (ret < 0)
		WARN("Failed to send message `%d' to TrustmeService", message);

	return ret;
}
