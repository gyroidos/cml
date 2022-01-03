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

/**
 * @file c_service.c
 *
 * Submodule for communicating with the Java Trustme Service located in the
 * associated container. It is possible to either send commands to the
 * Trustme Service and wait for asynchronous responses or to receive commands
 * from the Trustme Service.
 */

#define MOD_NAME "c_service"

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

typedef struct c_service {
	container_t *container; // weak reference
	int sock;
	int sock_connected; // socket to client which will get events
	event_io_t *event_io_sock;
	list_t *event_io_sock_connected_list; // list of clients
} c_service_t;

static int
c_service_send_container_cfg_name_proto(c_service_t *service, int sock_client)
{
	ASSERT(service);
	int ret = -1;

	INFO("Sending container config name %s to container %s",
	     container_get_name(service->container), container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_NAME;

	message_proto.container_cfg_name = mem_strdup(container_get_name(service->container));

	ret = protobuf_send_message(sock_client, (ProtobufCMessage *)&message_proto);

	mem_free0(message_proto.container_cfg_name);
	return ret;
}

static int
c_service_send_container_cfg_dns_proto(c_service_t *service, int sock_client)
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

	ret = protobuf_send_message(sock_client, (ProtobufCMessage *)&message_proto);

	mem_free0(message_proto.container_cfg_dns);
	return ret;
}

/**
 * Processes the received protobuf message and calls the relevant callback
 * functions on the associated container.
 */
static void
c_service_handle_received_message(c_service_t *service, int sock_client,
				  const ServiceToCmldMessage *message)
{
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
		INFO("Received a request for the container name from container %s",
		     container_get_description(service->container));
		if (c_service_send_container_cfg_name_proto(service, sock_client))
			INFO("sent reply to container");
		break;

	case SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_DNS_REQ:
		INFO("Received a request for the container name from container %s",
		     container_get_description(service->container));
		if (c_service_send_container_cfg_dns_proto(service, sock_client))
			INFO("sent reply to container");
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

		if (0 > audit_process_ack(service->container, message->audit_ack)) {
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

		c_service_handle_received_message(service, fd, message);
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
	service->event_io_sock_connected_list =
		list_remove(service->event_io_sock_connected_list, io);
	event_remove_io(io);
	event_io_free(io);
	// check if we are/were the main service event receiver
	// and give up our slot for new clients
	if (fd == service->sock_connected)
		service->sock_connected = -1;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected service socket");
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

	int client_sock = sock_unix_accept(fd);
	IF_TRUE_GOTO_ERROR(client_sock < 0, error);

	// We can only have one target service for events
	if (service->sock_connected < 0)
		service->sock_connected = client_sock;
	else
		INFO("Service socket already in use, create a command receiving socket only!");

	TRACE("Accepted connection %d from %s", service->sock_connected,
	      container_get_description(service->container));

	event_io_t *event =
		event_io_new(client_sock, EVENT_IO_READ, &c_service_cb_receive_message, service);

	event_add_io(event);
	service->event_io_sock_connected_list =
		list_append(service->event_io_sock_connected_list, event);

	// We leave service->sock open so the TrustmeService instances could connect
	// again in the future

	return;

error:
	WARN("Exception on socket while waiting for TrustmeService to connect;"
	     " closing socket and deregistering c_service_cb_accept");
	event_remove_io(io);
	event_io_free(io);
	service->event_io_sock = NULL;
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close service socket");
	service->sock = -1;
	return;
}

/**
 * Creates a new service object and associates it with a container.
 *
 * @param container A pointer to the associated container.
 * return The service object of the associated container as generic void pointer
 */
static void *
c_service_new(container_t *container)
{
	ASSERT(container);

	c_service_t *service = mem_new0(c_service_t, 1);
	service->container = container;
	service->sock = -1;
	service->sock_connected = -1;
	service->event_io_sock = NULL;
	service->event_io_sock_connected_list = NULL;

	return service;
}

/**
 * Resets the service to a defined state. The function may be called multiple
 * times.
 *
 * @param servicep The generic service object of the associated container.
 */
static void
c_service_cleanup(void *servicep, UNUSED bool is_rebooting)
{
	c_service_t *service = servicep;
	ASSERT(service);

	if (service->sock > 0) {
		if (close(service->sock) < 0) {
			WARN_ERRNO("Failed to close service socket");
		}
		service->sock = -1;
	}
	for (list_t *l = service->event_io_sock_connected_list; l; l = l->next) {
		event_io_t *event_io_sock_connected = l->data;
		event_remove_io(event_io_sock_connected);
		if (close(event_io_get_fd(event_io_sock_connected) < 0)) {
			WARN_ERRNO("Failed to close connected service socket");
		}
		event_io_free(event_io_sock_connected);
	}
	list_delete(service->event_io_sock_connected_list);
	service->event_io_sock_connected_list = NULL;

	if (service->sock_connected > 0)
		service->sock_connected = -1;

	if (service->event_io_sock) {
		event_remove_io(service->event_io_sock);
		event_io_free(service->event_io_sock);
		service->event_io_sock = NULL;
	}
}

/**
 * Stop hook, which calls the container shutdown routine
 * @param servicep The generic service object of the associated container.
 * @return 0 on success, -CONTAINER_ERROR_SERVICE on error.
 */
static int
c_service_stop(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	INFO("Send container stop command to TrustmeService");

	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__SHUTDOWN;

	if (service->sock_connected >= 0 &&
	    protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto) >= 0)
		return 0;

	char *argv[] = { "halt", NULL };
	if (container_run(service->container, false, argv[0], 1, argv, -1))
		return -CONTAINER_ERROR_SERVICE;

	return 0;
}

/**
 * Frees the service object.
 *
 * @param servicep The generic service object of the associated container to be freed.
 */
static void
c_service_free(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	mem_free0(service);
}

/**
 * Pre-clone hook.
 *
 * @param servicep The generic service object of the associated container.
 * @return 0 on success, -CONTAINER_ERROR_SERVICE on error.
 */
static int
c_service_start_pre_clone(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	service->sock = sock_unix_create(SOCK_STREAM);

	if (service->sock < 0)
		return CONTAINER_ERROR_SERVICE;

	return 0;
}

/**
 * Start-child hook.
 *
 * @param servicep The generic service object of the associated container.
 * @return 0 on success, -CONTAINER_ERROR_SERVICE on error.
 */
static int
c_service_start_child(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	if (sock_unix_bind(service->sock, C_SERVICE_SOCKET) < 0)
		return -CONTAINER_ERROR_SERVICE;

	return 0;
}

/**
 * Pre-exec hook.
 *
 * @param servicep The generic service object of the associated container.
 * @return 0 on success, -CONTAINER_ERROR_SERVICE on error.
 */
static int
c_service_start_pre_exec(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	if (sock_unix_listen(service->sock) < 0)
		return -CONTAINER_ERROR_SERVICE;

	// Now wait for initial connect from TrustmeService to socket.
	service->event_io_sock =
		event_io_new(service->sock, EVENT_IO_READ, &c_service_cb_accept, service);
	event_add_io(service->event_io_sock);

	return 0;
}

/**
 * Send packed audit record to service.
 * @param service The service object of the associated container.
 * @param buf packed protobuf message to be send
 * @param buf_len length of the packed protobuf message
 * @return 0 on success, -1 otherwise
*/
static int
c_service_audit_send_record(void *servicep, const uint8_t *buf, uint32_t buf_len)
{
	c_service_t *service = servicep;
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

/**
 * Notify container about stored audit events.
 * @param service The service object of the associated container.
 * @param remaining_audit storage capacity
 * @return the length of the serialized message (without length prefix)
*/
static int
c_service_audit_notify(void *servicep, uint64_t remaining_storage)
{
	c_service_t *service = servicep;
	ASSERT(service);

	TRACE("Notifying container %s about stored audit events, remaining storage: %" PRIu64,
	      uuid_string(container_get_uuid(service->container)), remaining_storage);
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_NOTIFY;

	message_proto.audit_remaining_storage = remaining_storage;

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);
}

static int
c_service_audit_notify_complete(void *servicep)
{
	c_service_t *service = servicep;
	ASSERT(service);

	if (service->sock_connected < 0) {
		WARN("Trying to send AUDIT_COMPLETE, but service socket is not connected.");
		return 0;
	}

	TRACE("Notifying container %s that all stored audit events were delivered",
	      uuid_string(container_get_uuid(service->container)));

	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_COMPLETE;

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *)&message_proto);
}

static container_module_t c_service_module = {
	.name = MOD_NAME,
	.container_new = c_service_new,
	.container_free = c_service_free,
	.container_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_service_start_pre_clone,
	.start_post_clone = NULL,
	.start_pre_exec = c_service_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = c_service_start_child,
	.start_pre_exec_child = NULL,
	.stop = c_service_stop,
	.cleanup = c_service_cleanup,
	.join_ns = NULL,
};

static void INIT
c_service_init(void)
{
	// register this module in container.c
	container_register_module(&c_service_module);

	// register relevant handlers implemented by this module
	container_register_audit_record_send_handler(MOD_NAME, c_service_audit_send_record);
	container_register_audit_record_notify_handler(MOD_NAME, c_service_audit_notify);
	container_register_audit_notify_complete_handler(MOD_NAME, c_service_audit_notify_complete);
}
