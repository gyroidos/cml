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

#include "c_service.h"
#include "device/fraunhofer/common/cml/daemon/c_service.pb-c.h"
#include "device/fraunhofer/common/cml/daemon/c_notification.pb-c.h"

#include "container.h"

#include "common/event.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define C_SERVICE_SOCKET SOCK_PATH(service)

struct c_service {
	container_t *container; // weak reference
	int sock;
	int sock_connected;
	event_io_t *event_io_sock;
	event_io_t *event_io_sock_connected;
	container_connectivity_t connectivity;
	container_callback_t *connectivity_observer;
	bool airplane_mode;
	container_callback_t *airplane_mode_observer;
};

static int
c_service_send_container_cfg_name_proto(c_service_t *service)
{
	ASSERT(service);
	int ret = -1;

	INFO("Sending container config name %s to container %s",
			container_get_name(service->container),
			container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_NAME;

	message_proto.container_cfg_name = mem_strdup(container_get_name(service->container));

	ret = protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);

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

	ret = protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);

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

		case SERVICE_TO_CMLD_MESSAGE__CODE__AUDIO_SUSPEND_COMPLETED:
			// currently empty
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__AUDIO_RESUME_COMPLETED:
			// currently empty
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__SUSPEND_COMPLETED:
			INFO("Received a suspend completed message from container %s",
				container_get_description(service->container));
			container_set_screen_on(service->container, false);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__RESUME_COMPLETED:
			INFO("Received a resume completed message from container %s",
				container_get_description(service->container));
			container_set_screen_on(service->container, true);
			break;

		/*
		case SERVICE_TO_CMLD_MESSAGE__CODE__WALLPAPER:
			// TODO What's the non-painful way to extract the length and data from a ProtobufCMessage?
			wallpaper_len = (*(ProtobufCBinaryData *) ((void *) ((uint8_t *) ((&message->wallpaper_data)) ))).len;
			DEBUG("Received wallpaper data (%d bytes)", wallpaper_len);
			// char *wallpaper_data = (char *) (*(ProtobufCBinaryData *) ((void *) ((uint8_t *) ((&message->wallpaper_data)) ))).data;
			break;
		*/

		case SERVICE_TO_CMLD_MESSAGE__CODE__SWITCH_CONTAINER:
			INFO("Received switch_container from container %s, target_container: %s",
				 container_get_description(service->container), message->target_container);
			if (container_get_allow_container_switch(service->container))
				container_set_switch_to_container(service->container, message->target_container);
			else
				INFO("Container %s is not allowed to switch to other containers; ignoring",
					container_get_description(service->container));
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__CALL_ACTIVE:
			INFO("Received a call active message from container %s",
				container_get_description(service->container));
			container_set_call_active(service->container, true);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__CALL_HANGUP:
			INFO("Received a call hangup message from container %s",
				container_get_description(service->container));
			container_set_call_active(service->container, false);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__SHUTDOWN:
			// check container state and take action if container is not
			// stopped or just shutting down
			if (container_get_state(service->container) == CONTAINER_STATE_SHUTTING_DOWN) {
				INFO("TrustmeService received container shutdown message for %s",
					container_get_description(service->container));
			}
			else if (container_get_state(service->container) == CONTAINER_STATE_STOPPED) {
				ERROR("TrustmeService received a notification that a stopped container %s \
					is shutting down",
					container_get_description(service->container));
			} else {
				INFO("TrustmeService received a notification that the container %s is \
					shutting down, so try to stop it from our side",
					container_get_description(service->container));
				// container_stop kills the container if there is a problem
				container_stop(service->container);
			}
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__MASTER_CLEAR:
			container_wipe(service->container);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__NOTIFICATION:
			INFO("Received a statusbar notification message from container %s",
				container_get_description(service->container));

			if (message->notification) {
				// TODO Evaluate log message on post code:
				// "Handle message -> notification code 0"
				DEBUG("Handle message -> notification code %d",
				      message->notification->code);

				size_t packed_notification_size =
					container_notification__get_packed_size(message->notification);
				uint8_t *packed_notification = mem_alloc(packed_notification_size);

				container_notification__pack(message->notification,
							     packed_notification);
				container_set_notification_message(service->container,
								   packed_notification,
								   packed_notification_size);
				mem_free(packed_notification);
			}
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__CONNECTIVITY_CHANGE:
			INFO("Received connectivity change message `%d' from container %s",
				message->connectivity,
				container_get_description(service->container));

			service->connectivity = (container_connectivity_t) message->connectivity;
			container_set_connectivity(service->container, (container_connectivity_t) message->connectivity);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__AIRPLANE_MODE_CHANGED:
			INFO("Received airplane mode change message `%d' from container %s",
				message->airplane_mode,
				container_get_description(service->container));

			service->airplane_mode = message->airplane_mode;
			container_set_airplane_mode(service->container, message->airplane_mode);
			break;

		case SERVICE_TO_CMLD_MESSAGE__CODE__IMEI_MAC_PHONENO:
			INFO("Received imei: %s, mac: %s and phoneno.: %s from container %s",
				message->imei ? message->imei : "",
				message->mac ? message->mac : "",
				message->phonenumber ? message-> phonenumber : "",
				container_get_description(service->container));
			if (message->imei)
				container_set_imei(service->container, message->imei);
			if (message->mac)
				container_set_mac_address(service->container, message->mac);
			if (message->phonenumber)
				container_set_phone_number(service->container, message->phonenumber);

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

	if (events & EVENT_IO_EXCEPT) {
		WARN("Exception on connected socket to TrustmeService; closing socket and deregistering c_service_cb_receive_message");
		event_remove_io(io);
		event_io_free(io);
		service->event_io_sock_connected = NULL;
		if (close(fd) < 0)
			WARN_ERRNO("Failed to close connected service socket");
		service->sock_connected = -1;
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	ServiceToCmldMessage *message = (ServiceToCmldMessage *) protobuf_recv_message(fd, &service_to_cmld_message__descriptor);
	if (!message) {
		WARN("Failed to receive and decode protobuf ServiceToCmldMessage");
		return;
	}

	c_service_handle_received_message(service, message);
	protobuf_c_message_free_unpacked((ProtobufCMessage *) message, NULL);
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

	TRACE("Accepted connection %d from %s", service->sock_connected, container_get_description(service->container));

	service->event_io_sock_connected = event_io_new(service->sock_connected, EVENT_IO_READ, &c_service_cb_receive_message, service);
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

static int
c_service_send_connectivity_proto(c_service_t *service, container_connectivity_t connectivity)
{
	ASSERT(service);

	INFO("Trying to send and enforce connectivity status %d to container %s",
			connectivity,
			container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__CONNECTIVITY_CHANGE;

	message_proto.has_connectivity = true;
	message_proto.connectivity = (const ContainerConnectivity)connectivity;

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);
}

static void
c_service_connectivity_observer_cb(container_t *container, UNUSED container_callback_t *cb, void *data)
{
	c_service_t *service = data;

	container_connectivity_t desired = container_get_connectivity(container);
	container_connectivity_t current = service->connectivity;

	if (current != desired) {
		/* container connectivity state changed from outside, try to enforce it into the container */
		if (c_service_send_connectivity_proto(service, desired) < 0) {
			WARN("Failed to send connectivity status to container %s",
					container_get_description(container));
		}
	}
}

static int
c_service_send_airplane_mode_proto(c_service_t *service, bool airplane_mode)
{
	ASSERT(service);

	INFO("Trying to send and enforce airplane mode %d to container %s",
			airplane_mode,
			container_get_description(service->container));

	/* fill connectivity and send to TrustmeService */
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__AIRPLANE_MODE_CHANGED;

	message_proto.has_airplane_mode = true;
	message_proto.airplane_mode = airplane_mode;

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);
}

static void
c_service_airplane_mode_observer_cb(container_t *container, UNUSED container_callback_t *cb, void *data)
{
	c_service_t *service = data;

	bool desired = container_get_airplane_mode(container);
	bool current = service->airplane_mode;

	if (current != desired) {
		/* container airplane mode changed from outside, try to enforce it into the container */
		if (c_service_send_airplane_mode_proto(service, desired) < 0) {
			WARN("Failed to send airplane mode change to container %s",
					container_get_description(container));
		}
	}
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

	service->connectivity = CONTAINER_CONNECTIVITY_OFFLINE;
	service->connectivity_observer = NULL;

	service->airplane_mode = false;
	service->airplane_mode_observer = NULL;

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
	if (service->connectivity_observer) {
		container_unregister_observer(service->container, service->connectivity_observer);
		service->connectivity_observer = NULL;
	}
	if (service->airplane_mode_observer) {
		container_unregister_observer(service->container, service->airplane_mode_observer);
		service->airplane_mode_observer = NULL;
	}
}

int c_service_stop(c_service_t *service)
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
	service->event_io_sock = event_io_new(service->sock, EVENT_IO_READ, &c_service_cb_accept, service);
	event_add_io(service->event_io_sock);

	/* register connectivity observer */
	service->connectivity_observer = container_register_observer(service->container, &c_service_connectivity_observer_cb, service);
	if (!service->connectivity_observer) {
		WARN("Could not register connectivity observer callback");
		return -1;
	}

	/* register airplane_mode observer */
	service->airplane_mode_observer = container_register_observer(service->container, &c_service_airplane_mode_observer_cb, service);
	if (!service->airplane_mode_observer) {
		WARN("Could not register airplane mode observer callback");
		return -1;
	}

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

	return protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);
}

static int
c_service_send_notification_proto(c_service_t *service)
{
	ASSERT(service);
	CmldToServiceMessage message_proto = CMLD_TO_SERVICE_MESSAGE__INIT;
	message_proto.code = CMLD_TO_SERVICE_MESSAGE__CODE__NOTIFICATION;

	// TODO define a single method for receiving message and message size
	// simultaneously because size can be changed when calling
	// container_get_notification_messagget_notification_messagee
	uint8_t *notification =
		container_get_notification_message(service->container);
	size_t notification_size =
		container_get_notification_message_size(service->container);

	ContainerNotification *container_notification =
		container_notification__unpack(NULL, notification_size, notification);

	if (!container_notification) {
		ERROR("Unable to unpack container notification");
		return -1;
	}

	message_proto.notification = container_notification;
	message_proto.source_id = container_get_notification_source_id(service->container);
	message_proto.source_color = container_get_notification_source_color_rgb_string(service->container);

	INFO("Sending container notification from %s to %s with timestamp %10lld",
	     message_proto.source_id, container_get_name(service->container),
	     (long long) container_notification->timestamp);
	int ret = protobuf_send_message(service->sock_connected, (ProtobufCMessage *) &message_proto);
	container_notification__free_unpacked(container_notification, NULL);

	return ret;
}

int
c_service_send_message(c_service_t *service, c_service_message_t message)
{
	DEBUG("Sending message");
	ASSERT(service);

	if (service->sock_connected < 0) {
		WARN("Trying to send message `%d' to Trustme Service but socket is not connected. " \
			 "We ignore this for now because the Trustme Service is probably still booting...", message);
		// TODO in the future, we should maybe buffer 'message' and try to resend
		// it once the Trustme Service has connected.
		return 0;
	}

	int ret = -1;
	switch (message) {
		case C_SERVICE_MESSAGE_SHUTDOWN:
			ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__SHUTDOWN);
			break;

		case C_SERVICE_MESSAGE_SUSPEND:
			ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__SUSPEND);
			break;

		case C_SERVICE_MESSAGE_RESUME:
			if ((ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__RESUME)) < 0)
				break;
			//ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__AUDIO_RESUME);
			break;

		/*
		case C_SERVICE_MESSAGE_WALLPAPER:
			ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__WALLPAPER);
			break;
		*/

		case C_SERVICE_MESSAGE_AUDIO_SUSPEND:
			ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__AUDIO_SUSPEND);
			break;

		case C_SERVICE_MESSAGE_AUDIO_RESUME:
			//ret = c_service_send_message_proto(service, CMLD_TO_SERVICE_MESSAGE__CODE__AUDIO_RESUME);
			break;

		case C_SERVICE_MESSAGE_NOTIFICATION:
			ret = c_service_send_notification_proto(service);
			break;

		default:
			WARN("Unknown message `%d' (not sent)", message);
			return -1;
	}

	if (ret < 0)
		WARN("Failed to send message `%d' to TrustmeService", message);

	return ret;
}
