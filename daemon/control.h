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

/**
 * @file control.h
 *
 * The control module implements the logic that controls CMLD through messages
 * that are received through a listening socket.
 *
 * Incoming messages (Protocol Buffers format) are decoded and various actions
 * are performed depending on the command contained in each message, such as
 * listing all containers, starting or stopping individual containers, etc.
 */

#ifndef CONTROL_H
#define CONTROL_H

#include <stdbool.h>

/**
 * Data structure containing the variables associated to a control socket.
 */
typedef struct control control_t;

/**
 * Responses that may be send to a controller via control_send_reponse.
 */
typedef enum {
	CONTROL_RESPONSE_CONTAINER_START_OK = 1,
	CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED,
	CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED,
	CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG,
	CONTROL_RESPONSE_CONTAINER_START_EEXIST,
	CONTROL_RESPONSE_DEVICE_LOCKED_TILL_REBOOT,
	CONTROL_RESPONSE_DEVICE_CHANGE_PIN_FAILED,
	CONTROL_RESPONSE_DEVICE_CHANGE_PIN_SUCCESSFUL,
	CONTROL_RESPONSE_DEVICE_PROVISIONING_ERROR,
	CONTROL_RESPONSE_DEVICE_CERT_ERROR,
	CONTROL_RESPONSE_DEVICE_CERT_OK,
} control_message_t;

/**
 * Creates a new control_t object listening on the specified socket.
 *
 * @param socket listening socket
 * @param privileged use privileged interface
 */
control_t *
control_new(int socket, bool privileged);

/**
 * Creates a new control_t object listening on a UNIX socket bound to the specified file.
 * Uses privileged control interface.
 *
 * @param path path of the socket file to bind the socket to
 */
control_t *
control_local_new(const char *path);

/**
 * Creates a new control_t object maintaining a remote connection over a internal
 * AF_INET client socket
 * Uses privileged control interface.
 *
 * @param hostip The IP adress of the remote host as String, e.g., 127.0.0.1
 * @param service The MDM port name or port number
 */
// TODO: allow a hostname instead of an ip address
control_t *
control_remote_new(const char *hostip, const char *service);

/**
 * Connects a remote control object to the host:ip provided during object creation.
 * Automatically retries the connection if it does not succeed until the corresponding
 * control_remote_disconnect() is called.
 */
int
control_remote_connect(control_t *control);

/**
 * Returns true if the given remote control object is already connected or trying
 * to connect. False otherwise.
 */
bool
control_remote_connecting(control_t *control);

/**
 * Disconnects a remote control object from its peer. Afterwards the state of the
 * control object is the same as immediately after the constructor.
 */
void
control_remote_disconnect(control_t *control);

/**
 * Frees the control_t object, closing the associated socket if necessary.
 */
void
control_free(control_t *control);

int
control_get_client_sock(control_t *control);

/**
 * Sends a protobuf message to the specified fd.
 */
int
control_send_message(control_message_t message, int fd);

#endif /* CONTROL_H */
