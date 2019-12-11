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
 * @file c_service.h
 *
 * Submodule for communicating with the Java Trustme Service located in the
 * associated container. It is possible to either send commands to the
 * Trustme Service and wait for asynchronous responses or to receive commands
 * from the Trustme Service.
 */

#ifndef C_SERVICE_H
#define C_SERVICE_H

#include "container.h"

typedef struct c_service c_service_t;

/**
 * Messages that may be send to the Trustme Service via c_service_send_message.
 */
typedef enum {
	C_SERVICE_MESSAGE_SHUTDOWN = 1,
	C_SERVICE_MESSAGE_SUSPEND,
	C_SERVICE_MESSAGE_RESUME,
	//C_SERVICE_MESSAGE_WALLPAPER,     // explicit request for current wallpaper
	C_SERVICE_MESSAGE_AUDIO_SUSPEND,
	C_SERVICE_MESSAGE_AUDIO_RESUME,
	C_SERVICE_MESSAGE_NOTIFICATION
} c_service_message_t;

/**
 * Creates a new service object and associates it with a container.
 *
 * @param container A pointer to the associated container.
 */
c_service_t *
c_service_new(
	container_t *
		container /*, configuration for communication with Trustme Service in container */);

/**
 * Resets the service to a defined state. The function may be called multiple
 * times.
 *
 * @param service The service object of the associated container to be freed.
 * @return 0 on success, -1 on error.
 */
void
c_service_cleanup(c_service_t *service);

/**
 * Stop hook, which calls the android shutdown routine
 */
int
c_service_stop(c_service_t *service);

/**
 * Frees the service object. Calls the cleanup function first.
 *
 * @param service The service object of the associated container to be freed.
 * @return 0 on success, -1 on error.
 */
void
c_service_free(c_service_t *service);

/**
 * Pre-clone hook.
 *
 * @param service The service object of the associated container.
 * @return 0 on success, -1 on error.
 */
int
c_service_start_pre_clone(c_service_t *service);

/**
 * Child hook.
 *
 * @param service The service object of the associated container.
 * @return 0 on success, -1 on error.
 */
int
c_service_start_child(c_service_t *service);

/**
 * pre-exec hook.
 *
 * @param service The service object of the associated container.
 * @return 0 on success, -1 on error.
 */
int
c_service_start_pre_exec(c_service_t *service);

/**
 * Sends a message to the Trustme Service. If the message induces a response
 * from the Trustme Service (e.g., wallpaper), the response will be delivered
 * asynchronously as a separate message. In this case, this module should invoke
 * a corresponding callback function to indicate to the container the arrival of
 * the response message (possibly along with the payload data).
 *
 * @param service The service object of the associated container.
 * @param message The message to send to the Trustme Service.
 * @return If the message has been sent successfully, 0 is returned.
 *         Note that this does not necessarily mean that the message
 *         has been successfully received by the Trustme Service.
 *         On error, -1 is returned.
 */
int
c_service_send_message(c_service_t *service, c_service_message_t message);

#endif /* C_SERVICE_H */
