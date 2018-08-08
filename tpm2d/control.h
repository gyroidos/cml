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
 * The control module implements the logic that controls TPM2D through messages
 * that are received through a listening socket.
 *
 * Incoming messages (Protocol Buffers format) are decoded and various actions
 * are performed depending on the command contained in each message, such as
 * setting up device encryption
 */


#ifndef TPM2D_CONTROL_H
#define TPM2D_CONTROL_H

#include <unistd.h>
#include <stdint.h>

/**
 * Data structure containing the variables associated to a control socket.
 */
typedef struct tpm2d_control tpm2d_control_t;

/**
 * Enum defining generic responses to commands
 */
typedef enum control_generic_response {
	CMD_OK = 1,
	CMD_FAILED
} control_generic_response_t; 

/**
 * Creates a new tpm2d_control_t object listening on a UNIX socket bound to the specified file.
 *
 * @param path path of the socket file to bind the socket to
 */
tpm2d_control_t *
tpm2d_control_new(const char *path);

#endif /* TPM2D_CONTROL_H */
