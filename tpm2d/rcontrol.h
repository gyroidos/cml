/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2019 Fraunhofer AISEC
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

/**
 * @file rcontrol.h
 *
 * The rcontrol module implements the logic that remotely controls TPM2D
 * through messages that are received through a listening ip socket.
 *
 * Incoming messages (Protocol Buffers format) are decoded and various actions
 * are performed depending on the command contained in each message, such as
 * performing remote attestation
 */

#ifndef TPM2D_RCONTROL_H
#define TPM2D_RCONTROL_H

#include <unistd.h>
#include <stdint.h>

/**
 * Data structure containing the variables associated to a rcontrol socket.
 */
typedef struct tpm2d_rcontrol tpm2d_rcontrol_t;

#ifndef TPM2D_NVMCRYPT_ONLY
/**
 * Creates a new tpm2d_rcontrol_t object listening on a INET socket bound
 * to the specified ip and port.
 *
 * @param path path of the socket file to bind the socket to
 */
tpm2d_rcontrol_t *
tpm2d_rcontrol_new(const char *ip, int port);

void
tpm2d_rcontrol_free(tpm2d_rcontrol_t *rcontrol);

#else
#include "common/macro.h"

static inline tpm2d_rcontrol_t *
tpm2d_rcontrol_new(UNUSED const char *ip, UNUSED int port)
{
	return NULL;
}

static inline void
tpm2d_rcontrol_free(UNUSED tpm2d_rcontrol_t *rcontrol)
{
}
#endif /* TPM2D_NVMCRYPT_ONLY */

#endif /* TPM2D_RCONTROL_H */
