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

#ifndef SOFTTOKEN_H
#define SOFTTOKEN_H

#include <stdbool.h>
#include <stddef.h>

#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "token.h"

#define STOKEN_DEFAULT_EXT ".p12"

typedef struct softtoken softtoken_t;

/**
 * Initializes a usb token, iff the serial number of the usb token reader matches
 * @param token ptr for scd token
 * @param ops ptr to store token operation callbacks
 * @param softtoken_dir storage directory of the softtoken
 * @return pointer to the softtoken structure on success or NULL on error
 */
void *
softtoken_new(token_t *token, token_operations_t **ops, const char *softtoken_dir);

#endif /* SOFTTOKEN_H */
