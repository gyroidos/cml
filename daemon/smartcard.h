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

#ifndef SMARTCARD_H
#define SMARTCARD_H

#include "cmld.h"
#include "container.h"
#include "stdbool.h"

typedef struct smartcard smartcard_t;

//has to be kept in sync with token.h
// clang-format off
#define SCD_TOKENCONTROL_SOCKET SOCK_PATH(tokencontrol)
// clang-format on

/**
 * @param path The directory where smartcard-related data is stored.
 */
smartcard_t *
smartcard_new(const char *path);

/**
 * @param smartcard The smartcard instance to be deleted.
 */
void
smartcard_free(smartcard_t *smartcard);

/**
 * Instruct the SCD to add the token associated to
 * @param container
 */
int
smartcard_scd_token_add_block(container_t *container);

/**
 * Instruct the SCD to remove the token associated to
 * @param container
 */
int
smartcard_scd_token_remove_block(container_t *container);

/**
 * Update the state of the token associated to
 * @param container
 */
int
smartcard_update_token_state(container_t *container);

/**
 * Control a container, e.g. start or stop it with the specified token pin
 *
 * @param smartcard smartcard struct representing the connection to the scd
 * @param container the container to be controlled (started or stopped)
 * @param resp_fd client fd to control session which should be used for responses
 * @param passwd passphrase/pin of the token
 * @param container_ctrl enum indicating the action (start, stop) to be carried out
 * @return 0 on success else -1
 */
int
smartcard_container_ctrl_handler(smartcard_t *smartcard, container_t *container, int resp_fd,
				 const char *passwd, cmld_container_ctrl_t container_ctrl);

/**
 * Change the passphrase/pin of the token associated to the container.
 * The function checks whether the token has previously been provisioned
 * with a device bound authentication code.
 * If it has not the function will interprete
 * @param passwd as the transport pin of the token, generate a new
 * authentication code from @newpasswd and the pairing_secret and initialize
 * the token with it.
 * Else, only the user part of the authentication code is changed.
 *
 * @param smartcard smartcard struct representing the connection to the scd
 * @param resp_fd client fd to control session which should be used for responses
 * @param passwd passphrase/pin of the token
 * @param newpasswd the new passphrase/pin for the token to which will be changed
 * return -1 on message transmission failure, 0 if message was sent to SCD
 */
int
smartcard_container_change_pin(smartcard_t *smartcard, container_t *container, int resp_fd,
			       const char *passwd, const char *newpasswd);

/**
 * checks whether the token associated to @param container has been provisioned
 * with a device bound authentication code yet.
 */
bool
smartcard_container_token_is_provisioned(const container_t *container);

/**
 * removes the keyfile of a container from the fs
 *
 * @param smartcard smartcard struct representing the device token
 * @param container
 */
int
smartcard_remove_keyfile(smartcard_t *smartcard, const container_t *container);

#endif /* SMARTCARD_H */
