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

#ifndef C_NOTIFICATION_CONFIG_H
#define C_NOTIFICATION_CONFIG_H

#include "common/list.h"
#include "common/macro.h"

#include <sys/types.h>

typedef struct c_notification_config c_notification_config_t;

typedef enum {
	NOTIFICATION_NOT_RESTRICTED = 1,
	NOTIFICATION_POST_ALLOWED,
	NOTIFICATION_CANCEL_ALLOWED,
	NOTIFICATION_DENY_ALL,
	NOTIFICATION_POLICY_UNKNOWN
} c_notification_config_policy_t;

c_notification_config_t *
c_notification_config_new(const char *file);

c_notification_config_t *
c_notification_config_new_default();

void
c_notification_config_free(c_notification_config_t *config);

int
c_notification_config_write(const c_notification_config_t *config);

c_notification_config_policy_t
c_notification_config_get_broadcast_policy(c_notification_config_t *config,
					   bool foreground);

bool
c_notification_config_is_disallowed_receiver(c_notification_config_t *config,
					     c_notification_config_policy_t policy,
					     UNUSED const char *name);

bool
c_notification_config_get_hide_content(c_notification_config_t *config);

const char *
c_notification_config_get_hidden_content_text(c_notification_config_t *config);

//TODO create enum for operation code in proto file and use it in
// get_allowed_receivers
#endif /* C_CONTAINER_CONFIG_H */
