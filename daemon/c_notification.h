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

#ifndef C_NOTIFICATION_H
#define C_NOTIFICATION_H

#include "container.h"

typedef struct c_notification c_notification_t;

typedef enum {
	NOTIFICATION_NOT_RESTRICTED_FG = 1,
	NOTIFICATION_POST_ALLOWED_FG,
	NOTIFICATION_CANCEL_ALLOWED_FG,
 } c_notification_foreground_policy_t;

typedef enum {
	NOTIFICATION_NOT_RESTRICTED_BG = 1,
	NOTIFICATION_POST_ALLOWED_BG,
	NOTIFICATION_CANCEL_ALLOWED_BG,
} c_notification_background_policy_t;

c_notification_t *
c_notification_new(container_t *container);

int
c_notification_set_base(c_notification_t *notification,
			int id,
			char *tag,
			char *pkg_name,
			char *title,
			char *text,
			char *custom_icon);

uint8_t *
c_notification_get_packed_message(c_notification_t *notification);

uint8_t *
c_notification_get_filtered_packed_message(c_notification_t *notification);

void
c_notification_set_packed_message(c_notification_t *notification,
				  uint8_t *packed_message, size_t packed_size);

size_t
c_notification_get_packed_message_size(const c_notification_t *notification);

char *
c_notification_get_source_id(const c_notification_t *notification);

void
c_notification_set_source_id(c_notification_t *notification,
			     const char *source_id);
char *
c_notification_get_source_name(const c_notification_t *notification);

void
c_notification_set_source_name(c_notification_t *notification,
			       const char *source_name);

char *
c_notification_get_source_color_rgb_string(const c_notification_t *notification);

void
c_notification_set_source_color_rgb_string(c_notification_t *notification,
			     const char *source_color_rgb_string);

bool
c_notification_is_base_notification(c_notification_t *notification);

void
c_notification_set_is_base_notification(c_notification_t *notification,
					bool is_base);

bool
c_notification_allows_send_operation(c_notification_t *notification,
				     bool fg, const char *container_name);

void
c_notification_free_packed_message(c_notification_t *notification);

void
c_notification_free(c_notification_t *notification);

void
c_notification_cleanup(c_notification_t *notification);

#endif /* C_NOTIFICATION_H */
