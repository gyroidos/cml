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

#include "c_notification.h"
#include "c_notification_config.h"
#include "device/fraunhofer/common/cml/daemon/c_notification.pb-c.h"

#include <string.h>
#include <time.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"

static const time_t NANO_SEC = 1000000000;

struct c_notification {
	container_t *container;
	ContainerNotification *message;
	uint8_t *packed_message;
	size_t packed_size;

	int id;
	char *tag;
	char *pkg_name;
	char *source_id;
	char *source_name;
	char *source_color_rgb_string;

	char *title;
	char *text;
	char *custom_icon;

	bool has_base;

	c_notification_config_t *config;
};

c_notification_t *
c_notification_new(container_t *container) {
	ASSERT(container);

	c_notification_t *notification = mem_new0(c_notification_t, 1);
	notification->container = container;
	notification->message = NULL;	// calloc does not init this with NULL
	notification->has_base = false;
	notification->config = c_notification_config_new_default();

	return notification;
}

int
c_notification_set_base(c_notification_t *notification,
			int id,
			char *tag,
			char *pkg_name,
			char *title,
			char *text,
			char *custom_icon) {
	ASSERT(notification);

	if (id < 0) {
		ERROR("notification id is invalid");
		return -1;
	}
	notification->id = id;

	if (!tag) {
		ERROR("notification tag is invalid (NULL)");
		return -1;
	}
	notification->tag = mem_strdup(tag);

	if (!pkg_name) {
		ERROR("notification pkg_name is invalid (NULL)");
		return -1;
	}
	notification->pkg_name = mem_strdup(pkg_name);
	notification->title = mem_strdup(title);
	notification->text = mem_strdup(text);
	notification->custom_icon = mem_strdup(custom_icon ? custom_icon : "");
	notification->has_base = true;

	return 0;
 }

static int
c_notification_pack_base(c_notification_t *notification) {
	ASSERT(notification);

	if (notification->packed_message) {
		WARN("Trying to overwrite packed base notification, aborting");
		return 0;
	}

	ContainerNotification message = CONTAINER_NOTIFICATION__INIT;
	message.code = CONTAINER_NOTIFICATION__CODE__POST_NOTIFICATION;

	if (notification->id < 0) {
		WARN("Mandatory base notification id invalid, unable to pack message");
		return -1;
	}
	message.id = notification->id;
	if (!notification->tag) {
		WARN("Mandatory base notification tag missing, unable to pack message");
		return -1;
	}
	message.tag = notification->tag;
	if (!notification->pkg_name) {
		WARN("Mandatory base notification pkg_name missing, unable to pack message");
		return -1;
	}
	message.pkg_name = notification->pkg_name;
	message.title = notification->title;
	message.text = notification->text;
	message.custom_icon = notification->custom_icon;

	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
		ERROR("Unable to get timestamp for base notification, aborting");
		return -1;
	}

	message.timestamp =  (long long)ts.tv_sec * NANO_SEC + ts.tv_nsec;
	message.has_timestamp = true;
	INFO(" Cmld notification timestamp: %llu ", (long long)message.timestamp);

	message.is_base = notification->has_base;
	message.has_is_base = true;

	notification->packed_size = container_notification__get_packed_size(&message);
	notification->packed_message =
		mem_alloc(notification->packed_size);
	container_notification__pack(&message, notification->packed_message);
	ASSERT(notification->packed_message);

	return  0;
}

static int
c_notification_pack_message(c_notification_t *notification) {
	ASSERT(notification);

	if (notification->message) {
		if (notification->packed_message) {
			WARN("Trying to overwrite packed notification message,"
			     " aborting");
			return 0;
		}
		notification->packed_size =
			container_notification__get_packed_size(notification->message);
		notification->packed_message =
			mem_alloc(notification->packed_size);
		size_t serialized_bytes =
			container_notification__pack(notification->message,
						     notification->packed_message);
		if (serialized_bytes == 0)
			WARN("Packed message has 0 bytes");

		return 0;
	}
	else {
		WARN("Unable to pack notification message (NULL)");
		return -1;
	}
}

static int
c_notification_unpack_message(c_notification_t *notification,
			      size_t packed_size, uint8_t *packed_message) {
	ASSERT(notification);
	if (!packed_message || packed_size == 0) {
		ERROR("Unable to unpack notification message;"
		     " packed_message is NULL or packed_size is 0)");
		return -1;
	}
	if (notification->message) {
		WARN("Trying to overwrite notification message, aborting");
		return 0;
	}

	notification->message =
		container_notification__unpack(NULL, packed_size, packed_message);
	if (!notification->message) {
		ERROR("Unable to unpack notification message (NULL)");
		return -1;
	}

	return 0;
}

static int
c_notification_hide_content(c_notification_t *notification) {
	ASSERT(notification);
	INFO("Hiding notification content");

	if (!notification->message) {
		if (!notification->packed_message || notification->packed_size <= 0) {
			DEBUG("Unable to hide content; message is empty");
			return -1;
		}

		int ret = c_notification_unpack_message(notification,
							notification->packed_size,
							notification->packed_message);
		if (ret != 0 || !notification->message) {
			ERROR("Unable to unpack message in order to hide content");
			return -1;
		}
	}
	const char* hidden_content_text =
		c_notification_config_get_hidden_content_text(notification->config);
	if (hidden_content_text) {
		notification->message->text = mem_strdup(hidden_content_text);

		/* Notification message has been modified.
		 * Packed message became obsolete -> free it. */
		c_notification_free_packed_message(notification);
	}
	else {
		WARN("Hidden content text is empty (NULL), setting empty string");
		notification->message->text = "";
		return -1;
	}

	return 0;
}

uint8_t *
c_notification_get_packed_message(c_notification_t *notification) {
	ASSERT(notification);

	if (notification->has_base) {
		INFO("Notification has base, packing notification message");
		c_notification_pack_base(notification);
	}
	else if (notification->message) {
		INFO("Notification has message, packing notification message");
		c_notification_pack_message(notification);
	}

	return notification->packed_message;
}

uint8_t *
c_notification_get_filtered_packed_message(c_notification_t *notification) {
	ASSERT(notification);

	if (!c_notification_is_base_notification(notification) &&
	    c_notification_config_get_hide_content(notification->config))
		c_notification_hide_content(notification);

	return c_notification_get_packed_message(notification);
}

void
c_notification_set_packed_message(c_notification_t *notification,
			   uint8_t *message, size_t message_size) {
	ASSERT(notification);

	if (!message) {
		WARN("Packed message has invalid value (NULL)");
		return;
	}

	if (notification->packed_message) {
		WARN("Packed message has not been freed, freeing it now");
		c_notification_free_packed_message(notification);
	}

	notification->packed_message = mem_alloc(message_size);
	notification->packed_size = message_size;
	memcpy(notification->packed_message, message, notification->packed_size);
	ASSERT(notification->packed_message);
}

size_t
c_notification_get_packed_message_size(const c_notification_t *notification) {
	ASSERT(notification);

	return notification->packed_size;
}

char *
c_notification_get_source_id(const c_notification_t *notification) {
	ASSERT(notification);

	return notification->source_id;
}

void
c_notification_set_source_id(c_notification_t *notification,
			     const char *source_id) {
	ASSERT(notification);

	if (!source_id)  {
		WARN("Source id has invalid value (NULL)");
		return;
	}

	if (notification->source_id) {
		mem_free(notification->source_id);
		notification->source_id = NULL;
	}
	//TODO write this into the stored protobuf message ContainerNotification
	notification->source_id = mem_strdup(source_id);
}

char *
c_notification_get_source_name(const c_notification_t *notification) {
	ASSERT(notification);

	return notification->source_name;
}

void
c_notification_set_source_name(c_notification_t *notification,
			     const char *source_name) {
	ASSERT(notification);

	if (!source_name)  {
		WARN("Source name has invalid value (NULL)");
		return;
	}

	if (notification->source_name) {
		mem_free(notification->source_name);
		notification->source_name = NULL;
	}
	//TODO write this into the stored protobuf message ContainerNotification
	notification->source_name = mem_strdup(source_name);
}

char *
c_notification_get_source_color_rgb_string(const c_notification_t *notification) {
	ASSERT(notification);

	return notification->source_color_rgb_string;
}

void
c_notification_set_source_color_rgb_string(c_notification_t *notification,
			     const char *source_color_rgb_string) {
	ASSERT(notification);

	if (!source_color_rgb_string)  {
		WARN("Source color rgb string has invalid value (NULL)");
		return;
	}

	if (notification->source_color_rgb_string) {
		mem_free(notification->source_color_rgb_string);
		notification->source_color_rgb_string = NULL;
	}
	notification->source_color_rgb_string = mem_strdup(source_color_rgb_string);
}

bool
c_notification_is_base_notification(c_notification_t *notification) {
	ASSERT(notification);

	return notification->has_base;
}

void
c_notification_set_is_base_notification(c_notification_t *notification,
					bool is_base) {
	ASSERT(notification);

	notification->has_base = is_base;
}

bool
c_notification_allows_send_operation(c_notification_t *notification,
				     bool fg, const char *container_name) {
	ASSERT(notification);
	ASSERT(container_name);

	if (notification->has_base)
		return true;
	else if (!notification->packed_message || notification->packed_size == 0)
		return false;

	int ret = 0;
	if (!notification->message) {
		ret = c_notification_unpack_message(notification,
						    notification->packed_size,
						    notification->packed_message);
	}

	if (notification->message && ret == 0) {
		c_notification_config_policy_t policy =
			c_notification_config_get_broadcast_policy(notification->config,
								   fg);
		if (policy == NOTIFICATION_DENY_ALL)
			return false;

		if (policy != NOTIFICATION_NOT_RESTRICTED) {
			switch (notification->message->code) {
			case CONTAINER_NOTIFICATION__CODE__POST_NOTIFICATION:
				if (policy != NOTIFICATION_POST_ALLOWED)
					return false;
			case CONTAINER_NOTIFICATION__CODE__CANCEL_NOTIFICATION:
				if (policy != NOTIFICATION_CANCEL_ALLOWED)
					return false;
			default:
				WARN("Unknown notification message code. Disallow send notification.");
				return false;
			}
		}

		return	!c_notification_config_is_disallowed_receiver(notification->config,
								      policy,
								      container_name);
	}
	ERROR("Unable to unpack message");

	return false;
}

void
c_notification_free_packed_message(c_notification_t *notification) {
	ASSERT(notification);

	if (notification->packed_message)
		mem_free(notification->packed_message);
	notification->packed_message = NULL;
	notification->packed_size = 0;
}

void
c_notification_free_unpacked_message(c_notification_t * notification) {
	ASSERT(notification);

	if (notification->message)
		container_notification__free_unpacked(notification->message, NULL);
	notification->message = NULL;
}

void
c_notification_free(c_notification_t *notification) {
	c_notification_cleanup(notification);

	if (notification->config) {
		c_notification_config_free(notification->config);
	}
	mem_free(notification);
}

void
c_notification_cleanup(c_notification_t *notification) {
	ASSERT(notification);

	if (notification->message) {
		container_notification__free_unpacked(notification->message, NULL);
		notification->message = NULL;
	}
	if (notification->packed_message) {
		mem_free(notification->packed_message);
		notification->packed_message = NULL;
	}
	if (notification->tag) {
		mem_free(notification->tag);
		notification->tag = NULL;
	}
	if (notification->pkg_name) {
		mem_free(notification->pkg_name);
		notification->pkg_name = NULL;
	}
	if (notification->source_id) {
		mem_free(notification->source_id);
		notification->source_id = NULL;
	}
	if (notification->title) {
		mem_free(notification->title);
		notification->title = NULL;
	}
	if (notification->text) {
		mem_free(notification->text);
		notification->text = NULL;
	}
	if (notification->custom_icon) {
		mem_free(notification->custom_icon);
		notification->custom_icon = NULL;
	}
	notification->packed_size = 0;
	notification->id = 0;
	notification->has_base = false;
}
