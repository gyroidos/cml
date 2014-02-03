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

#include "c_notification_config.h"
#include "device/fraunhofer/common/cml/daemon/c_notification.pb-c.h"

#include "common/list.h"
#include "common/mem.h"
#include "common/protobuf.h"

#include <string.h>

struct c_notification_config {
	char *file;

	ContainerNotificationConfig *cfg;
};

c_notification_config_t *
c_notification_config_new(const char *file) {
	//ASSERT(file);
	DEBUG("Loading container config from file \"%s\".", file);

	ContainerNotificationConfig *ccfg = NULL;
	if (file) {
		ccfg = (ContainerNotificationConfig *)
			protobuf_message_new_from_textfile(file, &container_notification_config__descriptor);
	}

	if (!file || !ccfg) {
		WARN("Failed loading notification config from file \"%s\"."
		     " Using default values.", file);

		ccfg = mem_new(ContainerNotificationConfig, 1);
		container_notification_config__init(ccfg);
#if PLATFORM_VERSION_MAJOR > 6
		ccfg->foreground =
			CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__DENY_ALL;
		ccfg->background =
			CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__DENY_ALL;
#else
		ccfg->foreground =
			CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__NO_RESTRICTIONS;
		ccfg->background =
			CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__NO_RESTRICTIONS;
#endif
	}
	ASSERT(ccfg);

	c_notification_config_t * config = mem_new0(c_notification_config_t, 1);
	if (file)
		config->file = mem_strdup(file);
	config->cfg = ccfg;

	return config;
}

c_notification_config_t *
c_notification_config_new_default() {

	return c_notification_config_new(NULL);
}

void
c_notification_config_free(c_notification_config_t *config) {
	ASSERT(config);
	protobuf_free_message((ProtobufCMessage *) config->cfg);
	mem_free(config->file);
	mem_free(config);
}

c_notification_config_policy_t
c_notification_config_get_broadcast_policy(c_notification_config_t *config,
					   bool foreground) {
	ASSERT(config);
	ASSERT(config->cfg);

	ContainerNotificationConfig__BroadcastPolicy policy;
	policy = foreground ? config->cfg->foreground
		            : config->cfg->background;

	switch (policy) {
	case CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__NO_RESTRICTIONS:
		return NOTIFICATION_NOT_RESTRICTED;
		break;
	case CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__ALLOW_POST:
		return NOTIFICATION_POST_ALLOWED;
		break;
	case CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__ALLOW_CANCEL:
		return NOTIFICATION_CANCEL_ALLOWED;
		break;
	case CONTAINER_NOTIFICATION_CONFIG__BROADCAST_POLICY__DENY_ALL:
		return NOTIFICATION_DENY_ALL;
		break;
	default:
		WARN("Unknown notification policy code");
		return NOTIFICATION_POLICY_UNKNOWN;
	}
}

bool
c_notification_config_is_disallowed_receiver(c_notification_config_t *config,
					     c_notification_config_policy_t policy,
					     const char *name) {
	ASSERT(config);
	ASSERT(config->cfg);

	if (config->cfg->n_disallowed_receivers_post == 0 &&
	    config->cfg->n_disallowed_receivers_cancel == 0) {
		DEBUG("Receivers blacklists are empty");
		return false;
	}

	if (policy == NOTIFICATION_POST_ALLOWED) {
		for (size_t i = 0; i < config->cfg->n_disallowed_receivers_post; i++) {
			if (strcmp(config->cfg->disallowed_receivers_post[i], name) == 0)
				return true;
		}
	}
	if (policy == NOTIFICATION_CANCEL_ALLOWED) {
		for (size_t i = 0; i < config->cfg->n_disallowed_receivers_cancel; i++) {
			if (strcmp(config->cfg->disallowed_receivers_cancel[i], name) == 0)
				return true;
		}
	}
	return true;
}

bool
c_notification_config_get_hide_content(c_notification_config_t *config) {
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->hide_content;
}

const char*
c_notification_config_get_hidden_content_text(c_notification_config_t *config) {
	ASSERT(config);
	ASSERT(config->cfg);

	return config->cfg->hidden_content_text;
}


