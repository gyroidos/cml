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

#ifndef SCD_CONTROL_H
#define SCD_CONTROL_H

#include <sys/types.h>

/**
 * Event that may be send to a registered event listener.
 */
typedef enum {
	SCD_EVENT_SE_REMOVED = 1,
} scd_event_t;

typedef struct scd_control scd_control_t;

scd_control_t *
scd_control_new(const char *path);

ssize_t
scd_control_send_event(scd_event_t event, const char *token_uuid);

#endif /* SCD_CONTROL_H */
