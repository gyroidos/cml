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

#ifndef DISPLAY_H
#define DISPLAY_H

#include <stdbool.h>

typedef struct display_wake display_wake_t;
typedef struct display_sleep display_sleep_t;
typedef struct display_status display_status_t;

int display_init(void);

bool display_is_on(void);

display_wake_t *display_register_wake_oneshot_cb(void (*func)(void *), void *data);

void display_unregister_wake_oneshot_cb(display_wake_t *display_wake);

/**
 * Register a one shot callback to be called when the display goes to sleep or
 * immediately if it is already sleeping.
 */

display_sleep_t *display_register_sleep_oneshot_cb(void (*func)(void *), void *data);

void display_unregister_sleep_oneshot_cb(display_sleep_t *display_sleep);

/*
display_status_t *
display_register_status_cb(void (* func)(bool, void *), void *data);
*/

void display_unregister_status_cb(display_status_t *display_status);

#endif /* DISPLAY_H */
