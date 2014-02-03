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

#include "display.h"

#include "hardware.h"
#include "common/macro.h"
#include "common/list.h"
#include "common/mem.h"
#include "common/event.h"

#define DISPLAY_TIMER_TIMEOUT 50

struct display_sleep {
	void (* func)(void *);
	void *data;
};

struct display_wake {
	void (* func)(void *);
	void *data;
};

struct display_status {
	display_sleep_t *sleep;
	display_wake_t *wake;
	void (* func)(bool, void *);
	void *data;
};

static list_t *display_sleep_cb_list = NULL;
static list_t *display_wake_cb_list = NULL;
static event_timer_t *timer_sleep = NULL;
static event_timer_t *timer_wake = NULL;

/******************************************************************************/

static void
display_sleep_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	if (display_is_on()) {
		DEBUG("display still on... waiting");
		return;
	}

	if (timer_sleep) {
		event_remove_timer(timer_sleep);
		event_timer_free(timer_sleep);
		timer_sleep = NULL;
	}

	while (display_sleep_cb_list) {
		display_sleep_t *sleep = display_sleep_cb_list->data;
		(sleep->func)(sleep->data);
		mem_free(sleep);
		display_sleep_cb_list = list_unlink(display_sleep_cb_list, display_sleep_cb_list);
	}
}

void
display_unregister_sleep_oneshot_cb(display_sleep_t *sleep)
{
	display_sleep_cb_list = list_remove(display_sleep_cb_list, sleep);
	mem_free(sleep);

	if (display_sleep_cb_list && timer_sleep) {
		event_remove_timer(timer_sleep);
		event_timer_free(timer_sleep);
		timer_sleep = NULL;
	}
}

display_sleep_t *
display_register_sleep_oneshot_cb(void (*func)(void *), void *data)
{
	ASSERT(func);

	display_sleep_t *sleep = mem_new(display_sleep_t, 1);

	sleep->func = func;
	sleep->data = data;

	display_sleep_cb_list = list_append(display_sleep_cb_list, sleep);

	if (!timer_sleep) {
		timer_sleep = event_timer_new(DISPLAY_TIMER_TIMEOUT, EVENT_TIMER_REPEAT_FOREVER,
			&display_sleep_cb, NULL);
		event_add_timer(timer_sleep);
	}

	return sleep;
}

/******************************************************************************/

static void
display_wake_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	if (!display_is_on()) {
		return;
	}

	if (timer_wake) {
		event_remove_timer(timer_wake);
		event_timer_free(timer_wake);
		timer_wake = NULL;
	}

	while (display_wake_cb_list) {
		display_wake_t *wake = display_wake_cb_list->data;
		(wake->func)(wake->data);
		mem_free(wake);
		display_wake_cb_list = list_unlink(display_wake_cb_list, display_wake_cb_list);
	}
}

void
display_unregister_wake_oneshot_cb(display_wake_t *wake)
{
	display_wake_cb_list = list_remove(display_wake_cb_list, wake);
	mem_free(wake);

	if (display_wake_cb_list && timer_wake) {
		event_remove_timer(timer_wake);
		event_timer_free(timer_wake);
		timer_wake = NULL;
	}
}

display_wake_t *
display_register_wake_oneshot_cb(void (*func)(void *), void *data)
{
	ASSERT(func);

	display_wake_t *wake = mem_new(display_wake_t, 1);

	wake->func = func;
	wake->data = data;

	display_wake_cb_list = list_append(display_wake_cb_list, wake);

	if (!timer_wake) {
		timer_wake = event_timer_new(DISPLAY_TIMER_TIMEOUT, EVENT_TIMER_REPEAT_FOREVER,
			&display_wake_cb, NULL);
		event_add_timer(timer_wake);
	}

	return wake;
}

/******************************************************************************/

static void
display_status_sleep_cb(void *data);

static void
display_status_wake_cb(void *data)
{
	display_status_t *status = data;

	ASSERT(status);

	status->wake = NULL;
	status->sleep = display_register_sleep_oneshot_cb(&display_status_sleep_cb, status);

	(status->func)(true, status->data);
}

static void
display_status_sleep_cb(void *data)
{
	display_status_t *status = data;

	ASSERT(status);

	status->sleep = NULL;
	status->wake = display_register_wake_oneshot_cb(&display_status_wake_cb, status);

	(status->func)(false, status->data);
}

display_status_t *
display_register_status_cb(void (*func)(bool, void *), void *data)
{
	display_status_t *status;

	ASSERT(func);

	status = mem_new0(display_status_t, 1);
	status->sleep = display_register_sleep_oneshot_cb(&display_status_sleep_cb, status);
	status->wake = NULL;
	status->func = func;
	status->data = data;

	return status;
}

void
display_unregister_status_cb(display_status_t *status)
{
	ASSERT(status);

	if (status->sleep)
		display_unregister_sleep_oneshot_cb(status->sleep);

	if (status->wake)
		display_unregister_wake_oneshot_cb(status->wake);

	mem_free(status);
}

/******************************************************************************/

bool
display_is_on(void)
{
	return hardware_display_power_state();
}
