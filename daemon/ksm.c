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

#include "ksm.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/file.h"

#define KSM_PATH "/sys/kernel/mm/ksm/"

#define KSM_RELAXED_SLEEP_MILLISECS 1500
#define KSM_RELAXED_PAGES_TO_SCAN 100

#define KSM_AGGRESSIVE_SLEEP_MILLISECS 100
#define KSM_AGGRESSIVE_PAGES_TO_SCAN 500

static event_timer_t *ksm_timer;

static void
ksm_set(int sleep_millisecs, int pages_to_scan)
{
	if (file_printf(KSM_PATH "sleep_millisecs", "%d", sleep_millisecs) < 0) {
		WARN("Could not configure KSM; no kernel support?");
		return;
	}
	if (file_printf(KSM_PATH "pages_to_scan", "%d", pages_to_scan) < 0) {
		WARN("Could not configure KSM; no kernel support?");
	}
}

static void
ksm_set_aggressive()
{
	DEBUG("Setting KSM aggressive settings (sleep_millisecs=%d, pages_to_scan=%d",
	      KSM_AGGRESSIVE_SLEEP_MILLISECS, KSM_AGGRESSIVE_PAGES_TO_SCAN);
	ksm_set(KSM_AGGRESSIVE_SLEEP_MILLISECS, KSM_AGGRESSIVE_PAGES_TO_SCAN);
}

static void
ksm_set_relaxed()
{
	DEBUG("Setting KSM relaxed settings (sleep_millisecs=%d, pages_to_scan=%d",
	      KSM_RELAXED_SLEEP_MILLISECS, KSM_RELAXED_PAGES_TO_SCAN);
	ksm_set(KSM_RELAXED_SLEEP_MILLISECS, KSM_RELAXED_PAGES_TO_SCAN);
}

static void
ksm_set_aggressive_timeout_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	ksm_set_relaxed();

	event_remove_timer(ksm_timer);
	event_timer_free(ksm_timer);
	ksm_timer = NULL;
}

void
ksm_set_aggressive_for(int millisecs)
{
	ksm_set_aggressive();

	if (ksm_timer) {
		/* if there is already a timer, renew it */
		event_remove_timer(ksm_timer);
		event_timer_free(ksm_timer);
		ksm_timer = NULL;
	}

	/* register timer to relax KSM after millisecs time */
	ksm_timer = event_timer_new(millisecs, 1, &ksm_set_aggressive_timeout_cb, NULL);
	event_add_timer(ksm_timer);
}

int
ksm_init()
{
	if (file_printf(KSM_PATH "sleep_millisecs", "%d", KSM_RELAXED_SLEEP_MILLISECS) < 0) {
		WARN("Could not configure KSM; no kernel support?");
		return -1;
	}
	if (file_printf(KSM_PATH "pages_to_scan", "%d", KSM_RELAXED_PAGES_TO_SCAN) < 0) {
		WARN("Could not configure KSM; no kernel support?");
		return -1;
	}
	if (file_printf(KSM_PATH "run", "%d", 1) < 0) {
		WARN("Could not configure KSM; no kernel support?");
		return -1;
	}
	return 0;
}
