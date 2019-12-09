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

#include "power.h"

#include "common/macro.h"
#include "common/event.h"

#include <stdio.h>
#include <sys/time.h>
#include <string.h>

/******************************************************************************/

/**
 * This function reads out the wakelocks set. The locks appear in the proc folder in the wakelocks file.
 * If the wakelock is recognized as active, it is printed.
 */
static void
power_debug_wakelocks(void)
{
	char line[4096];
	FILE *f;

	f = fopen("/sys/kernel/debug/wakeup_sources", "r");
	IF_NULL_RETURN_WARN_ERRNO(f);

	// iterate over all entries within the wakelocks file
	while (fgets(line, sizeof(line), f)) {
		char name[128];
		int active_count;
		int event_count;
		int wakeup_count;
		int expire_count;
		long long active_since;
		long long total_time;
		long long max_time;
		long long last_change;
		long long prevent_suspend_time;
		int n;

		// read out the line content
		n = sscanf(line, " %127[^\t] %d %d %d %d %lld %lld %lld %lld %lld\n", name, &active_count, &event_count,
			   &wakeup_count, &expire_count, &active_since, &total_time, &max_time, &last_change,
			   &prevent_suspend_time);

		// check if line could be read and wakelock activity
		if (n == 10 && active_since > 0)
			DEBUG("Active wakelock found: %s", name);
	}

	fclose(f);
}

/**
 * This function monitors the deepsleep state of the device and puts debug messages accordingly.
 * In case that the device was not in deepsleep during the last 60 seconds, it debugs the wakelocks,
 * which prevent the deepsleep.
 */
static void
power_cb_check_sleep(UNUSED event_timer_t *timer, UNUSED void *data)
{
	static struct timeval last_sleep = { 0, 0 };
	static struct timeval last_awake = { 0, 0 };
	static struct timeval last_print = { 0, 0 };
	struct timeval now, diff_sleep, diff_awake, diff_print;
	;

	IF_FALSE_RETURN_WARN_ERRNO(gettimeofday(&now, NULL) >= 0);

	// first call, set current time
	if (last_sleep.tv_sec == 0) {
		memcpy(&last_sleep, &now, sizeof(now));
		memcpy(&last_awake, &now, sizeof(now));
		memcpy(&last_print, &now, sizeof(now));
		return;
	}

	// check if last awake time was more than 10 seconds ago and set last sleep
	// point of time to now, as device got active.
	timersub(&now, &last_awake, &diff_awake);
	if (diff_awake.tv_sec > 10) {
		DEBUG("Seems we slept for %llu seconds, good!", (unsigned long long)diff_awake.tv_sec);
		memcpy(&last_sleep, &now, sizeof(now));
	}

	// check if device was not in deepsleep during last minute, but only indicate it every minute
	timersub(&now, &last_sleep, &diff_sleep);
	timersub(&now, &last_print, &diff_print);
	if (diff_sleep.tv_sec >= 60 && diff_print.tv_sec >= 60) {
		DEBUG("No sleep for %llu seconds, checking wakelocks...", (unsigned long long)diff_sleep.tv_sec);
		power_debug_wakelocks();
		memcpy(&last_print, &now, sizeof(now));
	}

	// triggering this function indicates awakeness of the device, i.e. set it
	memcpy(&last_awake, &now, sizeof(now));
}

/******************************************************************************/

int
power_init(void)
{
	event_timer_t *timer;

	timer = event_timer_new(1000, -1, &power_cb_check_sleep, NULL);
	event_add_timer(timer);

	return 0;
}
