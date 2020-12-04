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

#include "time.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/proc.h"
#include "common/sock.h"
#include "common/fd.h"

#include <errno.h>
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdbool.h>

#define NTP_SERVICE_PORT "123"
#define NTP_TIMESTAMP_DELTA 2208988800ull

#define TIME_MINUTES(m) (m * 60)
#define TIME_HOURS(h) (h * 60 * 60)

#define TIME_SYSTEM_OFF_ALLOW (TIME_HOURS(1))

#define NTP_LI_VERSION_MODE(li, version, mode) ((li << 6) | (version << 3) | mode)

typedef struct {
	uint8_t li_version_mode;
	uint8_t stratum;
	uint8_t poll_interval;
	uint8_t precision;
	uint32_t root_delay;
	uint32_t root_dispersion;
	uint32_t ref_clock_id;
	uint32_t ref_timestamp_sec;
	uint32_t ref_timestamp_frac;
	uint32_t orig_timestamp_sec;
	uint32_t orig_timestamp_frac;
	uint32_t rx_timestamp_sec;
	uint32_t rx_timestamp_frac;
	uint32_t tx_timestamp_sec; // for coarse server time we only use this
	uint32_t tx_timestamp_frac;
} ntp_v3_t;

static time_t btime_cml;
static char *time_ntp_server = "de.pool.ntp.org";
event_timer_t *time_clock_check_timer = NULL;
static bool time_out_of_sync = false;

static time_t
time_get_ntp_coarse(char *server)
{
	/*
	 * since we cannot trust our local time we just take
	 * the servers transmit timestamp into account and ignore
	 * local timestamps for roundtrip elimination
	 */
	ntp_v3_t *ntp = mem_new0(ntp_v3_t, 1);

	// li = 0 , version = 3 , mode = 3
	ntp->li_version_mode = NTP_LI_VERSION_MODE(0, 3, 3);

	int sock = sock_inet_create_and_connect(SOCK_DGRAM, server, NTP_SERVICE_PORT);
	IF_TRUE_GOTO(sock < 0, err);
	IF_TRUE_GOTO(write(sock, (char *)ntp, sizeof(ntp_v3_t)) < 0, err);
	IF_TRUE_GOTO(read(sock, (char *)ntp, sizeof(ntp_v3_t)) < 0, err);

	ntp->tx_timestamp_sec = ntohl(ntp->tx_timestamp_sec);
	ntp->tx_timestamp_frac = ntohl(ntp->tx_timestamp_frac);

	time_t ret = (time_t)(ntp->tx_timestamp_sec - NTP_TIMESTAMP_DELTA);

	INFO("Got current time from server %s", ctime(&ret));
	mem_free(ntp);
	return ret;
err:
	ERROR("Communication Error with NTP Server '%s'!", server);
	mem_free(ntp);
	return (time_t)-1;
}

static bool
time_system_clock_has_changed(void)
{
	unsigned long long btime;

	if (proc_stat_btime(&btime) < 0) {
		ERROR_ERRNO("Unable to read btime from proc)");
		return true;
	}
	if (fabs(difftime(btime, btime_cml)) < TIME_MINUTES(1)) {
		INFO("System clock still in trusted range.");
		return false;
	}
	return true;
}

static void
time_check_and_reset_clock_cb(event_timer_t *timer, UNUSED void *data)
{
	ASSERT(timer == time_clock_check_timer);

	if (!time_system_clock_has_changed()) {
		INFO("System clock not changed.");
		return;
	}

	time_t ntp_now = time_get_ntp_coarse(time_ntp_server);
	IF_TRUE_RETURN(ntp_now == (time_t)-1);

	time_t system_now = time(NULL);
	IF_TRUE_RETURN(system_now == (time_t)-1);

	if (fabs(difftime(ntp_now, system_now)) > TIME_SYSTEM_OFF_ALLOW) {
		INFO("System clock out of trusted range. updating internal btime according to NTP");
		btime_cml = ntp_now - btime_cml;
		event_remove_timer(timer);
		event_timer_free(timer);
		time_clock_check_timer = NULL;
		time_out_of_sync = true;
	} else {
		INFO("System clock still in trusted range.");
	}
}

int
time_init(void)
{
	unsigned long long btime;
	if (proc_stat_btime(&btime) < 0) {
		ERROR_ERRNO("Unable to read btime from proc)");
		return -1;
	}
	btime_cml = btime;
	return 0;
}

time_t
time_cml(time_t *tloc)
{
	time_t ret;
	struct timespec ts;

	if (clock_gettime(CLOCK_BOOTTIME, &ts) == -1) {
		ERROR_ERRNO("Unable to read CLOCK_BOOTTIME");
		return (time_t)-1;
	}

	ret = ts.tv_sec + btime_cml;
	if (tloc)
		*tloc = ret;

	return ret;
}

void
time_register_clock_check(void)
{
	// time already out of sync and coarse ntp timestamp in use
	IF_TRUE_RETURN(time_out_of_sync);

	if (time_clock_check_timer == NULL) {
		time_clock_check_timer =
			event_timer_new(TIME_MINUTES(11) * 1000, EVENT_TIMER_REPEAT_FOREVER,
					time_check_and_reset_clock_cb, NULL);
		event_add_timer(time_clock_check_timer);
	}

	// run time_check_and_reset_clock_cb at once
	time_check_and_reset_clock_cb(time_clock_check_timer, NULL);
}
