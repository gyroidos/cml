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

#include <time.h>

/**
 * Initialize time subsystem. This function takes a snapshot
 * of btime stamp according to the realtime and boottime clocks.
 *
 * @return  0 on success, -1 on error
 */
int
time_init(void);

/*
 * Simulate "time_t time(time_t *tloc)" with CLOCK_BOOTTIME and fixed CML
 * btime stamp during cmld start with time_init() before any container was running.
 *
 * @return  the value of time in seconds since the Epoch, ((time_t) -1) on error
 */
time_t
time_cml(time_t *tloc);

/*
 * Register the clock check timer. Execute this function after a container start.
 * Since container's (at least privileged containers) may set the system clock
 * through the service interface, e.g., by running an ntp server with
 * CAP_SYS_TIME inside the container. We have to register the clock watcher
 * which prvides coarse time stamp through time_cml above.
 * The timer deregisters it self if clock out of sync is detected and the
 * internal cml boot time stamp is adapted to an CML internal ntp request.
 */
void
time_register_clock_check(void);
