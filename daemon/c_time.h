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

/*
 * @file c_time.h
 *
 * This module implements the new time namespace available since Linux 5.6.
 * It resest the available clocks for boottime and monotonic by setting the
 * corresponding offsets to the negated current system values.
 * Thus, for instance uptime will show the time since a container was started
 * and not the overall system uptime.
 *
 * Time namespace could not be activated by clone directly but only by a call
 * to unshare. After unshare the calling process is not directly part of the
 * new time namespace, to be allowed to set the new clock offsets. All
 * children will be placed in the new time namespace. To put the later init
 * process of a container also to the new time namespace, a call to setns
 * using /proc/self/time_for_children does the trick.
 */

#ifndef C_TIME_H
#define C_TIME_H

#include "container.h"

typedef struct c_time c_time_t;

c_time_t *
c_time_new(container_t *container);

void
c_time_free(c_time_t *time);

int
c_time_start_child(const c_time_t *time);

int
c_time_start_pre_exec(const c_time_t *time);

int
c_time_start_post_exec(c_time_t *time);

int
c_time_start_pre_exec_child(const c_time_t *time);

void
c_time_cleanup(c_time_t *time);

time_t
c_time_get_uptime(const c_time_t *time);

time_t
c_time_get_creation_time(const c_time_t *time);

#endif /* C_TIME_H */
