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

#ifndef PROC_H
#define PROC_H

#include <unistd.h>

typedef struct proc_status proc_status_t;

proc_status_t *
proc_status_new(pid_t pid);

void
proc_status_free(proc_status_t *status);

const char *
proc_status_get_name(const proc_status_t *status);

pid_t
proc_status_get_ppid(const proc_status_t *status);

/**
 * Kills a process/service with a given name. If ppid is bigger
 * than 0 only process with this parent pid are killed.
 * @param ppid The pid of the parent process, might be negativ.
 * @param name The process name which should be killed.
 * @param sig The signal number, e.g. SIGKILL.
 */
int
proc_killall(pid_t ppid, const char *name, int sig);

/**
 * Returns the pid of the process matching name and ppid.
 * @param ppid The pid of the parent process.
 * @param name The process name to find.
 * @return pid of matched process, 0 if no match, -1 on error.
 */
pid_t
proc_find(pid_t ppid, const char *name);

#endif /* PROC_H */
