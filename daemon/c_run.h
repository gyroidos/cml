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

#ifndef C_RUN_H
#define C_RUN_H

#include "container.h"

typedef struct c_run c_run_t;

c_run_t *
c_run_new(container_t *container);

void
c_run_free(c_run_t *run);

void
c_run_cleanup(c_run_t *run);

int
c_run_write_exec_input(const c_run_t *run, char *exec_input, int session_fd);

int
c_run_exec_process(c_run_t *run, int create_pty, char *cmd, ssize_t argc, char **argv,
		   int session_fd);

int
c_run_get_console_sock_cmld(const c_run_t *run, int session_fd);

#endif /* C_RUN_H */
