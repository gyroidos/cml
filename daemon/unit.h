/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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

#ifndef UNIT_H
#define UNIT_H

#include "common/uuid.h"
#include "compartment.h"

#include <sys/types.h>

typedef struct unit unit_t;

void
unit_register_compartment_module(compartment_module_t *mod);

unit_t *
unit_new(const uuid_t *uuid, const char *name, const char *command, char **argv, char **env,
	 size_t env_len, bool netns, const char *data_path, const char *sock_name, int sock_type,
	 void (*on_sock_connect_cb)(int sock, const char *sock_path), bool restart);

void
unit_free(unit_t *unit);

const char *
unit_get_name(const unit_t *unit);

const char *
unit_get_description(const unit_t *unit);

const uuid_t *
unit_get_uuid(const unit_t *unit);

bool
unit_has_netns(const unit_t *unit);

pid_t
unit_get_pid(const unit_t *unit);

const char *
unit_get_sock_dir(const unit_t *unit);

int
unit_get_uid(const unit_t *unit);

const char *
unit_get_data_path(const unit_t *unit);

const char *
unit_get_sock_name(const unit_t *unit);

int
unit_get_sock_type(const unit_t *unit);

void (*unit_get_on_sock_connect_cb(const unit_t *unit))(int, const char *);

bool
unit_get_restart(const unit_t *unit);

compartment_state_t
unit_get_state(const unit_t *unit);

int
unit_device_allow(unit_t *unit, char *name, char type, int major, int minor);

int
unit_device_deny(unit_t *unit, char *name);

int
unit_device_set_initial_allow(unit_t *unit, list_t *device_names);

time_t
unit_get_creation_time(const unit_t *unit);

time_t
unit_get_uptime(const unit_t *unit);

int
unit_start(unit_t *unit);

int
unit_stop(unit_t *unit);

void
unit_kill(unit_t *unit);

#endif /* UNIT_H */
