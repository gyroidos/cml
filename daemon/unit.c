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

#include "unit.h"
#include "u_user.h"
#include "u_perm.h"
#include "u_time.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/list.h"
#include "common/sock.h"
#include "common/uuid.h"
#include "compartment.h"

#include <stdint.h>
#include <sys/stat.h>

struct unit {
	compartment_t *compartment;
	char *sock_name;
	int sock_type;
	char *data_path;
	void (*on_sock_connect_cb)(int sock, const char *sock_path);
	bool restart;
};

static char *unit_bin_path[] = { "/usr/sbin", "/sbin", "/usr/bin", "/bin" };

// list of compartment modules for all container objects
static list_t *compartment_module_list = NULL;

static list_t *
unit_get_compartment_modules(void)
{
	return compartment_module_list;
}

static void
unit_set_extension(void *extension_data, compartment_t *compartment)
{
	ASSERT(extension_data);
	ASSERT(compartment);

	unit_t *unit = extension_data;
	unit->compartment = compartment;
}

const char *
unit_get_sock_dir(const unit_t *unit)
{
	ASSERT(unit);
	u_user_t *u_user = compartment_module_get_instance_by_name(unit->compartment, "c_user");

	return u_user_get_sock_dir(u_user);
}

void
unit_register_compartment_module(compartment_module_t *mod)
{
	ASSERT(mod);

	compartment_module_list = list_append(compartment_module_list, mod);
	DEBUG("Unit module %s registered, nr of hooks: %d)", mod->name,
	      list_length(compartment_module_list));
}

unit_t *
unit_new(const uuid_t *uuid, const char *name, const char *command, char **argv, char **env,
	 size_t env_len, bool netns, const char *data_path, const char *sock_name, int sock_type,
	 void (*on_sock_connect_cb)(int sock, const char *sock_path), bool restart)
{
	// set type specific flags for compartment
	uint64_t flags = 0;
	flags |= COMPARTMENT_FLAG_TYPE_CONTAINER;
	// set namespace flags for compartment
	flags |= COMPARTMENT_FLAG_NS_USER;
	if (netns)
		flags |= COMPARTMENT_FLAG_NS_NET;
	// connect stdout and stderr in compartment
	flags |= COMPARTMENT_FLAG_CONNECT_STDFDS;

	unit_t *unit = mem_new0(unit_t, 1);

	// initial length of 2 + actual argv size to hold command name + final NULL pointer
	int argv_len = 2;
	for (char **arg = argv; arg && *arg; arg++)
		argv_len++;

	char *command_path = NULL;
	for (size_t i = 0; i < sizeof(unit_bin_path) / sizeof(unit_bin_path[0]); i++) {
		command_path = mem_printf("%s/%s", unit_bin_path[i], command);
		if (access(command_path, F_OK) == 0) {
			DEBUG("Found command '%s' in path '%s'", command, unit_bin_path[i]);
			break;
		}
	}
	if (command_path == NULL) {
		ERROR("Binary '%s' not found in valid path.", command);
		unit_free(unit);
		return NULL;
	}

	char **init_argv = mem_new0(char *, argv_len);
	init_argv[0] = command_path;

	size_t i = 1;
	for (char **arg = argv; arg && *arg; arg++, i++)
		init_argv[i] = mem_strdup(*arg);

	// create internal compartment object with unit as extension data
	compartment_extension_t *extension =
		compartment_extension_new(unit_set_extension, unit_get_compartment_modules, unit);
	unit->compartment = compartment_new(uuid, name, flags, init_argv[0], init_argv, env,
					    env_len, extension);

	if (!unit->compartment) {
		ERROR("Could not create internal compartment object");
		compartment_extension_free(extension);
		unit_free(unit);
		return NULL;
	}

	unit->data_path = mem_strdup(data_path);

	unit->sock_name = mem_strdup(sock_name);
	unit->sock_type = sock_type;
	unit->on_sock_connect_cb = on_sock_connect_cb;

	unit->restart = restart;

	return unit;
}

void
unit_free(unit_t *unit)
{
	ASSERT(unit);

	/*
	 * free compartment first, as c_*_free() may access
	 * unit resources through extension pointer
	 */
	if (unit->compartment)
		compartment_free(unit->compartment);

	if (unit->sock_name)
		mem_free0(unit->sock_name);

	if (unit->data_path)
		mem_free0(unit->data_path);

	mem_free0(unit);
}

const char *
unit_get_name(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_name(unit->compartment);
}

const char *
unit_get_description(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_description(unit->compartment);
}

const uuid_t *
unit_get_uuid(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_uuid(unit->compartment);
}

bool
unit_has_netns(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_flags(unit->compartment) & COMPARTMENT_FLAG_NS_NET;
}

pid_t
unit_get_pid(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_pid(unit->compartment);
}

int
unit_get_uid(const unit_t *unit)
{
	ASSERT(unit);
	u_user_t *user = compartment_module_get_instance_by_name(unit->compartment, "c_user");

	return u_user_get_uid(user);
}

const char *
unit_get_data_path(const unit_t *unit)
{
	ASSERT(unit);
	return unit->data_path;
}

const char *
unit_get_sock_name(const unit_t *unit)
{
	ASSERT(unit);
	return unit->sock_name;
}

int
unit_get_sock_type(const unit_t *unit)
{
	ASSERT(unit);
	return unit->sock_type;
}

bool
unit_get_restart(const unit_t *unit)
{
	ASSERT(unit);
	return unit->restart;
}

void (*unit_get_on_sock_connect_cb(const unit_t *unit))(int, const char *)
{
	ASSERT(unit);
	return unit->on_sock_connect_cb;
}

compartment_state_t
unit_get_state(const unit_t *unit)
{
	ASSERT(unit);
	return compartment_get_state(unit->compartment);
}

int
unit_device_allow(unit_t *unit, char *name, char type, int major, int minor)
{
	ASSERT(unit);
	u_perm_t *perm = compartment_module_get_instance_by_name(unit->compartment, "c_perm");

	return u_perm_allow_dev(perm, type, major, minor, name);
}

int
unit_device_deny(unit_t *unit, char *name)
{
	u_perm_t *perm = compartment_module_get_instance_by_name(unit->compartment, "c_perm");

	return u_perm_deny_dev(perm, name);
}

int
unit_device_set_initial_allow(unit_t *unit, list_t *device_names)
{
	u_perm_t *perm = compartment_module_get_instance_by_name(unit->compartment, "c_perm");

	return u_perm_set_initial_allow_dev(perm, device_names);
}

int
unit_start(unit_t *unit)
{
	ASSERT(unit);
	return compartment_start(unit->compartment);
}

int
unit_stop(unit_t *unit)
{
	ASSERT(unit);
	return compartment_stop(unit->compartment);
}

void
unit_kill(unit_t *unit)
{
	ASSERT(unit);

	unit->restart = false;
	compartment_kill(unit->compartment);
}

time_t
unit_get_creation_time(const unit_t *unit)
{
	ASSERT(unit);
	u_time_t *time = compartment_module_get_instance_by_name(unit->compartment, "c_time");

	return u_time_get_creation_time(time);
}

time_t
unit_get_uptime(const unit_t *unit)
{
	ASSERT(unit);
	u_time_t *time = compartment_module_get_instance_by_name(unit->compartment, "c_time");

	return u_time_get_uptime(time);
}
