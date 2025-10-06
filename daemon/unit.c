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

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"
#include "common/uuid.h"
#include "compartment.h"

#include <stdint.h>

struct unit {
	compartment_t *compartment;
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
	 size_t env_len, bool netns)
{
	// set type specific flags for compartment
	uint64_t flags = 0;
	flags |= COMPARTMENT_FLAG_TYPE_CONTAINER;
	// set namespace flags for compartment
	flags |= COMPARTMENT_FLAG_NS_USER;
	if (netns)
		flags |= COMPARTMENT_FLAG_NS_NET;

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
	compartment_kill(unit->compartment);
}
