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

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/list.h"
#include "common/sock.h"
#include "common/uuid.h"
#include "compartment.h"

#include <stdint.h>
#include <sys/inotify.h>
#include <sys/stat.h>

struct unit {
	compartment_t *compartment;
	char *sock_name;
	event_inotify_t *inotify_sock_dir;
	void (*on_sock_connect_cb)(int sock, const char *sock_path);
	compartment_callback_t *state_observer;
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

static void
unit_do_create_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify, void *data)
{
	IF_FALSE_RETURN(mask & IN_CREATE);

	unit_t *unit = data;
	ASSERT(unit);

	int sock = -1;

	struct stat s;
	mem_memset(&s, 0, sizeof(s));

	if (stat(path, &s) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	IF_FALSE_RETURN((s.st_mode & S_IFMT) == S_IFSOCK);

	IF_FALSE_RETURN(strstr(path, unit->sock_name));

	size_t retries = 0;
	sock = sock_unix_create_and_connect(SOCK_SEQPACKET, path);
	while (sock < 0 && retries < 10) {
		TRACE("Retry %zu connecting to %s", retries, path);
		NANOSLEEP(0, 500000000)
		sock = sock_unix_create_and_connect(SOCK_SEQPACKET, path);
		retries++;
	}

	if (sock < 0) {
		ERROR("Failed to connect to %s", unit->sock_name);
		return;
	}

	char *sock_path = mem_strdup(path);
	(unit->on_sock_connect_cb)(sock, sock_path);
	mem_free0(sock_path);
}

static void
unit_state_observer_cb(compartment_t *compartment, UNUSED compartment_callback_t *cb, void *data)
{
	ASSERT(compartment && data);
	unit_t *unit = data;

	switch (compartment_get_state(compartment)) {
	case COMPARTMENT_STATE_RUNNING: {
		// watch sock_dir for scd control socket to appear in filesystem
		unit->inotify_sock_dir = event_inotify_new(unit_get_sock_dir(unit), IN_CREATE,
							   unit_do_create_cb, unit);

		/* start watching for unit socket creation */
		int error = event_add_inotify(unit->inotify_sock_dir);
		if (error && error != -EEXIST) {
			WARN("Could not register inotify event for unit %s socket events!",
			     unit_get_description(unit));
		}
	} break;
	case COMPARTMENT_STATE_STOPPED: {
		event_remove_inotify(unit->inotify_sock_dir);
		event_inotify_free(unit->inotify_sock_dir);
		unit->inotify_sock_dir = NULL;

		/* auto restart unit if it was stopped */
		if (unit->restart) {
			INFO("unit %s stopped, restarting unit ...", unit_get_description(unit));
			if (unit_start(unit) < 0)
				WARN("unit %s could not be restarted!", unit_get_description(unit));
		}

	} break;
	default:
		return;
	}
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
	 size_t env_len, bool netns, const char *sock_name,
	 void (*on_sock_connect_cb)(int sock, const char *sock_path), bool restart)
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

	unit->sock_name = mem_strdup(sock_name);
	unit->on_sock_connect_cb = on_sock_connect_cb;

	unit->restart = restart;

	if (unit->on_sock_connect_cb) {
		unit->state_observer = compartment_register_observer(unit->compartment,
								     &unit_state_observer_cb, unit);
		if (!unit->state_observer) {
			WARN("Could not register unit state observer callback for %s",
			     unit_get_description(unit));
		}
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

	if (unit->sock_name)
		mem_free0(unit->sock_name);

	if (unit->inotify_sock_dir) {
		event_remove_inotify(unit->inotify_sock_dir);
		event_inotify_free(unit->inotify_sock_dir);
	}

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

	unit->restart = false;
	compartment_kill(unit->compartment);

	if (unit->on_sock_connect_cb)
		compartment_unregister_observer(unit->compartment, unit->state_observer);
}
