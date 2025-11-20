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

/**
 * @file u_service.c
 *
 * This module is responsible for checking socket connection with the service
 * located in the associated unit. It is responsible to switch compartment state
 * if the service is up and running inside the unit.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_service"

#include "common/event.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "compartment.h"
#include "unit.h"

#include <sys/inotify.h>
#include <sys/stat.h>

typedef struct u_service {
	unit_t *unit; //!< unit which the u_service struct is associated to
	compartment_t *compartment;
	compartment_callback_t *state_observer;
	event_inotify_t *inotify_sock_dir;
} u_service_t;

/**
 * This function allocates a new u_service_t instance, associated to a specific unit object.
 * @return the u_service_t servicework structure which holds serviceworking information for an unit.
 */
static void *
u_service_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_service_t *service = mem_new0(u_service_t, 1);
	service->unit = compartment_get_extension_data(compartment);
	service->compartment = compartment;

	return service;
}

/**
 * Frees the u_service_t structure
 */
static void
u_service_free(void *servicep)
{
	u_service_t *service = servicep;
	ASSERT(service);

	if (service->inotify_sock_dir) {
		event_remove_inotify(service->inotify_sock_dir);
		event_inotify_free(service->inotify_sock_dir);
	}

	mem_free0(service);
}

static void
u_service_do_create_cb(const char *path, uint32_t mask, UNUSED event_inotify_t *inotify, void *data)
{
	IF_FALSE_RETURN(mask & IN_CREATE);

	u_service_t *service = data;
	ASSERT(service);

	int sock = -1;

	struct stat s;
	mem_memset(&s, 0, sizeof(s));

	if (stat(path, &s) == -1) {
		WARN_ERRNO("Could not stat %s", path);
		return;
	}

	IF_FALSE_RETURN((s.st_mode & S_IFMT) == S_IFSOCK);

	IF_FALSE_RETURN(strstr(path, unit_get_sock_name(service->unit)));

	size_t retries = 0;
	sock = sock_unix_create_and_connect(unit_get_sock_type(service->unit), path);
	while (sock < 0 && retries < 10) {
		TRACE("Retry %zu connecting to %s", retries, path);
		NANOSLEEP(0, 500000000)
		sock = sock_unix_create_and_connect(unit_get_sock_type(service->unit), path);
		retries++;
	}

	if (sock < 0) {
		ERROR("Failed to connect to %s", unit_get_sock_name(service->unit));
		return;
	}

	// service inside unit has socket communictaion setup done and is up -> switch state
	compartment_set_state(service->compartment, COMPARTMENT_STATE_RUNNING);

	char *sock_path = mem_strdup(path);
	(unit_get_on_sock_connect_cb(service->unit))(sock, sock_path);
	mem_free0(sock_path);
}

static void
u_service_state_observer_cb(compartment_t *compartment, compartment_callback_t *cb, void *data)
{
	ASSERT(compartment && data);
	u_service_t *service = data;

	switch (compartment_get_state(compartment)) {
	case COMPARTMENT_STATE_BOOTING: {
		if (NULL == unit_get_on_sock_connect_cb(service->unit))
			break;

		// watch sock_dir for socket to appear in filesystem
		service->inotify_sock_dir =
			event_inotify_new(unit_get_sock_dir(service->unit), IN_CREATE,
					  u_service_do_create_cb, service);

		/* start watching for unit socket creation */
		int error = event_add_inotify(service->inotify_sock_dir);
		if (error && error != -EEXIST) {
			WARN("Could not register inotify event for unit %s socket events!",
			     unit_get_description(service->unit));
		}
	} break;
	case COMPARTMENT_STATE_STOPPED: {
		compartment_unregister_observer(service->compartment, cb);

		if (service->inotify_sock_dir) {
			event_remove_inotify(service->inotify_sock_dir);
			event_inotify_free(service->inotify_sock_dir);
			service->inotify_sock_dir = NULL;
		}

		/* auto restart unit if it was stopped */
		if (unit_get_restart(service->unit)) {
			INFO("unit %s stopped, restarting unit ...",
			     unit_get_description(service->unit));
			if (unit_start(service->unit) < 0)
				WARN("unit %s could not be restarted!",
				     unit_get_description(service->unit));
		}

	} break;
	default:
		return;
	}
}

static int
u_service_start_pre_clone(void *servicep)
{
	u_service_t *service = servicep;
	ASSERT(service);

	service->state_observer = compartment_register_observer(
		service->compartment, &u_service_state_observer_cb, service);
	if (!service->state_observer) {
		ERROR("Could not register unit state observer callback for %s",
		      unit_get_description(service->unit));
		return -COMPARTMENT_ERROR_SERVICE;
	}

	if (NULL == unit_get_on_sock_connect_cb(service->unit)) {
		// if no socket is set in unit, switch diretcly to state running
		compartment_set_state(service->compartment, COMPARTMENT_STATE_RUNNING);
	}

	return 0;
}

static compartment_module_t u_service_module = {
	.name = MOD_NAME,
	.compartment_new = u_service_new,
	.compartment_free = u_service_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = u_service_start_pre_clone,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_pre_exec_child_early = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
u_service_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_service_module);
}
