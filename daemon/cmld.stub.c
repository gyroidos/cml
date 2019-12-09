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

#include "cmld.stub.h"
#include "container.stub.h"

#include "common/uuid.h"
#include "common/list.h"
#include "common/str.h"
#include "common/macro.h"

//#include <stdio.h>

static list_t *g_containers = NULL;
static int g_nr_containers = 0;
static container_t *g_foreground = NULL;

static int g_feedback_fd;

/****************************************/
/*** Helper functions for unit test.  ***/
/****************************************/
void
cmld_stub_init(int fd)
{
	g_feedback_fd = fd;
}

container_t *
cmld_stub_container_create(const char *container_name)
{
	container_t *container = container_stub_new(container_name);
	if (container) {
		g_containers = list_append(g_containers, (void *)container);
		++g_nr_containers;
	}
	return container;
}

#if PLATFORM_VERSION_MAJOR < 5
/**
 * Implementation for missing dprintf(int fd, ...).
 */
static int
dprintf(int fd, const char *format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	char buf[4096];
	int len = vsnprintf(buf, sizeof(buf), format, argptr);
	va_end(argptr);
	write(fd, buf, len);
	return len;
}
#endif

/************************************/
/*** Stubbed CMLD API functions.  ***/
/************************************/

int
cmld_container_destroy(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	--g_nr_containers;
	g_containers = list_remove(g_containers, (void *)container);
	if (g_foreground == container) {
		if (g_nr_containers > 0)
			cmld_container_switch(cmld_container_get_by_index(0));
		else
			g_foreground = NULL;
	}

	container_free(container);

	return 0;
}

int
cmld_container_switch(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	if (container && list_find(g_containers, (void *)container)) {
		g_foreground = container;
		return 0;
	}
	return -1;
}

int
cmld_container_start(container_t *container, const char *key, bool no_switch)
{
	dprintf(g_feedback_fd, "%s: %s, key=%s, no_switch=%s", __func__, container_get_name(container),
		key ? key : "NULL", no_switch ? "true" : "false");

	if (!no_switch)
		cmld_container_switch(container);

	return 0;
}

int
cmld_container_start_with_smartcard(container_t *container, const char *passwd, bool no_switch)
{
	return cmld_container_start(container, passwd, no_switch);
}

int
cmld_container_stop(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

int
cmld_container_freeze(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

int
cmld_container_unfreeze(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

int
cmld_container_snapshot(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

int
cmld_container_wipe(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

void
cmld_wipe_device()
{
	return;
}

container_t *
cmld_container_get_by_uuid(uuid_t *uuid)
{
	if (uuid)
		for (list_t *l = g_containers; l; l = l->next) {
			container_t *container = (container_t *)l->data;
			const uuid_t *c_uuid = container_get_uuid(container);
			if (c_uuid && uuid_equals(uuid, c_uuid))
				return container;
		}
	return NULL;
}

container_t *
cmld_containers_get_foreground(void)
{
	return g_foreground;
}

int
cmld_containers_get_count()
{
	return g_nr_containers;
}

container_t *
cmld_container_get_by_index(int index)
{
	if (index >= 0 && index < g_nr_containers)
		for (list_t *l = g_containers; l; l = l->next, index--) {
			if (0 == index)
				return (container_t *)l->data;
		}

	return NULL;
}

const char *
cmld_get_device_uuid(void)
{
	return "bd42af59-e003-4426-84ef-d3a9c1dce8fd";
}

container_t *
cmld_containers_get_a0()
{
	return cmld_container_get_by_index(0);
}

int
cmld_container_allow_audio(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}

int
cmld_container_deny_audio(container_t *container)
{
	dprintf(g_feedback_fd, "%s: %s", __func__, container_get_name(container));

	return 0;
}
