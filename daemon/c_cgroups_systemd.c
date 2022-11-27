/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
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
 * @file c_cgroups_systemd.c
 *
 * This submodule provides functionality to setup delegated scope in compliance
 * with systems runnig systemd.
 */

#define MOD_NAME "c_cgroups_systemd"

#include "common/macro.h"
#include "common/mem.h"
#include "common/uuid.h"

#include <stdbool.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-event.h>
#include <unistd.h>

#define CGROUPS_FOLDER "/sys/fs/cgroup"
#define CGROUPS_SYSTEMD_SCOPE_NAME "gyroidos.scope"

extern char *c_cgroups_subtree;

typedef struct {
	char *scope;
	bool job_completed;
	int err;
} systemd_jobremoved_cb_data_t;

static systemd_jobremoved_cb_data_t *
systemd_jobremoved_cb_data_new(const char *scope, bool job_completed, int err)
{
	systemd_jobremoved_cb_data_t *data = mem_new0(systemd_jobremoved_cb_data_t, 1);

	data->scope = mem_strdup(scope);
	data->job_completed = job_completed;
	data->err = err;

	return data;
}

static void
systemd_jobremoved_cb_data_free(systemd_jobremoved_cb_data_t *data)
{
	IF_NULL_RETURN(data);

	if (data->scope)
		mem_free0(data->scope);
	mem_free0(data);
}

static int
c_cgroups_systemd_jobremoved_cb(sd_bus_message *msg, void *userdata, UNUSED sd_bus_error *error)
{
	const char *path, *unit, *result;
	uint32_t id;

	systemd_jobremoved_cb_data_t *jobremoved_data = userdata;

	IF_TRUE_RETVAL(sd_bus_message_read(msg, "uoss", &id, &path, &unit, &result) < 0, -1);

	IF_TRUE_RETVAL((jobremoved_data->scope && strcmp(unit, jobremoved_data->scope) != 0), -1);

	DEBUG("systemd job completed");
	jobremoved_data->job_completed = true;

	if (strcmp(result, "done") != 0) {
		ERROR("systmed job executed but failed '%s'", result);
		jobremoved_data->err = -1;
	}

	return 0;
}

static int
c_cgroups_systemd_create_scope(const char *scope, pid_t pid)
{
	sd_bus *bus = NULL;
	sd_bus_message *msg = NULL, *reply = NULL;
	sd_bus_error err = SD_BUS_ERROR_NULL;
	char *path = NULL;

	systemd_jobremoved_cb_data_t *cb_data = systemd_jobremoved_cb_data_new(scope, false, 0);

	IF_TRUE_GOTO(sd_bus_default(&bus) < 0, error);

	IF_TRUE_GOTO(sd_bus_match_signal(bus, NULL, "org.freedesktop.systemd1",
					 "/org/freedesktop/systemd1",
					 "org.freedesktop.systemd1.Manager", "JobRemoved",
					 c_cgroups_systemd_jobremoved_cb, cb_data) < 0,
		     error);

	IF_TRUE_GOTO(sd_bus_message_new_method_call(
			     bus, &msg, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
			     "org.freedesktop.systemd1.Manager", "StartTransientUnit") < 0,
		     error);

	IF_TRUE_GOTO(sd_bus_message_append(msg, "ss", scope, "fail") < 0, error);

	IF_TRUE_GOTO(sd_bus_message_open_container(msg, 'a', "(sv)") < 0, error);
	IF_TRUE_GOTO(sd_bus_message_append(msg, "(sv)", "PIDs", "au", 1, pid) < 0, error);
	IF_TRUE_GOTO(sd_bus_message_append(msg, "(sv)", "Delegate", "b", 1) < 0, error);
	IF_TRUE_GOTO(sd_bus_message_append(msg, "(sv)", "CollectMode", "s", "inactive-or-failed") <
			     0,
		     error);
	IF_TRUE_GOTO(sd_bus_message_close_container(msg) < 0, error);

	IF_TRUE_GOTO(sd_bus_message_append(msg, "a(sa(sv))", 0) < 0, error);

	IF_TRUE_GOTO(sd_bus_call(NULL, msg, 0, &err, &reply) < 0, error);

	IF_TRUE_GOTO(sd_bus_message_read(reply, "o", path) < 0, error);

	while (!cb_data->job_completed) {
		int ret;
		IF_TRUE_GOTO((ret = sd_bus_process(bus, NULL)) < 0, error);

		if (ret != 0)
			continue;

		DEBUG("Waiting for job_completed on dbus!");
		IF_TRUE_GOTO(sd_bus_wait(bus, (uint64_t)-1) < 0, error);
	}

	IF_TRUE_GOTO(cb_data->err, error);
	INFO("Sucessfully created scope '%s'", cb_data->scope);

	systemd_jobremoved_cb_data_free(cb_data);
	return 0;

error:
	systemd_jobremoved_cb_data_free(cb_data);
	return -1;
}

static void INIT
c_cgroups_systemd_init(void)
{
	// overwrite c_cgroups_subtree (from c_cgroups_v2.c)
	if (c_cgroups_systemd_create_scope(CGROUPS_SYSTEMD_SCOPE_NAME, getpid())) {
		WARN("Failed to create systemd scope using dbus API! Falling back to '%s' cgroup",
		     c_cgroups_subtree ? c_cgroups_subtree : "root");
		return;
	}
}
