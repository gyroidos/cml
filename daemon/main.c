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

/**
 * \mainpage The main CML daemon handling all containers etc.
 *
 * A good starting point is container.c (representing a container object)
 * and cmld.c (the central component of the container mangement layer daemon).
 */

#include "common/macro.h"
#include "common/event.h"
#include "common/file.h"
#include "common/logf.h"

#include "cmld.h"
#include "hardware.h"
#include "power.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#define DEFAULT_BASE_PATH "/data/cml"

static logf_handler_t *cml_daemon_logfile_handler = NULL;
static bool is_handling_sigint = false;

/******************************************************************************/

static void
main_core_dump_enable(void)
{
	struct rlimit core_limit;

	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
		ERROR_ERRNO("Could not set rlimits for core dump generation");
}

static void
main_exit(void)
{
	exit(0);
}

static void
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	if (is_handling_sigint)
		FATAL("Received SIGINT twice..");
	else
		INFO("Received SIGINT..");

	is_handling_sigint = true;
	if (cmld_containers_stop(&main_exit) < 0)
		ERROR("Could not stop all containers");
}

static void
main_sigterm_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGTERM..");
	if (cmld_containers_stop(&main_exit) < 0)
		ERROR("Could not stop all containers");
}

static void
main_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	DEBUG("Logfile will be closed and a new file opened");
	logf_unregister(cml_daemon_logfile_handler);
	cml_daemon_logfile_handler =
		logf_register(&logf_file_write, logf_file_new("/data/logs/cml-daemon"));
	logf_handler_set_prio(cml_daemon_logfile_handler, LOGF_PRIO_WARN);
}

/******************************************************************************/

int
main(int argc, char **argv)
{
	const char *path;

	if (file_exists("/dev/log/main"))
		logf_register(&logf_android_write, logf_android_new(argv[0]));
	else
		logf_register(&logf_klog_write, logf_klog_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	// TODO: where should we store the log files?
	// TODO: disable for non developer builds?
	cml_daemon_logfile_handler =
		logf_register(&logf_file_write, logf_file_new("/data/logs/cml-daemon"));
	logf_handler_set_prio(cml_daemon_logfile_handler, LOGF_PRIO_TRACE);

	main_core_dump_enable();

	INFO("Starting...");
	INFO("Device hardware is %s", hardware_get_name());

	if (argc >= 2)
		path = strdup(argv[1]);
	else
		path = DEFAULT_BASE_PATH;

	event_init();
	// TODO: remove for production builds?
	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig_int);

	event_signal_t *sig_term = event_signal_new(SIGTERM, &main_sigterm_cb, NULL);
	event_add_signal(sig_term);

	DEBUG("Initializing cmld...");
	event_timer_t *logfile_timer =
		event_timer_new(HOURS_TO_MILLISECONDS(24), EVENT_TIMER_REPEAT_FOREVER,
				main_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	if (cmld_init(path) < 0)
		FATAL("Could not init cmld");

	event_loop();

	return 0;
}
