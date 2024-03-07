/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
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
#include "lxcfs.h"
#include "tss.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

logf_handler_t *cml_daemon_logfile_handler = NULL;
static void *main_logfile_p = NULL;
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
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	if (is_handling_sigint)
		FATAL("Received SIGINT twice..");
	else
		INFO("Received SIGINT..");

	is_handling_sigint = true;
	if (cmld_containers_stop(&exit, 0) < 0)
		ERROR("Could not stop all containers");
}

static void
main_sigterm_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGTERM..");
	if (cmld_containers_stop(&exit, 0) < 0)
		ERROR("Could not stop all containers");
}

static void
main_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	DEBUG("Logfile will be closed and a new file opened");
	logf_unregister(cml_daemon_logfile_handler);
	logf_file_close(main_logfile_p);

	main_logfile_p = logf_file_new(LOGFILE_DIR "/cml-daemon");
	cml_daemon_logfile_handler = logf_register(&logf_file_write, main_logfile_p);
	logf_handler_set_prio(cml_daemon_logfile_handler, LOGF_PRIO_TRACE);
}

static void INIT
main_init(void)
{
	logf_register(&logf_file_write, stdout);

	main_logfile_p = logf_file_new(LOGFILE_DIR "/cml-daemon");
	cml_daemon_logfile_handler = logf_register(&logf_file_write, main_logfile_p);
	logf_handler_set_prio(cml_daemon_logfile_handler, LOGF_PRIO_TRACE);

	main_core_dump_enable();
}

/******************************************************************************/

int
main(int argc, char **argv)
{
	const char *path;

	INFO("Starting...");

	if (argc >= 2)
		path = strdup(argv[1]);
	else
		path = DEFAULT_BASE_PATH;

	event_init();

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

	if (atexit(&cmld_cleanup))
		WARN("could not register on exit cleanup method 'cmld_cleanup()'");

	event_loop();

	return 0;
}
