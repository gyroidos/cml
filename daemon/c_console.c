/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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
 * @file c_console.c
 *
 * This module provides a per-container console. A pty is allocated at
 * container start and its slave is bound as the container's /dev/console, so
 * the container's init and getty use it as their console. The master is held
 * by cmld and drained until a control client attaches to it, which lets a
 * client reconnect to the running console across disconnects (docker attach).
 */

#define _GNU_SOURCE

#define MOD_NAME "c_console"

#include "container.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/event.h"
#include "common/fd.h"

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <termios.h>

/* large enough to swallow a full-screen redraw while draining */
#define C_CONSOLE_DRAIN_BUF_SIZE (64 * 1024)

typedef struct c_console {
	container_t *container;
	int master; /* console pty master held by cmld, -1 if unavailable */
	char *slave_name;
	int attached_fd; /* control client fd forwarding the console, -1 if none */
	event_io_t *drain_io;
} c_console_t;

static void *
c_console_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_console_t *console = mem_new0(c_console_t, 1);
	console->container = compartment_get_extension_data(compartment);
	console->master = -1;
	console->attached_fd = -1;

	return console;
}

static void
c_console_free(void *consolep)
{
	c_console_t *console = consolep;
	ASSERT(console);

	if (console->slave_name)
		mem_free0(console->slave_name);
	mem_free0(console);
}

/*
 * Discards console output while no client is attached, so the container's
 * init never blocks writing to its console before or between attaches.
 */
static void
c_console_drain_cb(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	ASSERT(data);
	c_console_t *console = data;

	if (events & EVENT_IO_EXCEPT) {
		TRACE("Exception on console master fd %d", fd);
		if (console->drain_io) {
			event_remove_io(console->drain_io);
			event_io_free(console->drain_io);
			console->drain_io = NULL;
		}
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	uint8_t buf[C_CONSOLE_DRAIN_BUF_SIZE];
	ssize_t n;
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		; // drop output while detached
}

static void
c_console_drain_start(c_console_t *console)
{
	if (console->master < 0 || console->drain_io)
		return;

	console->drain_io = event_io_new(console->master, EVENT_IO_READ | EVENT_IO_EXCEPT,
					 c_console_drain_cb, console);
	event_add_io(console->drain_io);
}

static void
c_console_drain_stop(c_console_t *console)
{
	if (!console->drain_io)
		return;

	event_remove_io(console->drain_io);
	event_io_free(console->drain_io);
	console->drain_io = NULL;
}

/*
 * Allocate the console pty and bind its slave as the container's
 * /dev/console. Runs in cmld (host mount ns) on the container's root tree
 * before the container's init is executed, after c_vol has populated /dev.
 */
static int
c_console_start_pre_exec(void *consolep)
{
	c_console_t *console = consolep;
	ASSERT(console);

	char *root = container_get_rootdir(console->container);
	if (!root) {
		WARN("No rootdir for container %s, skipping console setup",
		     container_get_description(console->container));
		return 0;
	}

	char *console_path = mem_printf("%s/dev/console", root);

	int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (master < 0) {
		WARN_ERRNO("Could not allocate console pty for %s",
			   container_get_description(console->container));
		goto out;
	}
	if (grantpt(master) < 0 || unlockpt(master) < 0) {
		WARN_ERRNO("Could not grant/unlock console pty for %s",
			   container_get_description(console->container));
		close(master);
		master = -1;
		goto out;
	}

	char slave_name[100];
	if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
		WARN_ERRNO("Could not get console pty slave name");
		close(master);
		master = -1;
		goto out;
	}

	/*
	 * give the slave to the container's root in its user namespace so init
	 * can open /dev/console; grantpt() set it to cmld's (host) root
	 */
	int uid = container_get_uid(console->container);
	if (chown(slave_name, uid, uid) < 0)
		WARN_ERRNO("Could not chown console pty slave %s", slave_name);

	// replace whatever /dev/console the /dev copy produced with the pty slave
	if (file_exists(console_path) && unlink(console_path) < 0)
		WARN_ERRNO("Could not remove existing %s", console_path);
	if (file_touch(console_path) < 0) {
		WARN_ERRNO("Could not create console bind target %s", console_path);
		close(master);
		master = -1;
		goto out;
	}
	if (mount(slave_name, console_path, NULL, MS_BIND, NULL) < 0) {
		WARN_ERRNO("Could not bind %s onto %s", slave_name, console_path);
		close(master);
		master = -1;
		goto out;
	}

	fd_make_non_blocking(master);
	console->master = master;
	console->slave_name = mem_strdup(slave_name);

	// drain from the start so early boot output never blocks init
	c_console_drain_start(console);

	DEBUG("Set up console pty (master fd %d, slave %s) for %s", master, slave_name,
	      container_get_description(console->container));

out:
	mem_free0(console_path);
	return 0;
}

static void
c_console_cleanup(void *consolep, UNUSED bool is_rebooting)
{
	c_console_t *console = consolep;
	ASSERT(console);

	c_console_drain_stop(console);

	/*
	 * remove the bind mount of the pty slave on the container's
	 * /dev/console (made in the host mount ns). It must be a synchronous
	 * umount: /dev/console is a child of the shared tmpfs /dev, itself a
	 * child of the verity root. A lazy MNT_DETACH here would leave c_vol
	 * (CLEANUP_LATE) to lazily unmount /dev and the root too, so the verity
	 * dm device would still be busy when c_vol tries to remove it.
	 */
	if (console->slave_name) {
		char *root = container_get_rootdir(console->container);
		if (root) {
			char *console_path = mem_printf("%s/dev/console", root);
			if (umount(console_path) < 0 && errno != ENOENT && errno != EINVAL) {
				WARN_ERRNO("Could not unmount console bind %s, detaching lazily",
					   console_path);
				if (umount2(console_path, MNT_DETACH) < 0)
					WARN_ERRNO("Could not detach console bind %s",
						   console_path);
			}
			mem_free0(console_path);
		}
	}

	if (console->master >= 0) {
		close(console->master);
		console->master = -1;
	}
	console->attached_fd = -1;
	if (console->slave_name) {
		mem_free0(console->slave_name);
		console->slave_name = NULL;
	}
}

static int
c_console_attach(void *consolep, int session_fd)
{
	c_console_t *console = consolep;
	ASSERT(console);

	if (console->master < 0) {
		ERROR("No console available for container %s",
		      container_get_description(console->container));
		return -1;
	}

	// stop discarding output; the control module forwards the master now
	c_console_drain_stop(console);
	console->attached_fd = session_fd;

	return 0;
}

static int
c_console_detach(void *consolep, int session_fd)
{
	c_console_t *console = consolep;
	ASSERT(console);

	// only the currently attached client detaches the console
	if (console->attached_fd != session_fd)
		return 0;

	console->attached_fd = -1;

	// resume discarding output so init does not block while detached
	c_console_drain_start(console);

	return 0;
}

static int
c_console_get_master(void *consolep)
{
	c_console_t *console = consolep;
	ASSERT(console);

	return console->master;
}

static int
c_console_write_input(void *consolep, const uint8_t *input, size_t len, int session_fd)
{
	c_console_t *console = consolep;
	ASSERT(console);

	// only the attached client may inject input
	if (console->master < 0 || console->attached_fd != session_fd)
		return -1;
	if (len == 0)
		return 0;

	size_t total = 0;
	while (total < len) {
		ssize_t n = write(console->master, input + total, len - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			// pty buffer full: the container is not reading its console
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			ERROR_ERRNO("Could not write input to console");
			return -1;
		}
		total += n;
	}

	return total;
}

static int
c_console_set_winsize(void *consolep, uint16_t rows, uint16_t cols, int session_fd)
{
	c_console_t *console = consolep;
	ASSERT(console);

	if (console->master < 0 || console->attached_fd != session_fd)
		return -1;

	struct winsize ws = { .ws_row = rows, .ws_col = cols };
	if (ioctl(console->master, TIOCSWINSZ, &ws) < 0) {
		WARN_ERRNO("Could not set console winsize (%hu x %hu)", rows, cols);
		return -1;
	}

	return 0;
}

static compartment_module_t c_console_module = {
	.name = MOD_NAME,
	.compartment_new = c_console_new,
	.compartment_free = c_console_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = c_console_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_console_cleanup,
	.join_ns = NULL,
};

static void INIT
c_console_init(void)
{
	// register this module in container.c
	container_register_compartment_module(&c_console_module);

	// register relevant handlers implemented by this module
	container_register_console_attach_handler(MOD_NAME, c_console_attach);
	container_register_console_detach_handler(MOD_NAME, c_console_detach);
	container_register_console_get_master_handler(MOD_NAME, c_console_get_master);
	container_register_console_write_input_handler(MOD_NAME, c_console_write_input);
	container_register_console_set_winsize_handler(MOD_NAME, c_console_set_winsize);
}

static void DEINIT
c_console_deinit(void)
{
	container_unregister_console_attach_handler(MOD_NAME, c_console_attach);
	container_unregister_console_detach_handler(MOD_NAME, c_console_detach);
	container_unregister_console_get_master_handler(MOD_NAME, c_console_get_master);
	container_unregister_console_write_input_handler(MOD_NAME, c_console_write_input);
	container_unregister_console_set_winsize_handler(MOD_NAME, c_console_set_winsize);

	container_unregister_compartment_module(&c_console_module);
}
