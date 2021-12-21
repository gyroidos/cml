/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#define _GNU_SOURCE

#define MOD_NAME "c_fifo"

#include "cmld.h"
#include "container.h"
#include "audit.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/ns.h"
#include "common/uuid.h"
#include "common/str.h"
#include "common/fd.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>

#define FIFO_PATH "/dev/fifos"

typedef struct c_fifo {
	container_t *container;
	list_t *fifo_list;
} c_fifo_t;

void *
c_fifo_new(container_t *container)
{
	ASSERT(container);

	c_fifo_t *fifo = mem_new0(c_fifo_t, 1);

	fifo->container = container;
	fifo->fifo_list = container_get_fifo_list(fifo->container);

	return fifo;
}

static void
c_fifo_free(void *fifop)
{
	c_fifo_t *fifo = fifop;
	ASSERT(fifo);
	mem_free0(fifo);
}

static int
c_fifo_create_fifos(c_fifo_t *fifo, container_t *container)
{
	IF_NULL_RETVAL_ERROR(fifo, -1);
	IF_NULL_RETVAL_ERROR(container, -1);

	char *fifo_dir;

	const char *uuid = uuid_string(container_get_uuid(container));
	IF_NULL_RETVAL_ERROR(uuid, -1);

	uid_t uid = container_get_uid(container);

	DEBUG("Creating FIFO ends for container %s with uid %d", uuid, uid);

	fifo_dir = mem_printf("/tmp/%s%s", uuid, FIFO_PATH);

	if (dir_mkdir_p(fifo_dir, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s dir for container %s", fifo_dir,
			    container_get_name(fifo->container));
		goto error;
	}

	TRACE("Created FIFO dir: %s", fifo_dir);

	if (chown(fifo_dir, uid, uid)) {
		ERROR("Failed to chown fifo dir to %d", uid);
		goto error;
	}

	TRACE("Chowned FIFO at %s to %d", fifo_dir, uid);

	for (list_t *elem = fifo->fifo_list; elem != NULL; elem = elem->next) {
		char *current_fifo = elem->data;
		DEBUG("Preparing FIFO \'%s\'", current_fifo);

		char *fifo_path = mem_printf("%s/%s", fifo_dir, current_fifo);
		if (0 != mkfifo(fifo_path, 666)) {
			ERROR_ERRNO("Failed to create fifo at %s", fifo_path);
			mem_free0(fifo_path);
			audit_log_event(container_get_uuid(fifo->container), FSA, CMLD,
					CONTAINER_ISOLATION, "create-fifo",
					uuid_string(container_get_uuid(fifo->container)), 2, "name",
					current_fifo, 0);
			goto error;
		}

		audit_log_event(container_get_uuid(fifo->container), SSA, CMLD, CONTAINER_ISOLATION,
				"create-fifo", uuid_string(container_get_uuid(fifo->container)), 2,
				"name", current_fifo);
		TRACE("Created FIFO at %s", fifo_path);

		if (chown(fifo_path, uid, uid)) {
			audit_log_event(container_get_uuid(fifo->container), FSA, CMLD,
					CONTAINER_ISOLATION, "prepare-fifo-directory",
					uuid_string(container_get_uuid(fifo->container)), 2, "path",
					fifo_path);
			ERROR("Failed to chown fifo dir to %d", uid);
			mem_free0(fifo_path);
			goto error;
		}

		audit_log_event(container_get_uuid(fifo->container), SSA, CMLD, CONTAINER_ISOLATION,
				"prepare-fifo-directory",
				uuid_string(container_get_uuid(fifo->container)), 2, "path",
				fifo_path);
		DEBUG("Chowned FIFO at %s to %d", fifo_path ? fifo_path : "NULL", uid);

		mem_free0(fifo_path);
	}

	mem_free0(fifo_dir);

	return 0;

error:
	mem_free0(fifo_dir);
	return -1;
}

static int
c_fifo_loop(char *fifo_path_c0, char *fifo_path_container)
{
	int fromfd = -1, tofd = -1;

	//keep repopening c0 FIFO when closed
	while (1) {
		if (fromfd != -1 && close(fromfd)) {
			TRACE_ERRNO("Failed to close old reading fd");
		}

		if (tofd != -1 && close(tofd)) {
			TRACE_ERRNO("Failed to close old reading fd");
		}

		if (-1 == (fromfd = open(fifo_path_c0, O_RDONLY))) {
			ERROR_ERRNO("Failed to open fromfd at %s, exiting...", fifo_path_c0);
			exit(-1);
		}
		TRACE("Opened reading end for %s", fifo_path_c0);

		if (-1 == (tofd = open(fifo_path_container, O_WRONLY))) {
			ERROR_ERRNO("Failed to open tofd at %s, exiting ...", fifo_path_container);
			exit(-1);
		}
		TRACE("Opened writing end for %s", fifo_path_container);

		TRACE("Entering readloop with fromfd %d and tofd %d", fromfd, tofd);

		int count = 0;
		char buf[1024];

		while (1) {
			if (0 < (count = read(fromfd, &buf, sizeof(buf) - 1))) {
				TRACE("[READLOOP] Read returned %d, writing to target FIFO", count);

				buf[count] = 0;
				TRACE("[READLOOP] Read %d bytes from fd: %d: %s", count, fromfd,
				      buf);

				if (count != fd_write(tofd, buf, count)) {
					ERROR("Could not write all bytes to container FIFO end.");
					break;
				}
			} else {
				TRACE("[READLOOP] Read returned %d, try to reopen fds", count);
			}
		}
	}
}

static int
c_fifo_start_post_clone(void *fifop)
{
	c_fifo_t *fifo = fifop;
	ASSERT(fifo);

	int c0_pid = -1, target_pid = -1;
	container_t *c0 = cmld_containers_get_c0();

	if (c0 &&
	    (c0_pid = container_get_pid(c0)) != (target_pid = container_get_pid(fifo->container))) {
		DEBUG("Creating FIFOs in c0, ns_pid=%d", c0_pid);

		if (-1 == c_fifo_create_fifos(fifo, c0)) {
			ERROR("Failed to prepare container FIFOs in c0");
			return -CONTAINER_ERROR_FIFO;
		}

		DEBUG("Creating FIFOs in target container, ns_pid=%d", target_pid);

		if (-1 == c_fifo_create_fifos(fifo, fifo->container)) {
			ERROR("Failed to prepare container FIFOs in target container");
			return -CONTAINER_ERROR_FIFO;
		}

		//fork FIFO forwarding child
		for (list_t *elem = fifo->fifo_list; elem != NULL; elem = elem->next) {
			char *current_fifo = elem->data;

			int pid = fork();

			if (-1 == pid) {
				ERROR("Failed to clone forwarding child");
				return -CONTAINER_ERROR_FIFO;
			} else if (pid == 0) {
				DEBUG("Preparing forwarding for FIFO \'%s\'", current_fifo);

				char *fifo_path_c0 = mem_printf("/tmp/%s/%s/%s",
								uuid_string(container_get_uuid(c0)),
								FIFO_PATH, current_fifo);
				char *fifo_path_container =
					mem_printf("/tmp/%s/%s/%s",
						   uuid_string(container_get_uuid(fifo->container)),
						   FIFO_PATH, current_fifo);

				DEBUG("Forwarding from %s to %s", fifo_path_c0,
				      fifo_path_container);

				c_fifo_loop(fifo_path_c0, fifo_path_container);

				exit(EXIT_FAILURE);
			}

			DEBUG("Forked FIFO forwarding child %d for %s", pid, current_fifo);
		}

	} else {
		DEBUG("Could not get c0 instance, not preparing FIFOs for container %s",
		      container_get_name(fifo->container));
	}

	return 0;
}

static container_module_t c_fifo_module = {
	.name = MOD_NAME,
	.container_new = c_fifo_new,
	.container_free = c_fifo_free,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = c_fifo_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL, // FIXME provide proper cleanup handling
	.join_ns = NULL,
};

static void INIT
c_fifo_init(void)
{
	// register this module in container.c
	container_register_module(&c_fifo_module);
}
