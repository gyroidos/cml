/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
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
#include "common/event.h"
#include "common/file.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>

#define FIFO_PATH "/dev/fifos"

typedef struct c_fifo {
	container_t *container;
	list_t *fifo_list;
	list_t *forwarder_list;
} c_fifo_t;

void *
c_fifo_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_fifo_t *fifo = mem_new0(c_fifo_t, 1);

	fifo->container = compartment_get_extension_data(compartment);

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

static char *
c_fifo_get_c0_path_new(c_fifo_t *fifo)
{
	pid_t c0_pid, target_pid;
	container_t *c0 = cmld_containers_get_c0();
	char *fifo_path_c0;

	if (c0 &&
	    (c0_pid = container_get_pid(c0)) != (target_pid = container_get_pid(fifo->container))) {
		fifo_path_c0 =
			mem_printf("/tmp/%s/%s", uuid_string(container_get_uuid(c0)), FIFO_PATH);

		TRACE("Creating c0 fifos at %s, ns_pid=%d", fifo_path_c0, c0_pid);
	} else if (cmld_is_hostedmode_active()) {
		fifo_path_c0 = mem_printf("/tmp/cmlfifos/");

		TRACE("Creating c0 FIFOs on host at %s", fifo_path_c0);
	} else {
		DEBUG("Could not get c0 instance, not preparing FIFOs for container %s",
		      container_get_name(fifo->container));
		return NULL;
	}

	return fifo_path_c0;
}

static char *
c_fifo_get_container_path_new(c_fifo_t *fifo)
{
	return mem_printf("/tmp/%s/%s/", uuid_string(container_get_uuid(fifo->container)),
			  FIFO_PATH);
}

static void
c_fifo_cleanup(void *fifop, UNUSED bool is_rebooting)
{
	c_fifo_t *fifo = (c_fifo_t *)fifop;
	ASSERT(fifo);

	char *fifo_path_c0 = c_fifo_get_c0_path_new(fifo);
	IF_NULL_RETURN_DEBUG(fifo_path_c0);

	while (fifo->forwarder_list) {
		pid_t *pid = fifo->forwarder_list->data;
		ASSERT(pid);
		ASSERT(0 < *pid);

		DEBUG("Stopping forwarder %d", *pid);
		kill(*pid, SIGKILL);
		waitpid(*pid, NULL, 0);

		mem_free(pid);
		fifo->forwarder_list = list_unlink(fifo->forwarder_list, fifo->forwarder_list);
	}

	// clean up FIFOs in c0
	// FIFOs in container are removed during c_vol cleanup
	for (list_t *elem = fifo->fifo_list; elem != NULL; elem = elem->next) {
		char *current_fifo = (char *)elem->data;
		if (!current_fifo)
			continue;

		char *current_path = mem_printf("%s/%s", fifo_path_c0, current_fifo);

		DEBUG("Removing FIFO at %s", current_path);
		if (0 != unlink(current_path)) {
			ERROR("Failed to remove FIFO at %s", current_path);
		}
		mem_free(current_path);
	}
}

static int
c_fifo_create_fifos(c_fifo_t *fifo, uid_t uid, const char *fifo_dir, const uuid_t *container_uuid)
{
	IF_NULL_RETVAL_ERROR(fifo, -1);
	IF_NULL_RETVAL_ERROR(fifo_dir, -1);
	const char *audit_subject;

	if (cmld_is_hostedmode_active()) {
		audit_subject = "";
	} else {
		IF_NULL_RETVAL_ERROR(container_uuid, -1);
		audit_subject = uuid_string(container_uuid);
	}

	DEBUG("Creating FIFO ends at path %s", fifo_dir);

	if (dir_mkdir_p(fifo_dir, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not create fifo_dir at %s", fifo_dir);
		goto error;
	}

	TRACE("Created FIFO dir: %s", fifo_dir);

	if (chown(fifo_dir, uid, uid)) {
		ERROR("Failed to chown fifo dir to %d", uid);
		goto error;
	}

	TRACE("Chowned FIFO dir at %s to %d", fifo_dir, uid);

	for (list_t *elem = fifo->fifo_list; elem != NULL; elem = elem->next) {
		char *current_fifo = elem->data;
		DEBUG("Preparing FIFO \'%s\'", current_fifo);

		char *fifo_path = mem_printf("%s/%s", fifo_dir, current_fifo);
		if (0 != mkfifo(fifo_path, 666)) {
			audit_log_event(container_uuid, FSA, CMLD, CONTAINER_ISOLATION,
					"create-fifo", audit_subject, 2, "name", current_fifo, 0);
			ERROR_ERRNO("Failed to create fifo at %s", fifo_path);

			mem_free0(fifo_path);
			goto error;
		}

		audit_log_event(container_uuid, SSA, CMLD, CONTAINER_ISOLATION, "create-fifo",
				audit_subject, 2, "name", current_fifo);

		if (chown(fifo_path, uid, uid)) {
			audit_log_event(container_uuid, FSA, CMLD, CONTAINER_ISOLATION,
					"prepare-fifo-directory", audit_subject, 2, "path",
					fifo_path);
			ERROR("Failed to chown fifo dir to %d", uid);

			mem_free0(fifo_path);
			goto error;
		}

		audit_log_event(container_uuid, SSA, CMLD, CONTAINER_ISOLATION,
				"prepare-fifo-directory", audit_subject, 2, "path", fifo_path);
		DEBUG("Chowned FIFO at %s to %d", fifo_path ? fifo_path : "NULL", uid);

		mem_free0(fifo_path);
	}

	return 0;

error:
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

		if (!file_is_fifo(fifo_path_c0)) {
			ERROR("Could not open FIFO at %s, stopping forwarder", fifo_path_c0);
			_exit(0);
		}

		if (-1 == (fromfd = open(fifo_path_c0, O_RDONLY))) {
			ERROR_ERRNO("Failed to open fromfd at %s, exiting...", fifo_path_c0);
			_exit(-1);
		}
		TRACE("Opened reading end for %s", fifo_path_c0);

		if (!file_is_fifo(fifo_path_container)) {
			ERROR("Could not open FIFO at %s, stopping forwarder", fifo_path_container);
			_exit(0);
		}

		if (-1 == (tofd = open(fifo_path_container, O_WRONLY))) {
			ERROR_ERRNO("Failed to open tofd at %s, exiting ...", fifo_path_container);
			_exit(-1);
		}
		TRACE("Opened writing end for %s", fifo_path_container);

		TRACE("Entering readloop with fromfd %d and tofd %d", fromfd, tofd);

		int count = 0;
		char buf[1024];

		while (0 < (count = read(fromfd, &buf, sizeof(buf) - 1))) {
			TRACE("[READLOOP] Read returned %d, writing to target FIFO", count);

			buf[count] = 0;
			TRACE("[READLOOP] Read %d bytes from fd: %d: %s", count, fromfd, buf);

			if (count != fd_write(tofd, buf, count)) {
				ERROR("Could not write all bytes to container FIFO end.");
				break;
			}
		}

		TRACE("[READLOOP] Read returned %d, try to reopen fds", count);
	}

	_exit(0);
}

static int
c_fifo_start_post_clone(void *fifop)
{
	c_fifo_t *fifo = fifop;
	ASSERT(fifo);

	container_t *c0 = cmld_containers_get_c0();
	int ret = -1;
	char *fifo_path_c0 = NULL, *fifo_path_container = NULL;
	uid_t c0uid;

	if (cmld_containers_get_c0() == fifo->container) {
		DEBUG("Skipping fifo creation for c0");
		return 0;
	}

	// create FIFOs in c0
	DEBUG("Creating FIFOs in c0");
	fifo_path_c0 = c_fifo_get_c0_path_new(fifo);
	IF_NULL_RETVAL_ERROR(fifo_path_c0, -1);

	if (cmld_is_hostedmode_active()) {
		c0uid = 0;
		if (-1 == c_fifo_create_fifos(fifo, c0uid, fifo_path_c0, NULL)) {
			ERROR("Failed to prepare container FIFOs on host");
			ret = -COMPARTMENT_ERROR_FIFO;
			goto error;
		}
	} else {
		c0uid = container_get_uid(c0);
		if (-1 == c_fifo_create_fifos(fifo, c0uid, fifo_path_c0,
					      container_get_uuid(cmld_containers_get_c0()))) {
			ERROR("Failed to prepare container FIFOs in c0");
			ret = -COMPARTMENT_ERROR_FIFO;
			goto error;
		}
	}

	// create FIFOs in container
	DEBUG("Creating FIFOs in target container");
	fifo_path_container = c_fifo_get_container_path_new(fifo);

	if (-1 == c_fifo_create_fifos(fifo, container_get_uid(fifo->container), fifo_path_container,
				      container_get_uuid(fifo->container))) {
		ERROR("Failed to prepare container FIFOs in target container");
		ret = -COMPARTMENT_ERROR_FIFO;

		goto error;
	}

	//fork FIFO forwarding childs
	for (list_t *elem = fifo->fifo_list; elem != NULL; elem = elem->next) {
		char *current_fifo = elem->data;
		char *current_fifo_c0 = mem_printf("%s/%s", fifo_path_c0, current_fifo);
		char *current_fifo_container =
			mem_printf("%s/%s", fifo_path_container, current_fifo);

		int pid = fork();

		if (-1 == pid) {
			ERROR("Failed to clone forwarding child");
			mem_free(current_fifo_c0);
			mem_free(current_fifo_container);

			ret = -COMPARTMENT_ERROR_FIFO;

			goto error;

		} else if (pid == 0) {
			DEBUG("Preparing forwarding for FIFO \'%s\'", current_fifo);

			DEBUG("Forwarding from %s to %s", current_fifo_c0, current_fifo_container);

			event_reset();

			c_fifo_loop(current_fifo_c0, current_fifo_container);

			_exit(EXIT_FAILURE);
		}

		mem_free(current_fifo_c0);
		mem_free(current_fifo_container);

		pid_t *mpid = mem_alloc(sizeof(pid_t));
		*mpid = pid;
		DEBUG("Appending %d to forwarder list", *mpid);
		fifo->forwarder_list = list_append(fifo->forwarder_list, mpid);

		DEBUG("Forked FIFO forwarding child %d for %s", pid, current_fifo);
	}

	ret = 0;

error:
	mem_free(fifo_path_c0);

	if (fifo_path_container)
		mem_free(fifo_path_container);

	return ret;
}

static compartment_module_t c_fifo_module = {
	.name = MOD_NAME,
	.compartment_new = c_fifo_new,
	.compartment_free = c_fifo_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = c_fifo_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_fifo_cleanup,
	.join_ns = NULL,
};

static void INIT
c_fifo_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_fifo_module);
}
