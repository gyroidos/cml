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

#include "scd.pb-c.h"

#include "scd.h"
#include "scd_shared.h"
#include "cmld.h"

#include "common/macro.h"
#include "common/logf.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/sock.h"
#include "common/proc.h"
#include "common/protobuf.h"
#include "common/mem.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

// clang-format off
#define SCD_CONTROL_SOCKET "scd_control"
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

char *scd_sock_path = NULL;

static pid_t scd_pid;

static pid_t
scd_fork_and_exec(void)
{
	TRACE("Starting scd..");

	int status;
	pid_t pid = fork();
	char *const param_list[] = { SCD_BINARY_NAME, NULL };

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", SCD_BINARY_NAME);
		return -1;
	case 0:
		execvp((const char *)param_list[0], param_list);
		FATAL_ERRNO("Could not execvp %s", SCD_BINARY_NAME);
		return -1;
	default:
		// Just check if the child is alive but do not wait
		if (waitpid(pid, &status, WNOHANG) != 0) {
			ERROR("Failed to start %s", SCD_BINARY_NAME);
			return -1;
		}
		return pid;
	}
	return -1;
}

static int
scd_register_listener(int fd)
{
	int ret = -1;
	DaemonToToken out = DAEMON_TO_TOKEN__INIT;
	out.code = DAEMON_TO_TOKEN__CODE__REGISTER_EVENT_LISTENER;

	if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
		ERROR("Failed to send message to scd on fd %d", fd);
		return -1;
	}

	TokenToDaemon *msg =
		(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);
	if (!msg) {
		ERROR("Failed to get response from scd. Aborting scd_register_listener.");
		return -1;
	}

	switch (msg->code) {
	case TOKEN_TO_DAEMON__CODE__REGISTER_EVENT_LISTENER_OK: {
		TRACE("Successfully registered this cmld instance as event listener on scd.");
		ret = 0;
	} break;
	case TOKEN_TO_DAEMON__CODE__REGISTER_EVENT_LISTENER_ERROR: {
		ERROR("Registering this cmld instance as event listener on scd failed!");
	} break;
	default:
		ERROR("TokenToDaemon command %d not expected as answer to REGISTER_EVENT_LISTENER",
		      msg->code);
	}

	protobuf_free_message((ProtobufCMessage *)msg);
	return ret;
}

static void
scd_event_cb_recv_message(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	/*
	 * always check READ flag first, since also if the peer called close()
	 * and there is pending data on the socket the READ and EXCEPT flags are set.
	 * Thus, we have to read pending date before handling the EXCEPT event.
	 */
	if (events & EVENT_IO_READ) {
		TokenToDaemon *msg =
			(TokenToDaemon *)protobuf_recv_message(fd, &token_to_daemon__descriptor);

		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		switch (msg->code) {
		case TOKEN_TO_DAEMON__CODE__TOKEN_SE_REMOVED:
			if (msg->token_uuid) {
				uuid_t *c_uuid = uuid_new(msg->token_uuid);
				container_t *container = cmld_container_get_by_uuid(c_uuid);
				mem_free0(c_uuid);
				if (container)
					cmld_container_stop(container);

			} else {
				ERROR("Missing token_uuid in TOKEN_SE_REMOVED event");
			}
			break;
		default:
			ERROR("Invalid TokenToDaemon event %d", msg->code);
		}
		TRACE("Handled scd event connection %d", fd);
		protobuf_free_message((ProtobufCMessage *)msg);
	}
	// also check EXCEPT flag
	if (events & EVENT_IO_EXCEPT) {
		INFO("scd closed event connection; reconnect.");
		goto connection_err;
	}
	return;

connection_err:
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected scd event socket");
	// reconnect
	scd_init(false);
	return;
}

int
scd_init(bool start_daemon)
{
	int sock = -1;

	// In hosted mode, the init scripts should take care of correct scd initialization and start-up
	if (start_daemon) {
		// if device.cert is not present, start scd to initialize device (provisioning mode)
		if (!file_exists(DEVICE_CERT_FILE)) {
			INFO("Starting scd in Provisioning / Installing Mode");
			// Start the SCD in provisioning mode
			const char *const args[] = { SCD_BINARY_NAME, NULL };
			IF_FALSE_RETVAL_TRACE(proc_fork_and_execvp(args) == 0, -1);
		}

		// Start SCD and wait for control interface
		scd_pid = scd_fork_and_exec();
		IF_TRUE_RETVAL_TRACE(scd_pid == -1, -1);
	} else {
		DEBUG("Skipping scd launch as requested");
		scd_pid = -1;
	}

	scd_sock_path = sock_get_path_new(SCD_CONTROL_SOCKET);
	size_t retries = 0;
	do {
		NANOSLEEP(0, 500000000)
		sock = sock_unix_create_and_connect(SOCK_SEQPACKET, scd_sock_path);
		retries++;
		TRACE("Retry %zu connecting to scd", retries);
	} while (sock < 0 && retries < 10);

	if (sock < 0) {
		ERROR("Failed to connect to scd");
		close(sock);
		return -1;
	}

	if (scd_register_listener(sock) < 0) {
		ERROR("Failed to register event listener for scd events");
		close(sock);
		return -1;
	}

	/* register socket for receiving data */
	fd_make_non_blocking(sock);

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, scd_event_cb_recv_message, NULL);
	event_add_io(event);

	// allow access from namespaced child before chroot and execv of init
	if (chmod(scd_sock_path, 00777))
		WARN("could not change access rights for scd control socket");

	return 0;
}

void
scd_cleanup(void)
{
	IF_TRUE_RETURN_TRACE(scd_pid == -1);
	DEBUG("Stopping %s process with pid=%d!", SCD_BINARY_NAME, scd_pid);
	mem_free(scd_sock_path);
	scd_sock_path = NULL;
	kill(scd_pid, SIGTERM);
}
