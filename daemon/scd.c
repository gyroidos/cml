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
#include "unit.h"

#include "common/macro.h"
#include "common/logf.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/proc.h"
#include "common/protobuf.h"
#include "common/mem.h"

// clang-format off
#define SCD_CONTROL_SOCKET "scd_control"
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

#define SCD_UUID "00000000-0000-0000-0000-000000000001"

char *scd_sock_path = NULL;

static unit_t *scd_unit;

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
	return;
}

static void
scd_on_connect_cb(int sock, const char *sock_path)
{
	ASSERT(sock_path);
	if (scd_register_listener(sock) < 0) {
		ERROR("Failed to register event listener for scd events");
		if (scd_sock_path)
			mem_free0(scd_sock_path);
		close(sock);
		return;
	}

	if (scd_sock_path)
		mem_free0(scd_sock_path);
	scd_sock_path = mem_strdup(sock_path);

	/* register socket for receiving data */
	fd_make_non_blocking(sock);

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, &scd_event_cb_recv_message, NULL);
	event_add_io(event);

	if (cmld_init_stage_container() < 0)
		FATAL("Could not init cmld (container stage)!");
}

int
scd_init(void)
{
	// if device.cert is not present, scd will die. Hence, we set autorestart in unit_new
	scd_unit = unit_new(uuid_new(SCD_UUID), "SCD", SCD_BINARY_NAME, NULL, NULL, 0, false,
			    SCD_TOKEN_DIR, SCD_CONTROL_SOCKET, &scd_on_connect_cb, true);

	IF_NULL_RETVAL(scd_unit, -1);

	if (unit_start(scd_unit)) {
		unit_free(scd_unit);
		ERROR("Could nor start unit for scd!");
		return -1;
	}

	return 0;
}

void
scd_cleanup(void)
{
	unit_kill(scd_unit);
	if (scd_sock_path)
		mem_free0(scd_sock_path);
	unit_free(scd_unit);
}
