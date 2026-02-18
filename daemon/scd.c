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
#include "tss.h"
#include "tpm2d_shared.h"
#include "cmld.h"
#include "unit.h"

#include "common/macro.h"
#include "common/logf.h"
#include "common/dir.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"
#include "common/list.h"
#include "common/proc.h"
#include "common/protobuf.h"
#include "common/mem.h"
#include "common/sock.h"

#include <sys/inotify.h>

// clang-format off
#define SCD_CONTROL_SOCKET "scd_control"
// clang-format on

#ifndef SCD_BINARY_NAME
#define SCD_BINARY_NAME "scd"
#endif

#define SCD_DEVICE_ID_CONF SCD_TOKEN_DIR "/device_id.conf"

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

	/* notify containers about (re-)connection of the scd */
	for (int i = 0; i < cmld_containers_get_count(); i++) {
		container_t *container = cmld_container_get_by_index(i);
		if (container_scd_connect(container))
			ERROR("could not reconnect icontainer %s to scd!",
			      container_get_description(container));
	}

	cmld_init_stage_unit_notify(scd_unit);
}

static void
scd_tpm2d_inotify_written_cb(const char *path, uint32_t mask, event_inotify_t *inotify, void *data)
{
	IF_FALSE_RETURN(mask & IN_CLOSE_WRITE);

	unit_t *scd_unit = data;
	ASSERT(scd_unit);

	DEBUG("%s created", path);

	IF_TRUE_RETURN(strcmp(path, TPM2D_ATT_TSS_FILE));

	INFO("Provisioning by tpm2d finished: %s written.", path);

	if (unit_start(scd_unit) < 0) {
		unit_free(scd_unit);
		FATAL("Could not start unit for scd!");
	}

	event_remove_inotify(inotify);
	event_inotify_free(inotify);
}

int
scd_init(void)
{
	// ensure device_id configuration file is located in SCD_TOKEN_DIR
	char *legacy_device_id_path = mem_printf("%s/%s", cmld_get_cmld_dir(), "device_id.conf");
	if (file_is_regular(legacy_device_id_path) &&
	    file_move(legacy_device_id_path, SCD_DEVICE_ID_CONF, 512) < 0) {
		ERROR("Moving device_id.conf from old location %s to %s failed!",
		      legacy_device_id_path, SCD_DEVICE_ID_CONF);
		mem_free(legacy_device_id_path);
		return -1;
	}
	mem_free(legacy_device_id_path);

	// if device.cert is not present, scd will die. Hence, we set autorestart in unit_new
	scd_unit = unit_new(uuid_new(SCD_UUID), "SCD", SCD_BINARY_NAME, NULL, NULL, 0, true,
			    SCD_TOKEN_DIR, SCD_CONTROL_SOCKET, SOCK_SEQPACKET, &scd_on_connect_cb,
			    true);

	IF_NULL_RETVAL(scd_unit, -1);

	// scd also accesses the tpm for device cert signing
	list_t *dev_nodes = list_append(NULL, "/dev/tpm0");
	unit_device_set_initial_allow(scd_unit, dev_nodes);
	list_delete(dev_nodes);

	/*
	 * if tpm is not supported or tpm2d provisioning is already done
	 * just start scd unit else start inotify watch for device key
	 */
	if (file_exists(TPM2D_ATT_TSS_FILE) || !file_exists("/dev/tpm0") ||
	    !tss_is_tpm2d_installed()) {
		if (unit_start(scd_unit) < 0) {
			ERROR("Could not start unit for scd!");
			goto error;
		}
	} else {
		const char *token_dir = TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR;
		if (!file_is_dir(token_dir) && dir_mkdir_p(token_dir, 0755) < 0) {
			ERROR_ERRNO("Could not mkdir dir: %s for device key", token_dir);
			goto error;
		}
		// wait for tpm2d generated device key
		event_inotify_t *inotify_devkey = event_inotify_new(
			token_dir, IN_CLOSE_WRITE, scd_tpm2d_inotify_written_cb, scd_unit);

		// start watching for device key creation
		int error = event_add_inotify(inotify_devkey);
		if (error && error != -EEXIST) {
			ERROR("Could not register inotify event watching for device key of unit %s!",
			      unit_get_description(scd_unit));
			goto error;
		}
	}

	cmld_init_stage_unit_notify(scd_unit);
	return 0;

error:
	unit_free(scd_unit);
	return -1;
}

void
scd_cleanup(void)
{
	unit_kill(scd_unit);
	if (scd_sock_path)
		mem_free0(scd_sock_path);
	unit_free(scd_unit);
}

unit_t *
scd_get_unit(void)
{
	return scd_unit;
}
