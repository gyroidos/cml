/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#ifdef ANDROID
#include "device/fraunhofer/common/cml/service/c_service.pb-c.h"
#else
#include "c_service.pb-c.h"
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/logf.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"

#include <unistd.h>

// clang-format off
#define SERVICE_SOCKET SOCK_PATH(service)
// clang-format on

int
main(int argc, char **argv)
{
	logf_register(&logf_file_write, stdout);

	IF_TRUE_RETVAL(argc < 2, -1);

	const char *socket_file = SERVICE_SOCKET;
	if (!file_exists(socket_file))
		FATAL("Could not find socket file %s. Aborting.", socket_file);

	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0)
		FATAL("Could not connect to service on socket file %s. Aborting.", socket_file);

	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__EXEC_CAP_SYSTIME_PRIV;
	msg.captime_exec_path = argv[1];
	msg.n_captime_exec_param = argc - 2;
	msg.captime_exec_param = mem_new0(char *, argc - 2);
	for (int i = 0; i < argc - 2; ++i) {
		msg.captime_exec_param[i] = argv[i + 2];
		TRACE("param[%d]: %s", i, msg.captime_exec_param[i]);
	}

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)&msg);
	if (msg_size < 0)
		FATAL("Could not send exec request to cmld!, error: %zd\n", msg_size);

	// closing socket to cmld
	close(sock);

	mem_free(msg.captime_exec_param);
	return 0;
}
