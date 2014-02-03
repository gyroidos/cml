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

#include "control.c"
#include "device/fraunhofer/common/cml/daemon/control.pb-c.h"

#include "cmld.stub.h"
#include "container.stub.h"
#include "cmld.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/str.h"
#include "common/protobuf.h"
#include "common/sock.h"

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

/**
 * Helper function to create a socket pair.
 */
void make_socketpair(int fds[2])
{
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1) {
		perror("socketpair");
		exit(EXIT_FAILURE);
	}
}

int main()
{
	logf_register(&logf_test_write, stdout);

	// SETUP test environment
	INFO("Unit test: setup");
	int cmld_fd[2]; // 0=read, 1=write
	make_socketpair(cmld_fd);
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(cmld_fd[0], SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

	cmld_stub_init(cmld_fd[1]);
	UNUSED container_t *a0 = cmld_stub_container_create("A0");
	UNUSED container_t *a1 = cmld_stub_container_create("A1");
	control_t *control = control_local_new(SOCK_PATH(control));
	event_loop();
	control_free(control);

	return 0;
}
