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

#include "container.h"

#include "common/macro.h"
#include "common/mem.h"

int
main(UNUSED int argc, UNUSED char **argv)
{
	// Init logging
	logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_register(&logf_klog_write, logf_klog_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	DEBUG("test");

	container_t *container = container_new("/opt/trustme/containers/", NULL, "dummy conf", 0);

	int sock;
	if ((sock = container_bind_socket_before_start(container, "/test.sock")) < 0) {
		WARN("Binding socket before start failed");
	}

	int ret;
	if ((ret = container_start(container))) {
		switch (ret) {
			case CONTAINER_ERROR:
			case CONTAINER_ERROR_UEVENT:
				/* etc. pp. */
			default:
				FATAL_ERRNO("Starting a0 failed");
		}
	}
}
