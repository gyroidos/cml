/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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

#include "sock-sd.h"

#include <systemd/sd-daemon.h>
#include <unistd.h>
#include <string.h>

int
sock_sd_listen_fd(char *fd_name)
{
	int fds = sd_listen_fds(0);
	int fd = -1;
	if (fds < 0) {
		WARN("sd_listen_fds failed with %d", fds);
	} else if (fds == 0) {
		WARN("Systemd passed no file descriptor");
	} else {
		if (fd_name) {
			// get file descriptor by name
			char **fd_names = NULL;
			fds = sd_listen_fds_with_names(0, &fd_names);
			for (int i = 0; i < fds; i++) {
				DEBUG("%s = fd %d", fd_names[i], SD_LISTEN_FDS_START + i);
				if (strcmp(fd_name, fd_names[i]) == 0) {
					fd = SD_LISTEN_FDS_START + i;
					break;
				}
			}
		} else {
			// fd_name == NULL --> just take first fd
			fd = SD_LISTEN_FDS_START;
		}
	}
	return fd;
}
