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

/**
 * @file sock-sd.h
 *
 * Provides utility functions to work with Systemd sockets.
 */

#ifndef SOCK_SD_H
#define SOCK_SD_H

#include "macro.h"

/**
 * Get the filedescriptor of a Systemd managed socket
 * 
 * @param fd_name   The name of the fd as set by Systemd or NULL if there is only one
 * @return      fd on success, -1 on error
*/
#ifdef SYSTEMD
int
sock_sd_listen_fd(char *fd_name);
#else
int
sock_sd_listen_fd(UNUSED char *fd_name)
{
	return -1;
}
#endif // SYSTEMD

#endif // SOCK_SD_H
