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

#include <stdbool.h>

/**
 * Initialize the lxcfs submodule, gather pathes and start daemon.
 *
 * @return 0 if sucessfully initialized, -1 otherwise
 */
int
lxcfs_init(void);

/**
 * Cleanup the lxcfs submodule, mainly stop daemon.
 */
void
lxcfs_cleanup(void);

/**
 * Checks if userland and kernel supports lxcfs
 *
 * @return ture if lxcfs is supported, false if not
 */
bool
lxcfs_is_supported(void);

/**
 * Apply lxcfs provided virualization of proc files
 *
 * @param target Target proc directory for bind mounts
 * @return 0 on success, -1 otherwise
 */
int
lxcfs_mount_proc_overlay(char *target);
