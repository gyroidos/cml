/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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
 * @file reboot.h
 *
 * Provides utility function to reboot and poweroff the machine.
 */

#ifndef REBOOT_H
#define REBOOT_H

enum command { REBOOT, POWER_OFF };

/**
 * Reboots the system or performs a related action.
 *
 * @param cmd  the command describing a precise action to be performed, e.g., reboot or poweroff
 * @return  0 on success, -1 on failure. In case the system was successfully
 * restarted or stopped, the call does not return.
 */
int
reboot_reboot(int cmd);

#endif // REBOOT_H
