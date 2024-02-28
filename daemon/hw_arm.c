/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2019 Fraunhofer AISEC
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
 *
 * @file hw_arm.c
 *
 * This unit represents the hardware interface device specific implementation for a generic ARM architecture.
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/event.h"

#define BOOT_BL_BRIGHTNESS 26

/******************************************************************************/
static char *hw_arm_name = "arm";

const char *
hardware_get_name(void)
{
	return hw_arm_name;
}

list_t *
hardware_get_active_cgroups_subsystems(void)
{
	list_t *subsys_list = NULL;
	subsys_list = list_append(subsys_list, "net_cls,net_prio");
	subsys_list = list_append(subsys_list, "devices");
	subsys_list = list_append(subsys_list, "cpuset");
	subsys_list = list_append(subsys_list, "memory");
	subsys_list = list_append(subsys_list, "perf_event");
	subsys_list = list_append(subsys_list, "cpu,cpuacct");
	subsys_list = list_append(subsys_list, "blkio");
	subsys_list = list_append(subsys_list, "freezer");
	subsys_list = list_append(subsys_list, "pids");
	return subsys_list;
}

list_t *
hardware_get_nw_name_list(void)
{
	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "eth0");
	return nw_name_list;
}

int
hardware_get_random(unsigned char *buf, size_t len)
{
	const char *rnd = "/dev/hwrng";
	const char *sw = "/dev/random";

	int bytes_read = file_read(rnd, (char *)buf, len);
	if (bytes_read > 0 && (size_t)bytes_read == len) {
		return bytes_read;
	} else {
		if (!file_exists(sw)) {
			ERROR("Failed to retrieve random numbers. Neither random number generator %s or %s could be accessed!",
			      rnd, sw);
			return -1;
		}
		WARN("Could not access %s, falling back to %s. Check if device provides a hardware random number generator.",
		     rnd, sw);
		return file_read(sw, (char *)buf, len);
	}
}
