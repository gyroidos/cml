/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 *
 * @file hw_x86.c
 *
 * This unit represents the hardware interface device specific implementation for x86.
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/event.h"

#define BOOT_BL_BRIGHTNESS 26

/******************************************************************************/
static char *hw_x86_name = "x86";

const char *
hardware_get_name(void)
{
	return hw_x86_name;
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
