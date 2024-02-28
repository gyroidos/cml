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
 * @file hw_ppc.c
 *
 * This unit represents the hardware interface device specific implementation for PowerPC.
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/event.h"

/******************************************************************************/
static char *hw_ppc_serial_number = "00000000";
static char *hw_ppc_name = "ppc";

const char *
hardware_get_name(void)
{
	return hw_ppc_name;
}

const char *
hardware_get_manufacturer(void)
{
	// TODO check if this is the correct manufacturer string
	return "N/A";
}

const char *
hardware_get_model(void)
{
	// TODO return the proper "hardware model"
	return "PowerPC";
}

const char *
hardware_get_serial_number(void)
{
	return hw_ppc_serial_number;
}

const char *
hardware_get_bootimg_path(void)
{
	//return "/dev/block/platform/msm_sdcc.1/by-name/boot";
	return NULL;
}

const char *
hardware_get_block_by_name_path(void)
{
	//return "/dev/block/platform/msm_sdcc.1/by-name";
	return NULL;
}

int
hardware_set_led(UNUSED uint32_t color, UNUSED bool should_blink)
{
	return 0;
}

bool
hardware_is_led_on(void)
{
	return false;
}

const char *
hardware_get_powerbutton_input_path(void)
{
	return NULL;
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

list_t *
hardware_get_active_cgroups_subsystems(void)
{
	list_t *subsys_list = NULL;
	subsys_list = list_append(subsys_list, "devices");
	subsys_list = list_append(subsys_list, "cpu");
	subsys_list = list_append(subsys_list, "memory");
	subsys_list = list_append(subsys_list, "freezer");
	return subsys_list;
}

list_t *
hardware_get_nw_name_list(void)
{
	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "eth0");
	return nw_name_list;
}

const char *
hardware_get_routing_table_radio(void)
{
	return "";
}

const char *
hardware_get_radio_ifname(void)
{
	return NULL;
}

bool
hardware_supports_systemv_ipc(void)
{
	return false;
}

list_t *
hardware_get_nw_mv_name_list(void)
{
	/*
         * this list should start with the first mobile data iface
         * which is usually rmnet0
         */
	return NULL;
}
