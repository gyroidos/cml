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

#include <cutils/properties.h>

#define BOOT_BL_BRIGHTNESS 26

/******************************************************************************/
static const char *hw_x86_devices_whitelist_base[] = {
	"a *:* rwm", // allow all FIXME
	NULL
};

/**
 * List of devices allowed additionally in privileged containers.
 */
static const char *hw_x86_devices_whitelist_priv[] = {
	"a *:* rwm", // allow all FIXME
	NULL
};

/**
 * List of audio devices
 */
static const char *hw_x86_devices_whitelist_audio[] = {
	"a *:* rwm", // allow all FIXME
	NULL
};

static char *hw_x86_serial_number = "00000000";
static char *hw_x86_name = "x86";

const char *
hardware_get_name(void)
{
	return hw_x86_name;
}

const char *
hardware_get_manufacturer(void)
{
	// TODO check if this is the correct manufacturer string
	return "Intel / AMD";
}

const char *
hardware_get_model(void)
{
	// TODO return the proper "hardware model"
	return "x86-model";
}

const char *
hardware_get_serial_number(void)
{
	return hw_x86_serial_number;
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

static uint32_t led_color = 0;

int
hardware_set_led(uint32_t color, bool should_blink)
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

const char **
hardware_get_devices_whitelist_base()
{
	return hw_x86_devices_whitelist_base;
}

const char **
hardware_get_devices_whitelist_priv()
{
	return hw_x86_devices_whitelist_priv;
}

const char **
hardware_get_devices_whitelist_audio()
{
	return hw_x86_devices_whitelist_audio;
}

int
hardware_backlight_on()
{
	if (file_printf("/sys/class/leds/lcd-backlight/brightness", "%d", BOOT_BL_BRIGHTNESS) < 0) {
		WARN_ERRNO("Could not write brightness file");
		return -1;
	}
	return 0;
}

const char *
hardware_get_active_cgroups_subsystems(void)
{
	return "cpu,memory,freezer,devices";
}

list_t*
hardware_get_nw_name_list(void) {

	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "eth0");
	return nw_name_list;
}
