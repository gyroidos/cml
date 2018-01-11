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
 * @file hw_deb.c
 *
 * This unit represents the hardware interface device specific implementation for deb (Nexus 7 Mobile).
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"

#include <cutils/properties.h>
#define LED_W "/sys/class/leds/white/brightness"

#define DEVICE_ALLOW_ALL

/******************************************************************************/

/******************************************************************************/
#ifndef DEVICE_ALLOW_ALL
static const char *hw_deb_devices_whitelist_base[] = {
	/*************/
	/* Character */

	/********/
	/* MISC */
	"c 10:37 rwm", // cpu_dma_latency
	"c 10:39 rwm", // xt_qtaguid

	/* probably radio/audio related */
	"c 10:41 rwm", // msm_rtac
	"c 10:42 rwm", // msm_acdb

	/* android stuff */
	"c 10:43 rwm", // system
	"c 10:44 rwm", // radio
	"c 10:45 rwm", // events
	"c 10:46 rwm", // main
	"c 10:47 rwm", // ashmem
	"c 10:48 rwm", // binder
	"c 10:51 rwm", // alarm

	"c 10:52 rwm", // keychord
	"c 10:54 rwm", // usb_accessory

	"c 10:63 rwm", // bcm2079x
	"c 10:86 rwm", // smem_log
	"c 10:95 rwm", // ion

	/* qseecom,  kgsl-3d0 kernel graphics support layer. (Adreno stuff), diag */
	"c 244:0 rwm",
	"c 245:0 rwm",
	"c 246:0 rwm",
	"c 248:99 rwm", //ttyHS99 serial  Bluetooth
	"c 250:0 rwm", // sensors

	"c 251:* rwm", // smdcntl*

	"c 252:* rwm", // media*

	"c 253:* rwm", // rtc*

	/*************/
	/* Block     */
	//"b 179:0 rwm", // mmcblk0

	NULL
};

/**
 * List of devices allowed additionally in privileged containers.
 */
static const char *hw_deb_devices_whitelist_priv[] = {
	"c 1:1 rwm", // /dev/mem

	/* The following are all modem related and therefore currently necessary at least
	 * for the privileged container */
	/* It seems they are primarily used by the rmt_storage process */
	"b 179:12 rwm", // mmcblk0p12 -> modemst1
	"b 179:13 rwm", // mmcblk0p13 -> modemst2
	"b 179:21 rwm", // mmcblk0p21 -> fsg
	"b 179:22 rwm", // mmcblk0p22 -> fsc
	/* the "ssd" partition does not seem to be strictly necessary, but since it is
	 * definitely modem-related and we want to exclude sources of problems we still
	 * allow a0 access to it */
	"b 179:23 rwm", // mmcblk0p23 -> ssd

	NULL
};

/**
 * List of audio devices
 */
static const char *hw_deb_devices_whitelist_audio[] = {
	"c 116:* rwm", // ALSA Audio
	NULL
};
#endif // !DEVICE_ALLOW_ALL

static char *hw_deb_serial_number = NULL;
static char *hw_deb_name = NULL;

const char *
hardware_get_name(void)
{
	if (hw_deb_name == NULL) {
		hw_deb_name = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.hardware", hw_deb_name, NULL) > 0)) {
			WARN("Failed to read hardware name property");
			mem_free(hw_deb_name);
			hw_deb_name = NULL;
		}
	}

	return hw_deb_name;
}

const char *
hardware_get_manufacturer(void)
{
	// TODO check if this is the correct manufacturer string
	return "Google & Asus";
}

const char *
hardware_get_model(void)
{
	// TODO return the proper "hardware model"
	return "deb-model";
}

const char *
hardware_get_serial_number(void)
{
	if (hw_deb_serial_number == NULL) {
		hw_deb_serial_number = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.boot.serialno", hw_deb_serial_number, NULL) > 0)) {
			WARN("Failed to read hardware serialno property");
			mem_free(hw_deb_serial_number);
			hw_deb_serial_number = NULL;
		}
	}

	return hw_deb_serial_number;
}

const char *
hardware_get_bootimg_path(void)
{
	return "/dev/block/platform/msm_sdcc.1/by-name/boot";
}

const char *
hardware_get_block_by_name_path(void)
{
	return "/dev/block/platform/msm_sdcc.1/by-name";
}

int
hardware_set_led(uint32_t color)
{
	/* There is only one white LED, ignore color */
	IF_FALSE_RETVAL(file_printf(LED_W, "%u\n", color ? 255 : 0) >= 0, -1);
	return 0;
}

const char *
hardware_get_powerbutton_input_path(void)
{
	return "/dev/input/event5";
}

#ifdef DEVICE_ALLOW_ALL
static const char *devices_whitelist_allow_all[] = { "a *:* rwm", NULL };
#endif

const char **
hardware_get_devices_whitelist_base()
{
#ifdef DEVICE_ALLOW_ALL
	return devices_whitelist_allow_all;
#else
	return hw_deb_devices_whitelist_base;
#endif
}

const char **
hardware_get_devices_whitelist_priv()
{
#ifdef DEVICE_ALLOW_ALL
	return devices_whitelist_allow_all;
#else
	return hw_deb_devices_whitelist_priv;
#endif
}

const char **
hardware_get_devices_whitelist_audio()
{
#ifdef DEVICE_ALLOW_ALL
	return devices_whitelist_allow_all;
#else
	return hw_deb_devices_whitelist_audio;
#endif
}

int
hardware_backlight_on()
{
	char *max_brightness;
	if (!(max_brightness = file_read_new("/sys/class/leds/lcd-backlight/max_brightness", 20))) {
		WARN_ERRNO("Could not read max_brightness file");
		return -1;
	}
	if (file_printf("/sys/class/leds/lcd-backlight/brightness", "%s", max_brightness) < 0) {
		WARN_ERRNO("Could not write brightness file");
		free(max_brightness);
		return -1;
	}
	free(max_brightness);
	return 0;
}

const char *
hardware_get_active_cgroups_subsystems(void)
{
	return "cpu,freezer,devices";
}

list_t*
hardware_get_nw_name_list(void) {

	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "wlan0");
	nw_name_list = list_append(nw_name_list, "rmnet0");
	nw_name_list = list_append(nw_name_list, "p2p0");
	return nw_name_list;
}

bool
hardware_supports_systemv_ipc(void)
{
	return true;
}
