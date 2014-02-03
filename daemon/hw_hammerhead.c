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
 * @file hw_hammerhead.c
 *
 * This unit represents the hardware interface device specific implementation for hammerhead (Nexus 5).
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/event.h"

#include <cutils/properties.h>

#define LED_R "/sys/class/leds/red/brightness"
#define LED_G "/sys/class/leds/green/brightness"
#define LED_B "/sys/class/leds/blue/brightness"
#define LED_START "/sys/class/leds/red/rgb_start"
#define LED_R_ON_OFF_MS "/sys/class/leds/red/on_off_ms"
#define LED_G_ON_OFF_MS "/sys/class/leds/green/on_off_ms"
#define LED_B_ON_OFF_MS "/sys/class/leds/blue/on_off_ms"
#define LED_ON_DEFAULT 10000 /* Max value from kernel driver; should not be below 500 */
#define LED_OFF_DEFAULT 1	/* Min value from kernel driver */

/******************************************************************************/

static const char *hw_hammerhead_devices_whitelist_base[] = {
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
static const char *hw_hammerhead_devices_whitelist_priv[] = {
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
static const char *hw_hammerhead_devices_whitelist_audio[] = {
	"c 116:* rwm", // ALSA Audio
	NULL
};

static char *hw_hammerhead_serial_number = NULL;
static char *hw_hammerhead_name = NULL;

const char *
hardware_get_name(void)
{
	if (hw_hammerhead_name == NULL) {
		hw_hammerhead_name = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.hardware", hw_hammerhead_name, NULL) > 0)) {
			WARN("Failed to read hardware name property");
			mem_free(hw_hammerhead_name);
			hw_hammerhead_name = NULL;
		}
	}

	return hw_hammerhead_name;
}

const char *
hardware_get_manufacturer(void)
{
	// TODO check if this is the correct manufacturer string
	return "Google & LG Electronics";
}

const char *
hardware_get_model(void)
{
	// TODO return the proper "hardware model"
	return "hammerhead-model";
}

const char *
hardware_get_serial_number(void)
{
	if (hw_hammerhead_serial_number == NULL) {
		hw_hammerhead_serial_number = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.boot.serialno", hw_hammerhead_serial_number, NULL) > 0)) {
			WARN("Failed to read hardware serialno property");
			mem_free(hw_hammerhead_serial_number);
			hw_hammerhead_serial_number = NULL;
		}
	}

	return hw_hammerhead_serial_number;
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

static uint32_t led_color = 0;

static void
hardware_overwrite_led_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	//DEBUG("LED overwrite timer cb called");

	// TODO: check return values?
	file_printf(LED_START, "%d\n", 0);
	file_printf(LED_R_ON_OFF_MS, "%d %d\n", LED_ON_DEFAULT, LED_OFF_DEFAULT);
	file_printf(LED_G_ON_OFF_MS, "%d %d\n", LED_ON_DEFAULT, LED_OFF_DEFAULT);
	file_printf(LED_B_ON_OFF_MS, "%d %d\n", LED_ON_DEFAULT, LED_OFF_DEFAULT);
	IF_FALSE_RETURN(file_printf(LED_R, "%u\n", (led_color >> 24) & 0xff) >= 0);
	IF_FALSE_RETURN(file_printf(LED_G, "%u\n", (led_color >> 16) & 0xff) >= 0);
	IF_FALSE_RETURN(file_printf(LED_B, "%u\n", (led_color >>  8) & 0xff) >= 0);
	file_printf(LED_START, "%d\n", 1);
}

int
hardware_set_led(uint32_t color)
{
#ifndef DEBUG_BUILD
	static event_timer_t *overwrite_timer = NULL;

	//DEBUG("hardware_set_led() called");

	if (!overwrite_timer)
		overwrite_timer = event_timer_new(LED_ON_DEFAULT/2, EVENT_TIMER_REPEAT_FOREVER,
			&hardware_overwrite_led_cb, NULL);
#endif

	led_color = color;

	if (!((color >> 8) & 0xffffff)) {
		/* LED should be turned off */
		IF_FALSE_RETVAL(file_printf(LED_START, "%d\n", 0) >= 0, -1);
#ifndef DEBUG_BUILD
		event_remove_timer(overwrite_timer);
#endif
		return 0;
	}

#ifndef DEBUG_BUILD
	event_add_timer(overwrite_timer);
#endif

	hardware_overwrite_led_cb(NULL, NULL);

	return 0;
}

const char *
hardware_get_powerbutton_input_path(void)
{
	return "/dev/input/event0";
}

const char **
hardware_get_devices_whitelist_base()
{
	return hw_hammerhead_devices_whitelist_base;
}

const char **
hardware_get_devices_whitelist_priv()
{
	return hw_hammerhead_devices_whitelist_priv;
}

const char **
hardware_get_devices_whitelist_audio()
{
	return hw_hammerhead_devices_whitelist_audio;
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
	return "cpu,memory,freezer,devices";
}

list_t*
hardware_get_nw_name_list(void) {

	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "wlan0");
	nw_name_list = list_append(nw_name_list, "rmnet0");
	nw_name_list = list_append(nw_name_list, "p2p0");
	return nw_name_list;
}
