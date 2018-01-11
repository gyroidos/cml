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
 * @file hw_bullhead.c
 *
 * This unit represents the hardware interface device specific implementation for bullhead (Nexus 5X).
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/event.h"

#include <cutils/properties.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define LED_R "/sys/class/leds/red/brightness"
#define LED_G "/sys/class/leds/green/brightness"
#define LED_B "/sys/class/leds/blue/brightness"
#define LED_START "/sys/class/leds/red/rgb_start"
#define LED_R_ON_OFF_MS "/sys/class/leds/red/on_off_ms"
#define LED_G_ON_OFF_MS "/sys/class/leds/green/on_off_ms"
#define LED_B_ON_OFF_MS "/sys/class/leds/blue/on_off_ms"

#define LED_ON_DEFAULT 10000 /* Max value from kernel driver; should not be below 500 */
#define LED_OFF_DEFAULT 1	/* Min value from kernel driver */

#define LED_ON_BLINK 500
#define LED_OFF_BLINK 3000

#define BOOT_BL_BRIGHTNESS 26

/******************************************************************************/
static const char *hw_bullhead_devices_whitelist_base[] = {
	"a *:* rwm", // all
	NULL
};

/**
 * List of devices allowed additionally in privileged containers.
 */
static const char *hw_bullhead_devices_whitelist_priv[] = {
	"a *:* rwm", // all
	NULL
};

/**
 * List of audio devices
 */
static const char *hw_bullhead_devices_whitelist_audio[] = {
	"c 116:* rwm", // ALSA Audio
	NULL
};

static char *hw_bullhead_serial_number = NULL;
static char *hw_bullhead_name = NULL;

const char *
hardware_get_name(void)
{
	if (hw_bullhead_name == NULL) {
		hw_bullhead_name = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.hardware", hw_bullhead_name, NULL) > 0)) {
			WARN("Failed to read hardware name property");
			mem_free(hw_bullhead_name);
			hw_bullhead_name = NULL;
		}
	}

	return hw_bullhead_name;
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
	return "bullhead-model";
}

const char *
hardware_get_serial_number(void)
{
	if (hw_bullhead_serial_number == NULL) {
		hw_bullhead_serial_number = mem_alloc0(PROPERTY_VALUE_MAX);

		if (!(property_get("ro.boot.serialno", hw_bullhead_serial_number, NULL) > 0)) {
			WARN("Failed to read hardware serialno property");
			mem_free(hw_bullhead_serial_number);
			hw_bullhead_serial_number = NULL;
		}
	}

	return hw_bullhead_serial_number;
}

const char *
hardware_get_bootimg_path(void)
{
	return "/dev/block/platform/soc.0/f9824900.sdhci/by-name/boot";
}

const char *
hardware_get_block_by_name_path(void)
{
	return "/dev/block/platform/soc.0/f9824900.sdhci/by-name";
}

int
hardware_set_led(uint32_t color, bool should_blink)
{
	int led_time_on, led_time_off;

	if (!(color >> 8)) {
		/* LED should be turned off */
		IF_FALSE_RETVAL(file_printf(LED_START, "%d\n", 0) >= 0, -1);
		return 0;
	}

	if (should_blink) {
		led_time_on = LED_ON_BLINK;
		led_time_off = LED_OFF_BLINK;
	} else {
		led_time_on = LED_ON_DEFAULT;
		led_time_off = LED_OFF_DEFAULT;
	}

	file_printf(LED_START, "%d\n", 0);
	file_printf(LED_R_ON_OFF_MS, "%d %d\n", led_time_on, led_time_off);
	file_printf(LED_G_ON_OFF_MS, "%d %d\n", led_time_on, led_time_off);
	file_printf(LED_B_ON_OFF_MS, "%d %d\n", led_time_on, led_time_off);
	IF_FALSE_RETVAL(file_printf(LED_R, "%u\n", (color >> 24) & 0xff) >= 0, -1);
	IF_FALSE_RETVAL(file_printf(LED_G, "%u\n", (color >> 16) & 0xff) >= 0, -1);
	IF_FALSE_RETVAL(file_printf(LED_B, "%u\n", (color >>  8) & 0xff) >= 0, -1);
	file_printf(LED_START, "%d\n", 1);

	return 0;
}

bool
hardware_is_led_on()
{
	char led_start = 0;

	if (file_read(LED_START, &led_start, 1) < 0) {
		return false;
	}

	if (led_start == '1') {
		return true;
	}

	return false;
}

const char *
hardware_get_powerbutton_input_path(void)
{
	return "/dev/input/event2";
}

const char **
hardware_get_devices_whitelist_base()
{
	return hw_bullhead_devices_whitelist_base;
}

const char **
hardware_get_devices_whitelist_priv()
{
	return hw_bullhead_devices_whitelist_priv;
}

const char **
hardware_get_devices_whitelist_audio()
{
	return hw_bullhead_devices_whitelist_audio;
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

list_t*
hardware_get_nw_mv_name_list(void)
{
	/*
	 * this list should start with the first mobile data iface
	 * which is usually rmnet0
	 */
	list_t *nw_name_list = NULL;
	nw_name_list = list_append(nw_name_list, "rmnet_ipa0");
	return nw_name_list;
}

const char *
hardware_get_radio_ifname(void)
{
	return "rmnet_data0";
}

bool
hardware_supports_systemv_ipc(void)
{
	return false;
}

const char *
hardware_get_routing_table_radio(void)
{
	return "1004";
}

/*
 * keep this in sync with the corresponding
 * kernel header "include/uapi/linux/input.h"
 */
#define KEY_POWER_INJECT        0x2a0

int
hardware_get_key_power_inject(void)
{
	return KEY_POWER_INJECT;
}

#define SYSFS_DISPLAY_POWER_STATE_FILE "/sys/devices/soc.0/fd900000.qcom,mdss_mdp/power/runtime_status"

/******************************************************************************/

static bool prev_display_power_state = true;

bool
hardware_display_power_state(void)
{
	char buf[65] = { 0 };
	int fd;

	fd = open(SYSFS_DISPLAY_POWER_STATE_FILE, O_RDONLY);
	if (fd < 0) {
		WARN("Could not open sysfs display power status file");
		return prev_display_power_state;
	}

	if (read(fd, &buf, sizeof(buf) - 1) <= 0) {
		WARN("Could not read sysfs display power status");
		return prev_display_power_state;
	}

	prev_display_power_state = !!strncmp("suspended", buf, strlen("suspended"));

	//INFO("%s state %s read", SYSFS_DISPLAY_POWER_STATE_FILE, buf);

	return prev_display_power_state;
}

const char *
hardware_get_audio_device_dir(void)
{
	return "/dev/snd";
}

bool
hardware_is_audio_device(const char *file)
{
	// TODO: check for pcm* ?
	if (!strcmp(file, "controlC0"))
		return false;
	if (!strcmp(file, "timer"))
		return false;
	return true;
}

int
hardware_get_random(unsigned char *buf, size_t len)
{
	const char *rnd = "/dev/hw_random";
	const char *sw = "/dev/random";
	if (!file_exists(rnd)) {
		if (!file_exists(sw)) {
			ERROR("Failed to retrieve random numbers. Neither random number generator %s or %s could be accessed!", rnd, sw);
			return -1;
		}
		WARN("Could not access %s, falling back to %s. Check if device provides a hardware random number generator.", rnd, sw);
		rnd = sw;
	}
	return file_read(rnd, (char*)buf, len);
}

#define CMLD_PATH_WAKE_LOCK   "/sys/power/wake_lock"
#define CMLD_PATH_WAKE_UNLOCK "/sys/power/wake_unlock"

void
hardware_suspend_block(const char *name, size_t name_len)
{
	file_write(CMLD_PATH_WAKE_LOCK, name, name_len);
}

void
hardware_suspend_unblock(const char *name, size_t name_len)
{
	file_write(CMLD_PATH_WAKE_UNLOCK, name, name_len);
}
