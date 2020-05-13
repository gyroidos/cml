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
#define LED_OFF_DEFAULT 1    /* Min value from kernel driver */

#define LED_ON_BLINK 500
#define LED_OFF_BLINK 3000

#define BOOT_BL_BRIGHTNESS 26

/******************************************************************************/
static const char *hw_hammerhead_devices_whitelist_base[] = {
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

#ifdef DEBUG_BUILD
	/* ramdump for debugging */
	"c 10:38 rwm", // ramdump_smem
	"c 10:40 rwm", // ramdump_audio-ocmem

	"c 10:88 rwm", // ramdump_venus
	"c 10:89 rwm", // ramdump_smem-modem
	"c 10:90 rwm", // ramdump_modem
	"c 10:93 rwm", // ramdump_adsp
#endif

	/* qseecom,  kgsl-3d0 kernel graphics support layer. (Adreno stuff), diag */
	"c 243:0 rwm",	// qseecom
	"c 244:0 rwm",	// kgsl-3d0
	"c 245:0 rwm",	// diag
	"c 247:99 rwm", //ttyHS99 serial  Bluetooth

	"c 250:* rwm", // smdcntl*

	"c 251:* rwm", // media*

	"c 252:* rwm", // rtc*

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

	"c 241:* rwm", // uio (used by rmt_storage)
	"c 249:0 rwm", // sensors
	"c 254:0 rwm", // msm_thermal_query

	NULL
};

/**
 * List of audio devices
 */
static const char *hw_hammerhead_devices_whitelist_audio[] = { "c 116:* rwm", // ALSA Audio
							       NULL };

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
	IF_FALSE_RETVAL(file_printf(LED_B, "%u\n", (color >> 8) & 0xff) >= 0, -1);
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
	if (file_printf("/sys/class/leds/lcd-backlight/brightness", "%d", BOOT_BL_BRIGHTNESS) < 0) {
		WARN_ERRNO("Could not write brightness file");
		return -1;
	}
	return 0;
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

list_t *
hardware_get_nw_mv_name_list(void)
{
	/*
	 * this list should start with the first mobile data iface
	 * which is usually rmnet0
	 */
	list_t *nw_name_list = NULL;
	for (int i = 0; i < 8; ++i)
		nw_name_list = list_append(nw_name_list, mem_printf("rmnet%d", i));
	for (int i = 0; i < 9; ++i)
		nw_name_list = list_append(nw_name_list, mem_printf("rev_rmnet%d", i));
	return nw_name_list;
}

const char *
hardware_get_radio_ifname(void)
{
	return "rmnet0";
}

bool
hardware_supports_systemv_ipc(void)
{
	return true;
}

const char *
hardware_get_routing_table_radio(void)
{
	return "1022";
}

#define SYSFS_DISPLAY_POWER_STATE_FILE "/sys/devices/mdp.0/power/runtime_status"

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
			ERROR("Failed to retrieve random numbers. Neither random number generator %s or %s could be accessed!",
			      rnd, sw);
			return -1;
		}
		WARN("Could not access %s, falling back to %s. Check if device provides a hardware random number generator.",
		     rnd, sw);
		rnd = sw;
	}
	return file_read(rnd, (char *)buf, len);
}

#define CMLD_PATH_WAKE_LOCK "/sys/power/wake_lock"
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
