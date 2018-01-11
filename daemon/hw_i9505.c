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
 * @file hw_i9505.c
 *
 * This unit represents the hardware interface device specific implementation for the i9505 (Galaxy S4).
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/file.h"

#define LED_R  "/sys/class/leds/led_r/brightness"
#define LED_G  "/sys/class/leds/led_g/brightness"
#define LED_B  "/sys/class/leds/led_b/brightness"

/******************************************************************************/

/**
 * List of devices which are hardware specific and necessary for
 * every container independent from configuration 
 */
static const char *hw_i9505_devices_whitelist_base[] = {
	/* There is this strange process rmt_storage on i9505 which requires access to
	 * /dev/mem to work correctly... TODO analyze */
	"c 1:1 rwm", // /dev/mem

	/********/
	/* MISC */
	"c 10:16 rwm", // efs_bridge

	/* android stuff */
	"c 10:18 rwm", // system
	"c 10:19 rwm", // radio
	"c 10:20 rwm", // events
	"c 10:21 rwm", // main
	"c 10:22 rwm", // ashmem
	"c 10:23 rwm", // binder
	"c 10:26 rwm", // alarm

	"c 10:27 rwm", // usb_accessory
	"c 10:28 rwm", // mtp_usb

	/* misc drivers */
	"c 10:35 rwm", // bcm2079
	"c 10:38 rwm", // mdm
	"c 10:55 rwm", // msm_acdb
	"c 10:61 rwm", // smem_log
	"c 10:63 rwm", // ion

	"c 189:* rwm", // orginal alterate to 188 -> i9505 "usb_device"...

	//"c 237:* rwm", // BaseRemoteCtl

	//"c 238:* rwm", // rmi

	"c 239:* rwm", // hsicctl TODO radio related

	//"c 240:* rwm", // tzic TODO trustzone stuff?
	//"c 241:* rwm", // Qualcomm Secure Execution Environment Communicator

	"c 242:0 rwm", // kgsl-3d0 kernel graphics support layer. (Adreno stuff)

	"c 243:0 rwm", // DIAG driver qcom (diagnostics via USB?)

	"c 244:0 rwm", // msm_rotator (MSM Offline Image Rotator driver)

	//"c 245:* rwm", // ttyHSL Driver for msm HSUART serial device
	//"c 246:* rwm", // ttyHS

	/* MSM Video Core Driver */
	//"c 247:* rwm", // msm_vidc_enc Encoder
	//"c 248:* rwm", // msm_vidc_dec Decoder
	//"c 249:* rwm", // msm_vidc_reg Register?

	//"c 250:* rwm", // bsg - Block layer SCSI generic (bsg) driver 
	//"c 251:* rwm", // MSM Shared Memory Driver - Connection to the Baseband processor

	//"c 252:* rwm", // media ??

	//"c 253:* rwm", // RTC driver

	//"c 254:* rwm", // msm_sps MSM Smart Peripheral System (SPS) driver

	/*************/
	/* Block     */
	/* MMC block devices */
	//"b 179:* rwm", // mmc MMC devices

	/* The following partitions are currently required during first boot of a container 
	 * where they are copied into an container-specific image */
	/* TODO think about how to get rid of them in the container */
	//"b 179:1 rwm", // aphnlos
	//"b 179:2 rwm", // mdm
	//"b 179:10 rwm", // efs

	"b 179:0 rwm",  // mmcblk0 TODO the block device itself?! seems unhealthy

	"b 179:11 rwm", // modemst1
	"b 179:12 rwm", // modemst2

	"b 179:13 rwm", // m9kefs1
	"b 179:14 rwm", // m9kefs2
	"b 179:15 rwm", // m9kefs3

	"b 179:24 rwm", // fsg
	"b 179:25 rwm", // ssd

	NULL
};

/**
 * List of audio devices
 */
static const char *hw_i9505_devices_whitelist_audio[] = {
	"c 116:* rwm", // ALSA Audio
	NULL
};

const char **
hardware_get_devices_whitelist_base()
{
	return hw_i9505_devices_whitelist_base;
}

const char **
hardware_get_devices_whitelist_priv()
{
	return NULL;
}

const char **
hardware_get_devices_whitelist_audio()
{
	return hw_i9505_devices_whitelist_audio;
}

const char *
hardware_get_name(void)
{
	return "i9505"; // TODO: jflte?
}

const char *
hardware_get_manufacturer(void)
{
	return "Samsung";
}

const char *
hardware_get_model(void)
{
	return "GT-I9505";
}

const char *
hardware_get_serial_number(void)
{
	static const char *sn = NULL;

	if (sn)
		return sn;

	sn = file_read_new("/efs/FactoryApp/serial_no", 4096);
	return sn;
}

const char *
hardware_get_wifi_mac(void)
{
	static const char *mac = NULL;

	if (mac)
		return mac;

	mac = file_read_new("/efs/wifi/.mac.info", 4096);
	return mac;
}

const char *
hardware_get_bluetooth_mac(void)
{
	static const char *mac = NULL;

	if (mac)
		return mac;

	mac = file_read_new("/efs/bluetooth/bt_addr", 4096);
	return mac;
}

const char *
hardware_get_imei(void)
{
	return NULL; // TODO
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
	IF_FALSE_RETVAL(file_printf(LED_R, "%u\n", (color >> 24) & 0xff) >= 0, -1);
	IF_FALSE_RETVAL(file_printf(LED_G, "%u\n", (color >> 16) & 0xff) >= 0, -1);
	IF_FALSE_RETVAL(file_printf(LED_B, "%u\n", (color >>  8) & 0xff) >= 0, -1);
	return 0;
}

const char *
hardware_get_powerbutton_input_path(void)
{
	return "/dev/input/event0";
}

int
hardware_backlight_on()
{
	// TODO
	return 0;
}

const char *
hardware_get_active_cgroups_subsystems(void)
{
	return "cpu,memory,freezer,devices";
}

bool
hardware_supports_systemv_ipc(void)
{
	return true;
}
