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
 * @file hardware.h
 *
 * The hardware submodule contains device specific functionality or definitions.
 * The API is specified in the header file, while at compile time a specific
 * implementation is choosen, e.g. hw_i9505.c for Galaxy S4 or hw_hammerhead.c
 * for Nexus 5.
 */

#ifndef HARDWARE_H
#define HARDWARE_H

#include <stdint.h>
#include <stdbool.h>
#include "common/list.h"
#include <stddef.h>

/**
 * Get the unique hardware name, e.g. hammerhead.
 * @return The hardware name.
 */

const char *
hardware_get_name(void);

/**
 * Get the hardware manufacturer. This is a unique hardware key together with the model.
 * @return The hardware manufacturer.
 */

const char *
hardware_get_manufacturer(void);

/**
 * Get the base whitelist of hardware specific devices which are required for every container
 * independent from its configuration
 */
const char **
hardware_get_devices_whitelist_base();

/**
 * Get the whitelist of hardware specific devices which are additionally to the
 * base list allowed for privileged containers
 */
const char **
hardware_get_devices_whitelist_priv();

/**
 * Get whitelist of devices required for audio
 */
const char **
hardware_get_devices_whitelist_audio();

/**
 * Get the hardware model. This is a unique hardware key together with the manufacturer.
 * @return The hardware model.
 */

const char *
hardware_get_model(void);

/**
 * Get the hardware serial number. Together with the manufacturer and model information this identifies a device.
 * @return The serial number of the device.
 */

const char *
hardware_get_serial_number(void);

/**
 * Get the wifi mac address of the device.
 * @return The wifi mac address of the device.
 */

const char *
hardware_get_wifi_mac(void);

/**
 * Get the bluetooth mac address of the device.
 * @return The bluetooth mac address of the device.
 */

const char *
hardware_get_bluetooth_mac(void);

/**
 * Get the IMEI of the device.
 * @return The IMEI of the device.
 */

const char *
hardware_get_imei(void);

/**
 * Get the path to the boot partion.
 * @return the path.
 */
const char *
hardware_get_bootimg_path(void);

/**
 * Get the path to block devices by name,
 * e.g. /dev/block/platform/msm_sdcc.1/by-name.
 * @return The path.
 */

const char *
hardware_get_block_by_name_path(void);

/**
 * Get the path the powerbutton input device
 * e.g. /dev/input/event0.
 * @return The path.
 */

const char *
hardware_get_powerbutton_input_path(void);

/**
 * Set the color of the device LED by rgb values. Turn the LED off with value 0.
 * @param color The color value in #RRGGBBAA format.
 * @param should_blink If true let the LED blink (preferably done by hardware),
 * if false turn LED on constantly.
 * @return -1 on error else 0.
 */
int
hardware_set_led(uint32_t color, bool should_blink);

bool
hardware_is_led_on();

int
hardware_register_fb_status_cb(void (* func)(bool));

const char *
hardware_get_audio_device_dir(void);

bool
hardware_is_audio_device(const char *file);

bool
hardware_display_power_state(void);

int
hardware_backlight_on();

/**
 * Get random bytes using the hardware random number generator (if supported).
 * If no support is available, get random bytes from /dev/random.
 * @param buf	buffer where the random bytes will be returned (must be large enough to hold 'len' bytes)
 * @param len	number of random bytes to store in 'buf'
 */
int
hardware_get_random(unsigned char *buf, size_t len);

/**
 * Take a wakelock (suspend blocker) to disallow the system going to deep sleep
 * @param name	name of the suspend blocker (wakelock)
 * @param len	size of 'name' string
 */
void
hardware_suspend_block(const char *name, size_t name_len);

/**
 * Release a wakelock (suspend blocker) to allow the system going to deep sleep
 * @param name	name of the suspend blocker (wakelock)
 * @param len	size of 'name' string
 */
void
hardware_suspend_unblock(const char *name, size_t name_len);

/**
 * Returns the string of the active cgroups subsystems
 */
const char*
hardware_get_active_cgroups_subsystems(void);

/**
 * Returns list of network interfaces which should be
 * generated and connected(routed) to outside world
 */
list_t*
hardware_get_nw_name_list(void);

/**
 * Returns list of network interfaces which should be moved
 * into the privileged container's netns
 */
list_t*
hardware_get_nw_mv_name_list(void);

/**
 * Returns the interface name for mobile data (e.g., rmnet0)
 */
const char *
hardware_get_radio_ifname(void);

bool
hardware_supports_systemv_ipc(void);

const char *
hardware_get_routing_table_radio(void);

int
hardware_get_key_power_inject(void);

#endif /* HARDWARE_H */

