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
 * @file hw_qcom_generic.c
 *
 * This unit represents the part of the hardware interface implementation which is common
 * for qcom devices like i9505 (Galaxy S4) and hammerhead (LG Nexus 5).
 */

#include "hardware.h"

#include "common/macro.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/file.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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

	size_t read = file_read(rnd, (char*)buf, len);
	if (read == len) {
		return len;
	} else {
		if (!file_exists(sw)) {
			ERROR("Failed to retrieve random numbers. Neither random number generator %s or %s could be accessed!", rnd, sw);
			return -1;
		}
		WARN("Could not access %s, falling back to %s. Check if device provides a hardware random number generator.", rnd, sw);
		return file_read(sw, (char*)buf, len);
	}
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
