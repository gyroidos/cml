/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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

#include "reboot.h"
#ifdef ANDROID
#include <cutils/properties.h>
#include <cutils/android_reboot.h>
#else
#include <unistd.h>
#include <sys/reboot.h>
#endif

int
reboot_reboot(int cmd)
{
	int res = -1;
	switch (cmd) {
	case REBOOT:
#ifdef ANDROID
		// ANDROID_RB_RESTART is deprecated and no longer recommended to be used
		res = android_reboot(ANDROID_RB_RESTART, 0, 0);
#else
		res = reboot(RB_AUTOBOOT);
#endif
		break;
	case POWER_OFF:
#ifdef ANDROID
		res = android_reboot(ANDROID_RB_POWEROFF, 0, 0);
#else
		res = reboot(RB_POWER_OFF);
#endif
		break;
	}
	return res;
}
