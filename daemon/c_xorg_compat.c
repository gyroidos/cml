/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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
  * @file c_xorg_compat.c
  *
  * This module provdies compat funtionality for xorg on current kernel
  * grater then version 6.9.
  */

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define MOD_NAME "c_xorg_compat"

#include "common/macro.h"
#include "common/mem.h"
#include "compartment.h"
#include "container.h"

#include <limits.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#define SYS_DIR "/sys/class/graphics"

typedef struct c_xorg_compat {
	bool enabled;
} c_xorg_compat_t;

/******************************************************************************/

static void *
c_xorg_compat_new(compartment_t *compartment)
{
	ASSERT(compartment);

	c_xorg_compat_t *xorg_compat = mem_new0(c_xorg_compat_t, 1);
	xorg_compat->enabled = COMPARTMENT_FLAG_XORG_COMPAT & compartment_get_flags(compartment);

	return xorg_compat;
}

static void
c_xorg_compat_free(void *xorg_compatp)
{
	c_xorg_compat_t *xorg_compat = xorg_compatp;
	ASSERT(xorg_compat);
	mem_free0(xorg_compat);
}

static int
c_xorg_compat_start_child(void *xorg_compatp)
{
	c_xorg_compat_t *xorg_compat = xorg_compatp;
	ASSERT(xorg_compat);

	// if not enabled in config just skip for this compartment
	if (!xorg_compat->enabled)
		return 0;

	INFO("Enable xorg compat module");

	char link[PATH_MAX] = { 0 };
	if (readlink(SYS_DIR "/fb0", link, PATH_MAX) < 0) {
		WARN_ERRNO("Readlink of " SYS_DIR "/fb0 failed, no compat mode will be setup.");
		return 0;
	}

	IF_NULL_RETVAL(strstr(link, "devices/pci"), 0);

	const char *fb_drv;
	if (strstr(link, "efi-framebuffer"))
		fb_drv = "efi";
	else if (strstr(link, "vesa-framebuffer"))
		fb_drv = "vesa";
	else
		fb_drv = NULL;

	IF_NULL_RETVAL(fb_drv, 0);

	if (mount("graphics", SYS_DIR, "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount " SYS_DIR);
		goto err;
	}

	// restore fbcon link
	const char *lnk_target = "../../devices/virtual/graphics/fbcon";
	if (symlink(lnk_target, SYS_DIR "/fbcon")) {
		WARN_ERRNO("Could not link %s to " SYS_DIR "/fcon in container", lnk_target);
		goto err_mount;
	}

	// gen legacy fb0 link for platfrom drivers
	char *fb_lnk_target =
		mem_printf("../../bus/platform/devices/%s-framebuffer.0/graphics/fb0", fb_drv);
	if (symlink(lnk_target, SYS_DIR "/fb0")) {
		WARN_ERRNO("Could not link %s to " SYS_DIR "/fb0 in container", fb_lnk_target);
		goto err_fb_lnk;
	}

	INFO("Successfully setup xorg compat module");

	mem_free0(fb_lnk_target);
	return 0;

err_fb_lnk:
	mem_free0(fb_lnk_target);
err_mount:
	if (umount(SYS_DIR))
		WARN("Could not umount " SYS_DIR "!");
err:
	return -COMPARTMENT_ERROR;
}

static void
c_xorg_compat_cleanup(UNUSED void *xorg_compatp, UNUSED bool is_rebooting)
{
	if (umount(SYS_DIR))
		WARN("Could not umount " SYS_DIR " properly");
}

static compartment_module_t c_xorg_compat_module = {
	.name = MOD_NAME,
	.compartment_new = c_xorg_compat_new,
	.compartment_free = c_xorg_compat_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = c_xorg_compat_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_xorg_compat_cleanup,
	.join_ns = NULL,
	.flags = 0,
};

static void INIT
c_xorg_compat_init(void)
{
	// register this module in container.c
	container_register_compartment_module(&c_xorg_compat_module);
}
