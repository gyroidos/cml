/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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
 * @file u_perm.c
 *
 * This module is responsible for provideing permission control for units.
 * This includes device access, by populating a minimal /dev.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_perm"

#include "common/dir.h"
#include "common/file.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/ns.h"
#include "compartment.h"
#include "u_perm.h"
#include "unit.h"

#include <libgen.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include <linux/capability.h>

struct device_rule {
	mode_t mode;
	int major;
	int minor;
	const char *dst;
};

/**
 * Whitelist of devices to be available for all units
 */
static const struct device_rule unit_dev_whitelist[] = {
	{ S_IFCHR | 0666, 1, 3, "/dev/null" },	  { S_IFCHR | 0666, 1, 5, "/dev/zero" },
	{ S_IFCHR | 0666, 1, 7, "/dev/full" },	  { S_IFCHR | 0666, 1, 8, "/dev/random" },
	{ S_IFCHR | 0666, 1, 9, "/dev/urandom" }, { S_IFCHR | 0666, 10, 183, "/dev/hwrng" },
};

/* Permission structure */
struct u_perm {
	unit_t *unit; //!< unit which the u_perm struct is associated to
};

int
do_mknod_in_unit(const void *data)
{
	int ret = 0;
	const struct device_rule *d = data;

	char *dir = dirname(mem_strdup(d->dst));
	if (!file_is_dir(dir))
		dir_mkdir_p(dir, 00755);
	if (mknod(d->dst, d->mode, makedev(d->major, d->minor)) < 0) {
		ERROR_ERRNO("Could not mknod (%d:%d) at %s", d->major, d->minor, d->dst);
		ret = -1;
	} else {
		DEBUG("mknod (%d:%d) at %s done", d->major, d->minor, d->dst);
	}

	return ret;
}

int
do_unlink_in_unit(const void *data)
{
	int ret = 0;
	const char *dst = data;

	if (unlink(dst) < 0) {
		ERROR_ERRNO("Could not deny access to %s", dst);
		ret = -1;
	} else {
		DEBUG("removed device node at %s", dst);
	}

	return ret;
}

int
u_perm_allow_dev(u_perm_t *perm, char type, int major, int minor, const char *name)
{
	ASSERT(perm);

	mode_t mode = 0666;

	IF_FALSE_RETVAL(unit_get_pid(perm->unit) > 0, -1);

	switch (type) {
	case 'c':
		mode |= S_IFCHR;
		break;
	case 'b':
		mode |= S_IFBLK;
		break;
	default:
		ERROR("Could not parse dev type!");
		return -1;
	}

	struct device_rule dev_rule = { mode, major, minor, name };

	return namespace_exec(unit_get_pid(perm->unit), CLONE_NEWNS, unit_get_uid(perm->unit),
			      CAP_MKNOD, do_mknod_in_unit, &dev_rule);
}

int
u_perm_deny_dev(u_perm_t *perm, const char *name)
{
	ASSERT(perm);

	IF_FALSE_RETVAL(unit_get_pid(perm->unit) > 0, -1);

	return namespace_exec(unit_get_pid(perm->unit), CLONE_NEWNS, unit_get_uid(perm->unit), 0,
			      do_unlink_in_unit, name);
}

/**
 * This function allocates a new u_perm_t instance, associated to a specific unit object.
 * @return the u_perm_t permission structure which holds permassion access rules for an unit.
 */
static void *
u_perm_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_perm_t *perm = mem_new0(u_perm_t, 1);
	perm->unit = compartment_get_extension_data(compartment);

	return perm;
}

/**
 * Frees the u_perm_t structure
 */
static void
u_perm_free(void *permp)
{
	u_perm_t *perm = permp;
	ASSERT(perm);

	mem_free0(perm);
}

static int
u_perm_start_child_early(void *permp)
{
	u_perm_t *perm = permp;
	ASSERT(perm);

	if (umount("/dev") < 0) {
		if (umount2("/dev", MNT_DETACH) < 0) {
			ERROR_ERRNO("Could not umount host /dev!");
			return -COMPARTMENT_ERROR_VOL;
		}
	}

	if (mount("tmpfs", "/dev", "tmpfs", MS_RELATIME | MS_NOSUID, NULL) < 0) {
		ERROR_ERRNO("Could not mount /dev");
		return -COMPARTMENT_ERROR_VOL;
	}

	uid_t uid = unit_get_uid(perm->unit);
	uid_t gid = unit_get_uid(perm->unit);

	int dev_array_len = sizeof(unit_dev_whitelist) / sizeof(struct device_rule);
	for (int i = 0; i < dev_array_len; i++) {
		struct device_rule d = unit_dev_whitelist[i];
		if (mknod(d.dst, d.mode, makedev(d.major, d.minor)) < 0) {
			ERROR_ERRNO("Could not mknod (%d:%d) at %s", d.major, d.minor, d.dst);
			return -COMPARTMENT_ERROR_VOL;
		}
		DEBUG("mknod (%d:%d) at %s done", d.major, d.minor, d.dst);

		if (chown(d.dst, uid, gid) < 0)
			WARN_ERRNO("Could not chown device node '%s' to (%d:%d)", d.dst, uid, gid);
	}

	return 0;
}

static compartment_module_t u_perm_module = {
	.name = MOD_NAME,
	.compartment_new = u_perm_new,
	.compartment_free = u_perm_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = u_perm_start_child_early,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_pre_exec_child_early = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
u_perm_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_perm_module);
}
