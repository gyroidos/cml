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
 * @file u_idmapped.c
 *
 * This module is responsible for uid mapping of some mounts inside units.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_idmapped"

#include "common/dir.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/ns.h"
#include "common/sock.h"
#include "compartment.h"
#include "unit.h"
#include "cmld.h"
#include "mount.h"

#include <fcntl.h>

typedef struct u_idmapped {
	unit_t *unit; //!< unit which the u_perm struct is associated to
	list_t *mnt_list;
} u_idmapped_t;

typedef struct u_idmapped_mnt {
	char *src;
	char *dst;
} u_idmapped_mnt_t;

static u_idmapped_mnt_t *
u_idmapped_mnt_new(const char *src, const char *dst)
{
	u_idmapped_mnt_t *mnt = mem_new0(u_idmapped_mnt_t, 1);
	mnt->src = mem_strdup(src);
	mnt->dst = mem_strdup(dst);

	return mnt;
}

void
u_idmapped_mnt_free(u_idmapped_mnt_t *mnt)
{
	ASSERT(mnt);

	mem_free0(mnt->src);
	mem_free0(mnt->dst);

	mem_free0(mnt);
}

int
u_idmapped_add_mount(u_idmapped_t *idmapped, const char *src, const char *dst)
{
	ASSERT(idmapped);

	IF_FALSE_RETVAL(mount_is_idmapping_supported(), -1);

	IF_FALSE_RETVAL(src, -1);
	IF_FALSE_RETVAL(dst, -1);

	idmapped->mnt_list = list_append(idmapped->mnt_list, u_idmapped_mnt_new(src, dst));

	return 0;
}

/**
 * This function allocates a new u_idmapped_t instance, associated to a specific unit object.
 * @return the u_idmapped_t idmappedission structure which holds idmappedission access rules for an unit.
 */
static void *
u_idmapped_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	u_idmapped_t *idmapped = mem_new0(u_idmapped_t, 1);
	idmapped->unit = compartment_get_extension_data(compartment);

	// ensure data directory of unit in CML is root owned
	struct stat s;
	if (!stat(unit_get_data_path(idmapped->unit), &s) && s.st_uid != 0) {
		if (dir_chown_folder(unit_get_data_path(idmapped->unit), 0, 0) < 0) {
			FATAL("Could not chown %s to root:root failed.",
			      unit_get_data_path(idmapped->unit));
		}
	}

	return idmapped;
}

/**
 * Frees the u_idmapped_t structure
 */
static void
u_idmapped_free(void *idmappedp)
{
	u_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	mem_free0(idmapped);
}

struct do_mount_data {
	int userns_fd;
	u_idmapped_t *idmapped;
};

int
u_idmapped_do_mount(const void *data)
{
	const struct do_mount_data *datap = data;
	ASSERT(datap && datap->idmapped);

	int ret = -1;

	for (list_t *l = datap->idmapped->mnt_list; l; l = l->next) {
		u_idmapped_mnt_t *mnt = l->data;
		if (mount_idmapped(mnt->src, mnt->dst, datap->userns_fd) < 0) {
			ERROR("Could mount %s -> %s with uid mapping in unit %s!", mnt->src,
			      mnt->dst, unit_get_description(datap->idmapped->unit));
			goto out;
		} else {
			DEBUG("Mounted %s -> %s with uid mapping in unit %s.", mnt->src, mnt->dst,
			      unit_get_description(datap->idmapped->unit));
		}
	}

	ret = 0;
out:
	return ret;
}

static int
u_idmapped_start_pre_clone(void *idmappedp)
{
	u_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	// do not add mounts if idmapped mounts are unsupported
	if (!mount_is_idmapping_supported())
		return 0;

	IF_TRUE_RETVAL(u_idmapped_add_mount(idmapped, CMLD_SOCKET_DIR, CMLD_SOCKET_DIR) < 0,
		       -COMPARTMENT_ERROR_USER);
	IF_TRUE_RETVAL(u_idmapped_add_mount(idmapped, LOGFILE_DIR, LOGFILE_DIR) < 0,
		       -COMPARTMENT_ERROR_USER);
	IF_TRUE_RETVAL(u_idmapped_add_mount(idmapped, unit_get_data_path(idmapped->unit),
					    unit_get_data_path(idmapped->unit)) < 0,
		       -COMPARTMENT_ERROR_USER);

	return 0;
}

static int
u_idmapped_start_pre_exec(void *idmappedp)
{
	u_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	if (!mount_is_idmapping_supported())
		return 0;

	int ret = -COMPARTMENT_ERROR_USER;

	char *userns_path = mem_printf("/proc/%d/ns/user", unit_get_pid(idmapped->unit));
	int userns_fd = open(userns_path, O_RDONLY);
	if (userns_fd < 0) {
		ERROR_ERRNO("Failed to open userns fd for %s",
			    unit_get_description(idmapped->unit));
		goto out;
	}

	struct do_mount_data data = { .userns_fd = userns_fd, .idmapped = idmapped };

	if (namespace_exec(unit_get_pid(idmapped->unit), CLONE_NEWNS, 0, 0, u_idmapped_do_mount,
			   &data))
		goto out;

	ret = 0;
out:
	mem_free0(userns_path);
	close(userns_fd);
	return ret;
}

/**
 * Cleans up the u_idmapped_t struct.
 */
static void
u_idmapped_cleanup(void *idmappedp, UNUSED bool is_rebooting)
{
	u_idmapped_t *idmapped = idmappedp;
	ASSERT(idmapped);

	for (list_t *l = idmapped->mnt_list; l; l = l->next) {
		u_idmapped_mnt_t *mnt = l->data;
		u_idmapped_mnt_free(mnt);
	}
	list_delete(idmapped->mnt_list);
	idmapped->mnt_list = NULL;
}

static compartment_module_t u_idmapped_module = {
	.name = MOD_NAME,
	.compartment_new = u_idmapped_new,
	.compartment_free = u_idmapped_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = u_idmapped_start_pre_clone,
	.start_post_clone = NULL,
	.start_pre_exec = u_idmapped_start_pre_exec,
	.start_post_exec = NULL,
	.start_pre_exec_child_early = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = u_idmapped_cleanup,
	.join_ns = NULL,
};

static void INIT
u_idmapped_init(void)
{
	// register this module in unit.c
	unit_register_compartment_module(&u_idmapped_module);
}
