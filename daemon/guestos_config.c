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

#include "guestos_config.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/guestos.pb-c.h"
#else
#include "guestos.pb-c.h"
#endif

#include "mount.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"


/******************************************************************************/
guestos_config_t *
guestos_config_new_from_file(const char *file)
{
	ASSERT(file);
	DEBUG("Loading GuestOS config from \"%s\".", file);

	GuestOSConfig *cfg = (GuestOSConfig *)
		protobuf_message_new_from_textfile(file, &guest_osconfig__descriptor);
	if (!cfg) {
		ERROR("Failed loading GuestOS config from file \"%s\".", file);
	}
	return cfg;
}

guestos_config_t *
guestos_config_new_from_buffer(unsigned char *buf, size_t buflen)
{
	ASSERT(buf);
	DEBUG("Loading GuestOS config from string.");

	GuestOSConfig *cfg = (GuestOSConfig *)
		protobuf_message_new_from_buf(buf, buflen, &guest_osconfig__descriptor);
	if (!cfg) {
		ERROR("Failed loading GuestOS config from string.");
	}
	return cfg;
}


/**
 * Free an operating system data structure. Does not remove the persistent
 * parts of the operating system, i.e. the configuration and the images.
 * @param cfg The operating system to be freed.
 */
void
guestos_config_free(guestos_config_t *cfg)
{
	ASSERT(cfg);
	protobuf_free_message((ProtobufCMessage *) cfg);
}

int
guestos_config_write_to_file(const guestos_config_t *cfg, const char *file)
{
	ASSERT(cfg);
	return protobuf_message_write_to_file(file, (ProtobufCMessage *) cfg);
}

/******************************************************************************/

static inline enum mount_type
guestos_config_mount_type_from_protobuf(GuestOSMount__Type mt)
{
	switch (mt) {
		//TODO Prettify this
	case GUEST_OSMOUNT__TYPE__SHARED:
		return MOUNT_TYPE_SHARED;
	case GUEST_OSMOUNT__TYPE__DEVICE:
		return MOUNT_TYPE_DEVICE;
	case GUEST_OSMOUNT__TYPE__DEVICE_RW:
		return MOUNT_TYPE_DEVICE_RW;
	case GUEST_OSMOUNT__TYPE__EMPTY:
		return MOUNT_TYPE_EMPTY;
	case GUEST_OSMOUNT__TYPE__COPY:
		return MOUNT_TYPE_COPY;
	case GUEST_OSMOUNT__TYPE__FLASH:
		return MOUNT_TYPE_FLASH;
	case GUEST_OSMOUNT__TYPE__SHARED_DATA:
		return MOUNT_TYPE_SHARED_DATA;
	case GUEST_OSMOUNT__TYPE__OVERLAY_RO:
		return MOUNT_TYPE_OVERLAY_RO;
	case GUEST_OSMOUNT__TYPE__SHARED_RW:
		return MOUNT_TYPE_SHARED_RW;
	case GUEST_OSMOUNT__TYPE__OVERLAY_RW:
		return MOUNT_TYPE_OVERLAY_RW;
	default:
		FATAL("Invalid protobuf mount type %d.", mt);
	}
}

#if 0
static inline GuestOSMount__Type
guestos_config_mount_type_to_protobuf(enum mount_type mt)
{
	switch (mt) {
		//TODO Prettify this
	case MOUNT_TYPE_SHARED:
		return GUEST_OSMOUNT__TYPE__SHARED;
	case MOUNT_TYPE_DEVICE_RW:
		return GUEST_OSMOUNT__TYPE__DEVICE_RW;
	case MOUNT_TYPE_EMPTY:
		return GUEST_OSMOUNT__TYPE__EMPTY;
	case MOUNT_TYPE_COPY:
		return GUEST_OSMOUNT__TYPE__COPY;
	case MOUNT_TYPE_FLASH:
		return GUEST_OSMOUNT__TYPE__FLASH;
	case MOUNT_TYPE_SHARED_DATA:
		return GUEST_OSMOUNT__TYPE__SHARED_DATA;
	case MOUNT_TYPE_OVERLAY_RO:
		return GUEST_OSMOUNT__TYPE__OVERLAY_RO;
	default:
		FATAL("Invalid mount type %d.", mt);
	}
}
#endif // currently unused

static void
guestos_config_fill_mount_internal(GuestOSMount **mounts, size_t n_mounts, mount_t *mount)
{
	ASSERT(mount);

	IF_NULL_RETURN(mounts);

	for (size_t i = 0; i < n_mounts; i++) {
		GuestOSMount *m = mounts[i];
		mount_entry_t *e = mount_add_entry(mount,
				guestos_config_mount_type_from_protobuf(m->mount_type),
				m->image_file, m->mount_point, m->fs_type, m->def_size);
		mount_entry_set_size(e, m->image_size);
		if (m->image_sha1)
			mount_entry_set_sha1(e, m->image_sha1);
		if (m->image_sha2_256)
			mount_entry_set_sha256(e, m->image_sha2_256);
		if (m->mount_data)
			mount_entry_set_mount_data(e, m->mount_data);

	}
}

void
guestos_config_fill_mount(const guestos_config_t *cfg, mount_t *mount)
{
	ASSERT(cfg);
	guestos_config_fill_mount_internal(cfg->mounts, cfg->n_mounts, mount);
}

void
guestos_config_fill_mount_setup(const guestos_config_t *cfg, mount_t *mount)
{
	ASSERT(cfg);
	guestos_config_fill_mount_internal(cfg->mounts_setup, cfg->n_mounts_setup, mount);
}


/******************************************************************************/

const char *
guestos_config_get_name(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->name;
}

const char *
guestos_config_get_hardware(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->hardware;
}

uint64_t
guestos_config_get_version(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->version;
}

const char *
guestos_config_get_init(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->init_path;
}

char **
guestos_config_get_init_argv_new(const guestos_config_t *cfg)
{
	ASSERT(cfg);

	// construct an NULL terminated argv buffer for execve
	char **init_argv = mem_new0(char *, cfg->n_init_param + 2);
	init_argv[0] = mem_strdup(cfg->init_path);

	for (size_t i = 0; i < cfg->n_init_param; i++) {
		init_argv[i+1] = mem_strdup(cfg->init_param[i]);
	}
	return init_argv;
}

char **
guestos_config_get_init_env_new(const guestos_config_t *cfg)
{
	ASSERT(cfg);

	// construct an NULL terminated env buffer for execve
	char **env = mem_new0(char *, cfg->n_init_env+1);
	for (size_t i = 0; i < cfg->n_init_env; i++) {
		env[i] = mem_strdup(cfg->init_env[i]);
	}
	return env;
}

uint32_t
guestos_config_get_min_ram_limit(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->has_min_ram_limit ? cfg->min_ram_limit : 0;
}
/*
uint32_t guestos_config_get_max_ram_limit(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->has_max_ram_limit ? cfg->max_ram_limit : 0;
}
*/
uint32_t
guestos_config_get_def_ram_limit(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->has_def_ram_limit ? cfg->def_ram_limit : 0;
}

bool
guestos_config_get_feature_vpn(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->feature_vpn ? cfg->feature_vpn : false;
}

bool
guestos_config_get_feature_bg_booting(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->feature_bg_booting ? cfg->feature_bg_booting : false;
}

bool
guestos_config_get_feature_devtmpfs(const guestos_config_t *cfg)
{
	ASSERT(cfg);
	return cfg->feature_devtmpfs ? cfg->feature_devtmpfs : false;
}
