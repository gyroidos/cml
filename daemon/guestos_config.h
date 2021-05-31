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

#ifndef GUESTOS_CONFIG_H
#define GUESTOS_CONFIG_H

/**
 * @file guestos_config.h
 *
 * The Guest OS config module represents the contents of a GuestOS config file
 * which is stored in protobuf text format.
 */

#include "mount.h"

#include <stdint.h>

/**
 * A structure to present a guest operating system.
 */
typedef struct _GuestOSConfig guestos_config_t;

/******************************************************************************/

/**
 * Loads a GuestOS config from the given file.
 * @param file the file from which to load the config
 * @return the guestos_config_t instance or NULL on error
 */
guestos_config_t *
guestos_config_new_from_file(const char *file);

/**
 * Loads a GuestOS config from the given buffer.
 * @param buf the buffer containing the GuestOS config
 * @param buflen the length of the config in the buffer
 * @return the guestos_config_t instance or NULL on error
 */
guestos_config_t *
guestos_config_new_from_buffer(unsigned char *buf, size_t buflen);

/**
 * Frees the given guestos_config_t instance.
 */
void
guestos_config_free(guestos_config_t *cfg);

/**
 * Serializes the GuestOS config structure and writes is to the given file.
 * @param cfg the guestos_config_t instance with the config to be serialized
 * @param file the file to which to write the serialized GuestOS config
 */
int
guestos_config_write_to_file(const guestos_config_t *cfg, const char *file);

/******************************************************************************/

/**
 * Fills the given mount struct with the mounts provided by the given GuestOS config.
 * @param cfg the guestos_config_t instance
 * @param mnt the mount_t struct to fill
 */
void
guestos_config_fill_mount(const guestos_config_t *cfg, mount_t *mnt);

/**
 * Fills the given mount struct with the setup mounts provided by the given GuestOS config.
 * @param cfg the guestos_config_t instance
 * @param mnt the mount_t struct to fill
 */
void
guestos_config_fill_mount_setup(const guestos_config_t *cfg, mount_t *mnt);

/******************************************************************************/

/**
 * Returns the GuestOS name configured in the GuestOS config.
 */
const char *
guestos_config_get_name(const guestos_config_t *cfg);

/**
 * Returns the hardware model configured in the GuestOS config.
 */
const char *
guestos_config_get_hardware(const guestos_config_t *cfg);

/**
 * Returns the GuestOS versionin the GuestOS config.
 */
uint64_t
guestos_config_get_version(const guestos_config_t *cfg);

/**
 * Returns the init script configured in the GuestOS config.
 */
const char *
guestos_config_get_init(const guestos_config_t *cfg);

/**
 * Constructs and allocates an new argv buffer for execve
 */
char **
guestos_config_get_init_argv_new(const guestos_config_t *cfg);

/**
 * Returns guestos specific environment for execve
 */
char **
guestos_config_get_init_env(const guestos_config_t *cfg);

/**
 * Returns the size of environment buffer
 */
size_t
guestos_config_get_init_env_len(const guestos_config_t *cfg);

/**
 * Returns the minimum RAM configured in the GuestOS config.
 */
uint32_t
guestos_config_get_min_ram_limit(const guestos_config_t *cfg);

/**
 * Returns the RAM limit configured in the GuestOS config.
 */
uint32_t
guestos_config_get_def_ram_limit(const guestos_config_t *cfg);

/**
 * Returns if feture vpn is enabled in the GuestOS config.
 */
bool
guestos_config_get_feature_vpn(const guestos_config_t *cfg);

/**
 * Returns if the GuestOS supports background booting.
 */
bool
guestos_config_get_feature_bg_booting(const guestos_config_t *cfg);

/**
 * Returns if the GuestOS is allowed to install new GuestOSes
 * e.g., an OS which converts other container runtime images for the CML
 */
bool
guestos_config_get_feature_install_guest(const guestos_config_t *cfg);

/**
 * Returns the URL to the file server for updating/installing new images
 */
const char *
guestos_config_get_update_base_url(const guestos_config_t *cfg);

#endif /* GUESTOS_CONFIG_H */
