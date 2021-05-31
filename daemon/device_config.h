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
 * @file device_config.h
 *
 * Implements a device global configuration file.
 * The configuration can be changed via MDM or GUI by the user or administrator.
 */

#ifndef DEVICE_H
#define DEVICE_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct device_config device_config_t;

/**
 * Create a new config object from a config file.
 * @param path Path to the config file. Can be NULL to indicate that an empty
 *             device_config_t object should be created.
 * @return The new device_config_t object or NULL on an error.
 */
device_config_t *
device_config_new(const char *path);

void
device_config_free(device_config_t *config);

//int
//device_config_read_from_fd(device_config_t *config, int fd);

int
device_config_write(const device_config_t *config);

//int
//device_config_write_to_fd(const device_config_t *config, int fd);

/*************************/
/* GETTER + SETTER       */
/*************************/

const char *
device_config_get_uuid(const device_config_t *config);

const char *
device_config_get_mdm_node(const device_config_t *config);

const char *
device_config_get_mdm_service(const device_config_t *config);

const char *
device_config_get_telephony_uuid(const device_config_t *config);

const char *
device_config_get_update_base_url(const device_config_t *config);

const char *
device_config_get_c0os(const device_config_t *config);

const char *
device_config_get_host_addr(const device_config_t *config);

const char *
device_config_get_host_dns(const device_config_t *config);

const char *
device_config_get_host_gateway(const device_config_t *config);

uint32_t
device_config_get_host_subnet(const device_config_t *config);

const char *
device_config_get_host_if(const device_config_t *config);

bool
device_config_get_locally_signed_images(const device_config_t *config);

bool
device_config_get_hostedmode(const device_config_t *config);

bool
device_config_get_signed_configs(const device_config_t *config);

bool
device_config_get_audit_size(const device_config_t *config);

bool
device_config_get_tpm_enabled(const device_config_t *config);
#endif /* DEVICE_H */
