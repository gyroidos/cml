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

#ifndef DOCKER_H
#define DOCKER_H

#include "common/list.h"

typedef struct docker_remote_file {
	char *media_type;
	int size;
	char *digest_algorithm;
	char *digest;
	char *suffix;
	char *platform_arch;
	char *platform_variant;
} docker_remote_file_t;

typedef struct docker_manifest {
	int schema_version;
	char *media_type;

	docker_remote_file_t *config;

	int layers_size;
	docker_remote_file_t **layers;
} docker_manifest_t;

typedef struct docker_exposed_port {
	char protocol[10];
	int port;
} docker_exposed_port_t;

typedef struct docker_config {
	char *hostname;
	char *domainname;
	char *user;
	list_t *exposedports_list;
	int env_size;
	char **env;
	int cmd_size;
	char **cmd;
	int entrypoint_size;
	char **entrypoint;
	list_t *volumes_list;
	list_t *labels_list;
} docker_config_t;

typedef struct docker_manifest_list {
	int schema_version;
	char *media_type;
	int manifests_size;
	docker_remote_file_t **manifests;
} docker_manifest_list_t;

docker_manifest_list_t *
docker_parse_manifest_list_new(const char *raw_file_buffer);

docker_manifest_t *
docker_parse_manifest_new(const char *raw_file_buffer);

docker_config_t *
docker_parse_config_new(const char *raw_file_buffer);

void
docker_manifest_list_free(docker_manifest_list_t *ml);

void
docker_manifest_free(docker_manifest_t *manifest);

void
docker_config_free(docker_config_t *cfg);

int
docker_download_manifest_list(const char *curl_token, const char *out_file, const char *image_name,
			      const char *image_tag);

int
docker_download_manifest(const char *curl_token, const char *out_file, const char *image_name, const char *image_tag);

int
docker_download_image(char *curl_token, const docker_manifest_t *manifest, const char *out_path, const char *image_name,
		      const char *image_tag);

/* functions for accessing docker registry */
void
docker_set_host_url(const char *url);

int
docker_generate_basic_auth(const char *user, const char *password, const char *token_file);

char *
docker_get_curl_token_new(char *image_name, char *token_file);

#endif /* DOCKER_H */
