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

#include "docker.h"

#include "common/macro.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/list.h"
#include "common/mem.h"

#include "cJSON/cJSON.h"
#include "util.h"

#include <unistd.h>
#include <sys/wait.h>

#define BUF_SIZE 10 * 4096
#define CURL_PATH "curl"

#define MEDIA_TYPE_MANIFEST_LIST_V2 "application/vnd.docker.distribution.manifest.list.v2+json"
#define MEDIA_TYPE_MANIFEST_V2 "application/vnd.docker.distribution.manifest.v2+json"
#define MEDIA_TYPE_MANIFEST_V1 "application/vnd.docker.distribution.manifest.v1+json"

static char *host_url = NULL;

static void
docker_remote_file_free(docker_remote_file_t *rf)
{
	if (rf->media_type)
		mem_free(rf->media_type);
	if (rf->digest_algorithm)
		mem_free(rf->digest_algorithm);
	// strtok sub pointer
	//if (rf->digest)
	//	mem_free(rf->digest);
	if (rf->suffix)
		mem_free(rf->suffix);
	if (rf->platform_arch)
		mem_free(rf->platform_arch);
	if (rf->platform_variant)
		mem_free(rf->platform_variant);
	mem_free(rf);
}

static docker_remote_file_t *
parse_remote_file_new(cJSON *rf_obj, char *suffix)
{
	docker_remote_file_t *rf = mem_new0(docker_remote_file_t, 1);
	rf->suffix = mem_strdup(suffix);

	cJSON *jmedia_type = cJSON_GetObjectItem(rf_obj, "mediaType");
	if (cJSON_IsString(jmedia_type))
		rf->media_type = mem_strdup(jmedia_type->valuestring);

	cJSON *jsize = cJSON_GetObjectItem(rf_obj, "size");
	if (cJSON_IsNumber(jsize))
		rf->size = jsize->valueint;

	cJSON *jdigest = cJSON_GetObjectItem(rf_obj, "digest");
	if (cJSON_IsString(jdigest)) {
		rf->digest_algorithm = strtok(mem_strdup(jdigest->valuestring), ":");
		rf->digest = strtok(NULL, ":");
	}
	cJSON *jplatform = cJSON_GetObjectItem(rf_obj, "platform");
	if (cJSON_IsObject(jplatform)) {
		cJSON *jplatform_arch = cJSON_GetObjectItem(jplatform, "architecture");
		if (cJSON_IsString(jplatform_arch))
			rf->platform_arch = mem_strdup(jplatform_arch->valuestring);
		cJSON *jplatform_variant = cJSON_GetObjectItem(jplatform, "variant");
		if (cJSON_IsString(jplatform_variant))
			rf->platform_variant = mem_strdup(jplatform_variant->valuestring);
	}

	INFO("Parsed remote file: \n\t type: %s\n\t size: %d\n\t digest %s :: %s (arch %s:%s)", rf->media_type,
	     rf->size, rf->digest_algorithm, rf->digest, rf->platform_arch, rf->platform_variant);
	return rf;
}

docker_manifest_list_t *
docker_parse_manifest_list_new(const char *raw_file_buffer)
{
	cJSON *jroot = NULL;
	docker_manifest_list_t *ml = mem_alloc0(sizeof(docker_manifest_list_t));

	jroot = cJSON_Parse(raw_file_buffer);

	cJSON *jschema = cJSON_GetObjectItem(jroot, "schemaVersion");
	if (cJSON_IsNumber(jschema))
		ml->schema_version = jschema->valueint;
	switch (ml->schema_version) {
	case 1: {
		// no manifetslist support (client answerd with v1 manifest)
		// construct a default manifest list for the v2 manifest
		cJSON *jarchitecture = cJSON_GetObjectItem(jroot, "architecture");
		cJSON *jtag = cJSON_GetObjectItem(jroot, "tag");
		if (cJSON_IsString(jarchitecture) && cJSON_IsString(jtag)) {
			ml->schema_version = 2;
			ml->manifests_size = 1;
			ml->manifests = mem_alloc0(sizeof(docker_remote_file_t *));
			ml->manifests[0] = mem_alloc0(sizeof(docker_remote_file_t));
			ml->manifests[0]->media_type = mem_strdup(MEDIA_TYPE_MANIFEST_V2);
			ml->manifests[0]->size = 0;
			ml->manifests[0]->digest_algorithm = NULL;
			ml->manifests[0]->digest = mem_strdup(jtag->valuestring);
			ml->manifests[0]->platform_arch = mem_strdup(jarchitecture->valuestring);
		} else {
			ERROR("Unsuported schema verison = %d", ml->schema_version);
			mem_free(ml);
			ml = NULL;
			goto out;
		}
		break;
	}
	case 2: {
		cJSON *jmanifests = cJSON_GetObjectItem(jroot, "manifests");
		ml->manifests_size = cJSON_GetArraySize(jmanifests);
		if (ml->manifests_size < 0) {
			ERROR("No manifests in list");
			mem_free(ml);
			ml = NULL;
			goto out;
		}

		cJSON *jmedia_type = cJSON_GetObjectItem(jroot, "mediaType");
		if (cJSON_IsString(jmedia_type)) {
			ml->media_type = mem_strdup(jmedia_type->valuestring);
		}

		ml->manifests = mem_alloc0(ml->manifests_size * sizeof(docker_remote_file_t *));
		for (int i = 0; i < ml->manifests_size; ++i) {
			cJSON *item = cJSON_GetArrayItem(jmanifests, i);
			ml->manifests[i] = parse_remote_file_new(item, ".json");
		}
		break;
	}
	default:
		ERROR("Unsuported schema verison = %d", ml->schema_version);
		mem_free(ml);
		ml = NULL;
	}
out:
	cJSON_Delete(jroot);
	return ml;
}

void
docker_manifest_list_free(docker_manifest_list_t *ml)
{
	if (ml->media_type)
		mem_free(ml->media_type);
	for (int i = 0; i < ml->manifests_size; ++i) {
		if (ml->manifests[i])
			docker_remote_file_free(ml->manifests[i]);
	}
	mem_free(ml);
}

docker_manifest_t *
docker_parse_manifest_new(const char *raw_file_buffer)
{
	cJSON *jroot = NULL;
	docker_manifest_t *manifest = mem_alloc0(sizeof(docker_manifest_t));

	jroot = cJSON_Parse(raw_file_buffer);
	// seems a manifest contains an array with just one item
	cJSON *jschema = cJSON_GetArrayItem(jroot, 0);
	if (cJSON_IsNumber(jschema))
		manifest->schema_version = jschema->valueint;

	cJSON *jmedia_type = cJSON_GetObjectItem(jroot, "mediaType");
	if (cJSON_IsString(jmedia_type)) {
		manifest->media_type = mem_strdup(jmedia_type->valuestring);
	}

	cJSON *jconfig = cJSON_GetObjectItem(jroot, "config");
	manifest->config = parse_remote_file_new(jconfig, ".json");

	cJSON *jlayers = cJSON_GetObjectItem(jroot, "layers");
	manifest->layers_size = cJSON_GetArraySize(jlayers);
	manifest->layers = mem_alloc0(manifest->layers_size * sizeof(docker_remote_file_t *));
	for (int i = 0; i < manifest->layers_size; ++i) {
		cJSON *item = cJSON_GetArrayItem(jlayers, i);
		manifest->layers[i] = parse_remote_file_new(item, ".tar.gz");
	}

	cJSON_Delete(jroot);
	return manifest;
}

void
docker_manifest_free(docker_manifest_t *manifest)
{
	if (manifest->media_type)
		mem_free(manifest->media_type);

	if (manifest->config)
		docker_remote_file_free(manifest->config);

	for (int i = 0; i < manifest->layers_size; ++i) {
		if (manifest->layers[i])
			docker_remote_file_free(manifest->layers[i]);
	}
	mem_free(manifest);
}

docker_config_t *
docker_parse_config_new(const char *raw_file_buffer)
{
	cJSON *jroot = NULL;
	docker_config_t *config = mem_alloc0(sizeof(docker_config_t));

	jroot = cJSON_Parse(raw_file_buffer);

	cJSON *jconfig = cJSON_GetObjectItem(jroot, "config");

	cJSON *jhostname = cJSON_GetObjectItem(jconfig, "Hostname");
	if (jhostname->type == cJSON_String)
		config->hostname = mem_strdup(jhostname->valuestring);

	cJSON *jdomainname = cJSON_GetObjectItem(jconfig, "Domainname");
	if (jdomainname->type == cJSON_String)
		config->domainname = mem_strdup(jdomainname->valuestring);

	cJSON *juser = cJSON_GetObjectItem(jconfig, "User");
	if (juser->type == cJSON_String)
		config->user = mem_strdup(juser->valuestring);

	if (cJSON_GetObjectItem(jconfig, "ExposedPorts")) {
		cJSON *jexposedports = cJSON_GetObjectItem(jconfig, "ExposedPorts")->child;
		for (cJSON *item = jexposedports; item; item = item->next) {
			if (item && item->type == cJSON_Object) {
				docker_exposed_port_t *port = mem_alloc0(sizeof(docker_exposed_port_t));
				INFO("Parsing port %s", item->string);
				sscanf(item->string, "%d/%9s", &port->port, port->protocol);
				config->exposedports_list = list_append(config->exposedports_list, port);
			}
		}
	}

	cJSON *jenv = cJSON_GetObjectItem(jconfig, "Env");
	if (cJSON_IsArray(jenv)) {
		config->env_size = cJSON_GetArraySize(jenv);
		config->env = mem_alloc0(config->env_size * sizeof(char *));
		for (int i = 0; i < config->env_size; ++i) {
			cJSON *item = cJSON_GetArrayItem(jenv, i);
			if (item && item->type == cJSON_String)
				config->env[i] = mem_strdup(item->valuestring);
		}
	}

	cJSON *jcmd = cJSON_GetObjectItem(jconfig, "Cmd");
	if (cJSON_IsArray(jcmd)) {
		config->cmd_size = cJSON_GetArraySize(jcmd);
		config->cmd = mem_alloc0(config->cmd_size * sizeof(char *));
		for (int i = 0; i < config->cmd_size; ++i) {
			cJSON *item = cJSON_GetArrayItem(jcmd, i);
			if (item && item->type == cJSON_String)
				config->cmd[i] = mem_strdup(item->valuestring);
		}
	}

	cJSON *jentrypoint = cJSON_GetObjectItem(jconfig, "Entrypoint");
	if (cJSON_IsArray(jentrypoint)) {
		config->entrypoint_size = cJSON_GetArraySize(jentrypoint);
		config->entrypoint = mem_alloc0(config->entrypoint_size * sizeof(char *));
		for (int i = 0; i < config->entrypoint_size; ++i) {
			cJSON *item = cJSON_GetArrayItem(jentrypoint, i);
			if (item && item->type == cJSON_String)
				config->entrypoint[i] = mem_strdup(item->valuestring);
		}
	}

	if (cJSON_GetObjectItem(jconfig, "Volumes")) {
		cJSON *jvolumes = cJSON_GetObjectItem(jconfig, "Volumes")->child;
		for (cJSON *item = jvolumes; item; item = item->next) {
			if (item && item->type == cJSON_Object) {
				config->volumes_list = list_append(config->volumes_list, mem_strdup(item->string));
			}
		}
	}

	if (cJSON_GetObjectItem(jconfig, "Labels")) {
		cJSON *jlabels = cJSON_GetObjectItem(jconfig, "Labels")->child;
		for (cJSON *item = jlabels; item; item = item->next) {
			if (item && item->type == cJSON_Object) {
				config->labels_list = list_append(config->labels_list, mem_strdup(item->string));
			}
		}
	}

	cJSON_Delete(jroot);
	return config;
}

void
docker_config_free(docker_config_t *cfg)
{
	if (cfg->hostname)
		mem_free(cfg->hostname);
	if (cfg->domainname)
		mem_free(cfg->domainname);
	if (cfg->user)
		mem_free(cfg->user);

	for (list_t *l = cfg->exposedports_list; l; l = l->next) {
		mem_free(l->data);
	}
	list_delete(cfg->exposedports_list);

	if (cfg->env) {
		for (int i = 0; i < cfg->env_size; ++i)
			mem_free(cfg->env[i]);
		mem_free(cfg->env);
	}

	if (cfg->cmd) {
		for (int i = 0; i < cfg->cmd_size; ++i)
			mem_free(cfg->cmd[i]);
		mem_free(cfg->cmd);
	}

	if (cfg->entrypoint) {
		for (int i = 0; i < cfg->entrypoint_size; ++i)
			mem_free(cfg->entrypoint[i]);
		mem_free(cfg->entrypoint);
	}

	for (list_t *l = cfg->labels_list; l; l = l->next) {
		mem_free(l->data);
	}
	list_delete(cfg->labels_list);

	mem_free(cfg);
}

void
docker_set_host_url(const char *url)
{
	host_url = mem_strdup(url);
}

int
docker_generate_basic_auth(const char *user, const char *password, const char *token_file)
{
	int ret = 0;

	char *in = mem_printf("%s:%s", user, password);
	size_t out_size = 256 * sizeof(char);
	char *out = mem_alloc0(out_size);

	INFO("Generating login token");
	b64_ntop((unsigned char *)in, strlen(in), out, out_size);

	// DEBUG("Basic Auth Token: %s\n", out);
	char *auth = mem_printf("Authorization: Basic %s", out);
	char *url = mem_printf("https://%s", host_url);

	const char *const argv[] = { CURL_PATH, "-fsSL", "-H", auth, url, NULL };
	ret = util_fork_and_execvp(CURL_PATH, argv);
	if (ret == 0) {
		INFO("Auth OK. Storing access token!");
		file_printf(token_file, "{ \"token\": \"%s\" }", out);
	}

	mem_free(in);
	mem_free(out);
	mem_free(auth);
	mem_free(url);

	return ret;
}

char *
docker_get_curl_token_new(char *image_name, char *token_file)
{
	char *url = mem_printf("https://auth.docker.io/token?service="
			       "registry.docker.io&scope=repository:%s%s:pull",
			       !strchr(image_name, '/') ? "library/" : "", image_name);

	if (!file_exists(token_file)) {
		const char *const argv[] = { CURL_PATH, "-fsSL", url, "-o", token_file, NULL };
		util_fork_and_execvp(CURL_PATH, argv);
	}

	cJSON *jroot = NULL;

	char *buf = file_read_new(token_file, BUF_SIZE);
	if (!buf) {
		ERROR("Could not read token file");
		return NULL;
	}

	jroot = cJSON_Parse(buf);
	cJSON *jtoken = cJSON_GetObjectItem(jroot, "token");

	char *token = mem_strdup(jtoken->valuestring);
	//DEBUG("token: %s", token);

	mem_free(url);
	cJSON_Delete(jroot);
	return token;
}

int
docker_download_manifest_list(const char *curl_token, const char *out_file, const char *image_name,
			      const char *image_tag)
{
	//char *url = mem_printf("https://registry-1.docker.io/v2/library/%s/manifests/%s", image_name, image_tag);
	char *url = mem_printf("https://%s/v2/%s%s/manifests/%s", host_url, !strchr(image_name, '/') ? "library/" : "",
			       image_name, image_tag);

	char *auth_basic = mem_printf("Authorization: Basic %s", curl_token);
	char *auth_bearer = mem_printf("Authorization: Bearer %s", curl_token);
	char *acceptlist = "Accept: " MEDIA_TYPE_MANIFEST_LIST_V2;

	const char *const argv_basic[] = { CURL_PATH,  "-fsSL", "-H", auth_basic, "-H",
					   acceptlist, url,     "-o", out_file,   NULL };
	const char *const argv_bearer[] = { CURL_PATH,  "-fsSL", "-H", auth_bearer, "-H",
					    acceptlist, url,     "-o", out_file,    NULL };

	int ret = util_fork_and_execvp(CURL_PATH, argv_bearer);
	if (ret != 0) {
		INFO("Bearer auth failed (curl returned %d), trying Basic auth", ret);
		ret = util_fork_and_execvp(CURL_PATH, argv_basic);
	}

	mem_free(url);
	mem_free(auth_basic);
	mem_free(auth_bearer);
	return ret;
}

int
docker_download_manifest(const char *curl_token, const char *out_file, const char *image_name, const char *image_tag)
{
	//char *url = mem_printf("https://registry-1.docker.io/v2/library/%s/manifests/%s", image_name, image_tag);
	char *url = mem_printf("https://%s/v2/%s%s/manifests/%s", host_url, !strchr(image_name, '/') ? "library/" : "",
			       image_name, image_tag);

	char *auth_basic = mem_printf("Authorization: Basic %s", curl_token);
	char *auth_bearer = mem_printf("Authorization: Bearer %s", curl_token);
	char *acceptv2 = "Accept: " MEDIA_TYPE_MANIFEST_V2;
	char *acceptv1 = "Accept: " MEDIA_TYPE_MANIFEST_V1;

	const char *const argv_basic[] = { CURL_PATH, "-fsSL",  "-H", auth_basic, "-H",     acceptv2,
					   "-H",      acceptv1, url,  "-o",       out_file, NULL };
	const char *const argv_bearer[] = { CURL_PATH, "-fsSL",  "-H", auth_bearer, "-H",     acceptv2,
					    "-H",      acceptv1, url,  "-o",	out_file, NULL };

	int ret = util_fork_and_execvp(CURL_PATH, argv_bearer);
	if (ret != 0) {
		INFO("Bearer auth failed (curl returned %d), trying Basic auth", ret);
		ret = util_fork_and_execvp(CURL_PATH, argv_basic);
	}

	mem_free(url);
	mem_free(auth_basic);
	mem_free(auth_bearer);
	return ret;
}

static int
download_docker_remote_file(const char *curl_token, const docker_remote_file_t *rf, const char *out_path,
			    const char *image_name)
{
	int ret = 0;
	char *image_hash = NULL;

	char *out_file = mem_printf("%s/%s%s", out_path, rf->digest, rf->suffix);

	if (file_exists(out_file) && file_size(out_file) == rf->size) {
		image_hash = util_hash_sha256_image_file_new(out_file);
		if (!strncmp(image_hash, rf->digest, strlen(image_hash))) {
			INFO("File %s already downloaded!", rf->digest);
			mem_free(image_hash);
			return ret;
		}
		mem_free(image_hash);
	}

	//char *url = mem_printf("https://registry-1.docker.io/v2/library/%s/blobs/%s:%s",
	char *url = mem_printf("https://%s/v2/%s%s/blobs/%s:%s", host_url, !strchr(image_name, '/') ? "library/" : "",
			       image_name, rf->digest_algorithm, rf->digest);

	char *auth_basic = mem_printf("Authorization: Basic %s", curl_token);
	char *auth_bearer = mem_printf("Authorization: Bearer %s", curl_token);
	const char *const argv_bearer[] = { CURL_PATH, "-fSL", "--progress", "-H", auth_bearer,
					    url,       "-o",   out_file,     NULL };
	const char *const argv_basic[] = {
		CURL_PATH, "-fSL", "--progress", "-H", auth_basic, url, "-o", out_file, NULL
	};

	ret = util_fork_and_execvp(CURL_PATH, argv_bearer);
	if (ret != 0)
		ret = util_fork_and_execvp(CURL_PATH, argv_basic);

	mem_free(url);
	mem_free(auth_basic);
	mem_free(auth_bearer);

	if (ret < 0) {
		ERROR("Download failed!");
		return ret;
	}

	image_hash = util_hash_sha256_image_file_new(out_file);
	if (strncmp(image_hash, rf->digest, strlen(image_hash))) {
		ERROR("SHA256 sum missmatch!");
		ret = -1;
	}
	INFO("Download of file %s completed!", rf->digest);

	if (image_hash)
		mem_free(image_hash);

	return ret;
}

int
docker_download_image(char *curl_token, const docker_manifest_t *manifest, const char *out_path, const char *image_name,
		      const char *image_tag)
{
	int ret = download_docker_remote_file(curl_token, manifest->config, out_path, image_name);
	if (ret < 0) {
		ERROR("Failed to download %s!", manifest->config->digest);
		return -1;
	}
	for (int i = 0; i < manifest->layers_size; ++i) {
		ret = download_docker_remote_file(curl_token, manifest->layers[i], out_path, image_name);
		if (ret < 0) {
			ERROR("Failed to download %s!", manifest->config->digest);
			return -1;
		}
	}
	INFO("Download image %s:%s completed!", image_name, image_tag);
	return 0;
}
