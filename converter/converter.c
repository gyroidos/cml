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

#ifdef ANDROID
#include "device/fraunhofer/common/cml/converter/guestos.pb-c.h"
#else
#include "guestos.pb-c.h"
#endif

#include "common/macro.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/list.h"
#include "common/protobuf.h"
#include "common/mem.h"

#include "docker.h"
#include "util.h"
#include "control.h"

#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define BUF_SIZE 10 * 4096

#define WORK_PATH "/tmp/trustx-converter"
#define IMAGE_NAME_ROOT "root.img"
#define MIN_INIT "/sbin/cservice"
#define FILE_SERVER_ETH "eth0"

#define SSIG_KEY_FILE UTIL_PKI_PATH "dockerlocal-ssig.key"
#define SSIG_CERT_FILE UTIL_PKI_PATH "dockerlocal-ssig.cert"
#define LOCALCA_CERT_FILE UTIL_PKI_PATH "ssig_rootca.cert"

#define SYSTEM_ARCH "x86" // TODO get this from running system
#define WWW_ROOT "/www/pages/operatingsystems"
#define TMP_OS_IMAGES_PREFIX "/tmp/operatingsystems/"
#define WWW_OS_IMAGES_DIR TMP_OS_IMAGES_PREFIX SYSTEM_ARCH

static char *
get_ifname_ip_new(const char *ifname)
{
	struct ifreq ifr;
	struct in_addr ip;
	int sock;

	char *ip_str = NULL;

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

	IF_FALSE_GOTO_DEBUG_ERRNO((ioctl(sock, SIOCGIFADDR, &ifr) == 0), err);
	ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

	ip_str = mem_strdup(inet_ntoa(ip));
err:
	close(sock);
	if (ip_str == NULL) {
		FATAL_ERRNO("Failed to get ifname %s ip address string.", ifname);
	}
	return ip_str;
}

int
write_guestos_config(docker_config_t *config, const char *root_image_file, const char *image_path,
		     const char *image_name, const char *image_tag)
{
	int ret = -1;
	char *out_file;
	char *out_sig_file;
	char *out_cert_file;
	char *out_image_path_versioned;
	char *out_www_image_path_versioned;
	char *image_path_unversioned;

	GuestOSConfig cfg = GUEST_OSCONFIG__INIT;

	cfg.name = mem_printf("%s_%s", image_name, image_tag);

	cfg.upstream_version = mem_strdup(image_tag);
	cfg.hardware = "x86";
	cfg.version = (int)time(NULL);

	image_path_unversioned = mem_printf("%s/%s_%s", image_path, image_name, image_tag);
	out_image_path_versioned = mem_printf("%s-%" PRId64, image_path_unversioned, cfg.version);
	out_file = mem_printf("%s.conf", out_image_path_versioned);

	cfg.n_mounts = list_length(config->volumes_list) + 1;
	INFO("cfg.n_mounts: %zu", cfg.n_mounts);
	cfg.mounts = mem_new(GuestOSMount *, cfg.n_mounts);

	GuestOSMount mount_root = GUEST_OSMOUNT__INIT;
	mount_root.image_file = strtok(mem_strdup(IMAGE_NAME_ROOT), ".");
	mount_root.mount_point = mem_strdup("/");
	mount_root.fs_type = mem_strdup("squashfs");
	mount_root.mount_type = GUEST_OSMOUNT__TYPE__SHARED_RW;

	// add image_sha1 and image_sha256 values
	mount_root.has_image_size = true;
	mount_root.image_size = file_size(root_image_file);
	mount_root.image_sha1 = util_hash_sha_image_file_new(root_image_file);
	mount_root.image_sha2_256 = util_hash_sha256_image_file_new(root_image_file);

	cfg.mounts[0] = &mount_root;

	int i = 1;
	// default sceleton for every volume
	GuestOSMount mount_vol = GUEST_OSMOUNT__INIT;

	for (list_t *l = config->volumes_list; l; l = l->next) {
		char *vol_mount = l->data;
		INFO("Config Volume: %s", vol_mount);

		cfg.mounts[i] = mem_new0(GuestOSMount, 1);
		memcpy(cfg.mounts[i], &mount_vol, sizeof(GuestOSMount));

		cfg.mounts[i]->image_file = mem_printf("volume_%d", i);
		cfg.mounts[i]->mount_point = mem_strdup(vol_mount);
		cfg.mounts[i]->fs_type = mem_strdup("ext4");
		cfg.mounts[i]->mount_type = GUEST_OSMOUNT__TYPE__EMPTY;
		cfg.mounts[i]->has_def_size = true;
		i++;
	}

	cfg.n_init_env = config->env_size;
	cfg.init_env = mem_new(char *, config->env_size);
	for (int i = 0; i < config->env_size; ++i) {
		INFO("Env[%d]: %s", i, config->env[i]);
		cfg.init_env[i] = config->env[i];
	}

	int index = 0;
	int init_size = config->entrypoint_size + config->cmd_size;
	char **init = mem_new(char *, init_size);
	for (int i = 0; i < config->entrypoint_size; ++i, ++index) {
		INFO("Config Entrypoint[%d]: %s", i, config->entrypoint[i]);
		init[index] = config->entrypoint[i];
	}
	for (int i = 0; i < config->cmd_size; ++i, ++index) {
		INFO("Config Cmd[%d]: %s", i, config->cmd[i]);
		init[index] = config->cmd[i];
	}

	cfg.init_path = MIN_INIT;
	cfg.n_init_param = init_size;
	cfg.init_param = &init[0];

	for (list_t *l = config->exposedports_list; l; l = l->next) {
		docker_exposed_port_t *port = l->data;
		INFO("Config Exposed Port: %d (%s)", port->port, port->protocol);
	}
	for (list_t *l = config->labels_list; l; l = l->next) {
		char *label = l->data;
		INFO("Config Label: %s", label);
	}

	I18NString description = I18_NSTRING__INIT;
	description.en = mem_printf("Converted docker image: %s:%s", image_name, image_tag);
	description.de = mem_printf("Konvertiertes docker image: %s:%s", image_name, image_tag);
	cfg.description = &description;

	// skip siging and pushing if no control interface is available
	if (!control_is_enabled()) {
		protobuf_message_write_to_file(out_file, (ProtobufCMessage *)&cfg);
		goto free_stuff;
	}

	char *local_ip = get_ifname_ip_new("eth0");
	cfg.update_base_url = mem_printf("http://%s/", local_ip);
	mem_free(local_ip);

	protobuf_message_write_to_file(out_file, (ProtobufCMessage *)&cfg);

	out_sig_file = mem_printf("%s.sig", out_image_path_versioned);
	out_cert_file = mem_printf("%s.cert", out_image_path_versioned);
	if (!file_exists(SSIG_KEY_FILE)) {
		if (util_gen_pki() < 0)
			WARN("Could not generate PKI and register PKI");
		else if (file_exists(LOCALCA_CERT_FILE)) {
			control_register_localca(LOCALCA_CERT_FILE);
		}
	}
	ret = util_sign_guestos(out_sig_file, out_file, SSIG_KEY_FILE);
	if (ret == 0) {
		if (file_copy(SSIG_CERT_FILE, out_cert_file, file_size(SSIG_CERT_FILE), 512, 0) < 0)
			WARN("Could not copy Certificate to %s", out_cert_file);
	}

	if (dir_mkdir_p(WWW_OS_IMAGES_DIR, 0755))
		ERROR_ERRNO("Can't create folder for hosting image files");

	if (symlink(TMP_OS_IMAGES_PREFIX, WWW_ROOT) < 0 && errno != EEXIST)
		ERROR_ERRNO("Can't symlink %s foder to %s", TMP_OS_IMAGES_PREFIX, WWW_ROOT);

	out_www_image_path_versioned = mem_printf("%s/%s_%s-%" PRId64, WWW_OS_IMAGES_DIR,
						  image_name, image_tag, cfg.version);

	if (rename(image_path_unversioned, out_www_image_path_versioned) < 0)
		ERROR_ERRNO("Can't rename dir %s", image_path_unversioned);
	else
		ret = control_push_guestos(out_file, out_cert_file, out_sig_file);

	mem_free(cfg.update_base_url);
	mem_free(out_sig_file);
	mem_free(out_cert_file);
	mem_free(out_www_image_path_versioned);

free_stuff:
	for (uint32_t j = 0; j < cfg.n_mounts; ++j) {
		mem_free(cfg.mounts[j]->image_file);
		mem_free(cfg.mounts[j]->mount_point);
		mem_free(cfg.mounts[j]->fs_type);
		mem_free(cfg.mounts[j]->image_sha1);
		mem_free(cfg.mounts[j]->image_sha2_256);
		if (j > 0) {
			mem_free(cfg.mounts[j]);
		}
	}
	mem_free(cfg.name);
	mem_free(cfg.upstream_version);
	mem_free(cfg.mounts);
	mem_free(description.en);
	mem_free(description.de);
	mem_free(init);
	mem_free(image_path_unversioned);
	mem_free(out_image_path_versioned);
	mem_free(out_file);

	return ret;
}

char *
merge_layers_new(docker_manifest_t *manifest, char *in_path, char *out_path, char *image_name,
		 char *image_tag)
{
	char *target_image_path = mem_printf("%s/%s_%s", out_path, image_name, image_tag);
	char *extracted_image_path =
		mem_printf("%s/%s_%s_extracted", out_path, image_name, image_tag);
	char *image_file = NULL;

	if (dir_mkdir_p(extracted_image_path, 0755) < 0) {
		ERROR_ERRNO("Can't create dir %s", extracted_image_path);
		goto out;
	}
	if (dir_mkdir_p(target_image_path, 0755) < 0) {
		ERROR_ERRNO("Can't create dir %s", target_image_path);
		goto out;
	}

	for (int i = 0; i < manifest->layers_size; ++i) {
		char *layer_file_name = mem_printf("%s/%s%s", in_path, manifest->layers[i]->digest,
						   manifest->layers[i]->suffix);
		INFO("Extracting layer[%d]: %s", i, layer_file_name);
		if (-1 == util_tar_extract(layer_file_name, extracted_image_path)) {
			ERROR_ERRNO("Failed to extract %s", layer_file_name);
			mem_free(layer_file_name);
			goto out;
		}
		mem_free(layer_file_name);
	}
	image_file = mem_printf("%s/%s", target_image_path, IMAGE_NAME_ROOT);
	if (util_squash_image(extracted_image_path, image_file) < 0) {
		mem_free(image_file);
		image_file = NULL;
		goto out;
	}
out:
	mem_free(extracted_image_path);
	mem_free(target_image_path);
	return image_file;
}

void
print_usage(char *progname)
{
	ERROR("Usage: %s login -u <username> -p <password>"
	      " -r <hostname:port>",
	      progname);
	ERROR("Usage: %s pull [-r <hostname:port>] [-a <arch>]"
	      " <imagename> [-t <imagetag>]",
	      progname);
	exit(-1);
}

static const struct option pull_options[] = { { "registry", optional_argument, 0, 'r' },
					      { "arch", optional_argument, 0, 'a' },
					      { "tag", optional_argument, 0, 't' },
					      { "help", no_argument, 0, 'h' },
					      { 0, 0, 0, 0 } };

static const struct option login_options[] = { { "registry", required_argument, 0, 'r' },
					       { "user", required_argument, 0, 'u' },
					       { "password", required_argument, 0, 'p' },
					       { "help", no_argument, 0, 'h' },
					       { 0, 0, 0, 0 } };

int
main(UNUSED int argc, char **argv)
{
	char *buf;
	char *manifest_file = NULL;
	char *manifest_list_file = NULL;
	char *image_tag = NULL;
	char *image_name = NULL;
	;
	char *image_arch = NULL;

	char *config_file_name = NULL;
	docker_config_t *config = NULL;
	char *trustx_image_path = NULL;
	char *trustx_image_file = NULL;

	docker_manifest_list_t *ml = NULL;
	char *manifest_url_digest = NULL;
	docker_manifest_t *manifest = NULL;

	logf_register(&logf_file_write, stdout);

	char *docker_image_path = mem_printf("%s/%s", WORK_PATH, "docker_image");
	if (dir_mkdir_p(docker_image_path, 0755) < 0) {
		ERROR_ERRNO("Can't create working dir %s", docker_image_path);
	}

	char *token_file = mem_printf("%s/curl_token", docker_image_path);

	// need at least one more argument (command string)
	if (optind >= argc)
		print_usage(argv[0]);

	const char *command = argv[optind++];
	if (!strcasecmp(command, "pull")) {
		optind--;
		char **pull_argv = &argv[optind];
		int pull_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		const char *url = "registry-1.docker.io";
		image_arch = "amd64";
		image_tag = "latest";
		for (int c, option_index = 0;
		     - 1 != (c = getopt_long(pull_argc, pull_argv, "t:r:a:", pull_options,
					     &option_index));) {
			switch (c) {
			case 'r':
				url = optarg ? optarg : "registry-1.docker.io";
				break;
			case 't':
				image_tag = optarg ? optarg : "latest";
				break;
			case 'a':
				image_arch = optarg ? optarg : "amd64";
				break;
			default:
				print_usage(argv[0]);
			}
		}
		optind += argc - pull_argc; // adjust optind to be used with argv
		// need at least one more argument (i.e. command string)
		if (optind >= argc)
			print_usage(argv[0]);

		docker_set_host_url(url);
		image_name = argv[optind++];
		INFO("imagename %s", image_name);
	}
	if (!strcasecmp(command, "login")) {
		optind--;
		char **login_argv = &argv[optind];
		int login_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		const char *url = NULL;
		const char *user = NULL;
		const char *password = NULL;
		for (int c, option_index = 0;
		     - 1 != (c = getopt_long(login_argc, login_argv, ":r:u:p", login_options,
					     &option_index));) {
			switch (c) {
			case 'r':
				url = optarg;
				break;
			case 'u':
				user = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			default:
				print_usage(argv[0]);
			}
		}
		if (!user || !password || !url) {
			ERROR("no user/password given!");
			print_usage(argv[0]);
		}
		docker_set_host_url(url);
		docker_generate_basic_auth(user, password, token_file);
		mem_free(token_file);
		mem_free(docker_image_path);
		return 0;
	}

	char *token = docker_get_curl_token_new(image_name, token_file);
	IF_NULL_GOTO_ERROR(token, err);

	manifest_list_file = mem_printf("%s/%s", docker_image_path, "manifests.json");
	if (file_exists(manifest_list_file))
		unlink(manifest_list_file);

	if (docker_download_manifest_list(token, manifest_list_file, image_name, image_tag) < 0) {
		ERROR("Could not download manifest list");
		goto err;
	}
	DEBUG("Trying to read manifest list %s", manifest_list_file);
	buf = file_read_new(manifest_list_file, BUF_SIZE);
	if (!buf) {
		ERROR("Could not read manifest list file");
		goto err;
	}

	ml = docker_parse_manifest_list_new(buf);

	mem_free(buf);
	buf = NULL;

	for (int i = 0; i < ml->manifests_size; ++i) {
		if (!strcmp(ml->manifests[i]->platform_arch, image_arch)) {
			if (ml->manifests[i]->digest_algorithm == NULL) {
				manifest_url_digest = mem_strdup(image_tag);
			} else {
				manifest_url_digest =
					mem_printf("%s:%s", ml->manifests[i]->digest_algorithm,
						   ml->manifests[i]->digest);
			}
			if (strcmp(image_arch, "arm")) // for arm run throuh to latest subarch
				break;
		}
	}
	if (!manifest_url_digest) {
		ERROR("No manifets for requested architecture found!");
		goto err;
	}
	INFO("manifests with url digest %s", manifest_url_digest);

	manifest_file = mem_printf("%s/%s", docker_image_path, "manifest.json");
	if (file_exists(manifest_file))
		unlink(manifest_file);

	if (docker_download_manifest(token, manifest_file, image_name, manifest_url_digest) < 0) {
		ERROR("Could not download manifest");
		goto err;
	}

	DEBUG("Trying to read manifest %s", manifest_file);
	buf = file_read_new(manifest_file, BUF_SIZE);
	if (!buf) {
		ERROR("Could not read manifest file");
		goto err;
	}

	manifest = docker_parse_manifest_new(buf);

	mem_free(buf);
	buf = NULL;

	if (docker_download_image(token, manifest, docker_image_path, image_name, image_tag) < 0) {
		ERROR("Downloading image %s failed!", image_name);
		goto err;
	}

	INFO("Cleaning up token_file: %s", token_file);
	if (file_exists(token_file))
		remove(token_file);

	config_file_name = mem_printf("%s/%s%s", docker_image_path, manifest->config->digest,
				      manifest->config->suffix);
	DEBUG("Trying to read config %s", config_file_name);
	buf = file_read_new(config_file_name, BUF_SIZE);
	if (!buf) {
		ERROR("Could not read config file");
		goto err;
	}
	config = docker_parse_config_new(buf);

	// replace the slashes in docker image name to be compatible with trustme
	// guestos names, e.g. library/debian -> library_debian
	char *strp = image_name;
	while ((strp = strchr(strp, '/')) != NULL)
		*strp++ = '_';

	trustx_image_path = mem_printf("%s/%s", WORK_PATH, "trustx_image");
	if (dir_mkdir_p(trustx_image_path, 0755) < 0) {
		ERROR_ERRNO("Can't create out dir %s", trustx_image_path);
		goto err;
	}

	trustx_image_file = merge_layers_new(manifest, docker_image_path, trustx_image_path,
					     image_name, image_tag);
	if (NULL == trustx_image_file) {
		ERROR("Failed to merge layers resulting image file is NULL!");
		goto err;
	}

	write_guestos_config(config, trustx_image_file, trustx_image_path, image_name, image_tag);

	mem_free(manifest_list_file);
	mem_free(manifest_file);
	mem_free(docker_image_path);
	mem_free(trustx_image_path);
	mem_free(trustx_image_file);

	docker_manifest_free(manifest);
	docker_config_free(config);

	mem_free(token_file);
	mem_free(token);
	return 0;

err:
	INFO("Cleaning up token_file: %s", token_file);
	if (file_exists(token_file))
		remove(token_file);
	mem_free(token_file);
	if (token)
		mem_free(token);

	if (manifest_list_file)
		mem_free(manifest_list_file);
	if (manifest_url_digest)
		mem_free(manifest_url_digest);
	if (manifest_file)
		mem_free(manifest_file);
	if (docker_image_path)
		mem_free(docker_image_path);
	if (trustx_image_path)
		mem_free(trustx_image_path);
	if (trustx_image_file)
		mem_free(trustx_image_file);

	if (manifest)
		docker_manifest_free(manifest);
	if (config)
		docker_config_free(config);
	return -1;
}
