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

#include "guestos_mgr.h"
#include "guestos.h"
#include "guestos_config.h"

#include "cmld.h"
#include "download.h"
#include "smartcard.h"

#include "common/macro.h"
#include "common/list.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/fd.h"
#include "common/dir.h"
#include "common/event.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#define GUESTOS_MGR_VERIFY_HASH_ALGO SHA512
#define GUESTOS_MGR_FILE_MOVE_BLOCKSIZE 4096

// Notification title and messages regarding trustme system updates.
#define GUESTOS_MGR_UPDATE_TITLE "Trustme Update"
#define GUESTOS_MGR_UPDATE_DOWNLOAD "Downloading..."
#define GUESTOS_MGR_UPDATE_DOWNLOAD_CUSTOM_ICON "stat_sys_download" // Android drawable resource
#define GUESTOS_MGR_UPDATE_DOWNLOAD_NO_WIFI "Waiting for WiFi connection..."
#define GUESTOS_MGR_UPDATE_SUCCESS "Reboot to install"
#define GUESTOS_MGR_UPDATE_FAILED "Download failed"

static list_t *guestos_list = NULL;

static const char *guestos_basepath = NULL;

/******************************************************************************/

static void
guestos_mgr_purge_obsolete(void)
{
	INFO("Looking for obsolete GuestOSes to purge...");
	for (list_t *l = guestos_list; l; ) {
		list_t *next = l->next;
		guestos_t *os = l->data;
		guestos_t *latest = guestos_mgr_get_latest_by_name(guestos_get_name(os), true);
		if ((latest && guestos_get_version(os) < guestos_get_version(latest)) ||
				!strcmp(guestos_get_name(os), "a1os") ||  // update code, to be removed
				!strcmp(guestos_get_name(os), "a2os") ) { // update code, to be removed
			guestos_list = list_unlink(guestos_list, l);
			guestos_purge(os);
			guestos_free(os);
		}
		l = next;
	}
}

static int
guestos_mgr_load_operatingsystems_cb(const char *path, const char *name, UNUSED void *data)
{
	int res = 0; // counter

	char *dir = mem_printf("%s/%s", path, name);
	if (!file_is_dir(dir))
		goto cleanup;

	char *cfg_file = guestos_get_cfg_file_new(dir);
	char *sig_file = guestos_get_sig_file_new(dir);
	char *cert_file = guestos_get_cert_file_new(dir);

	smartcard_crypto_verify_result_t verify_result = smartcard_crypto_verify_file_block(
			cfg_file, sig_file, cert_file, GUESTOS_MGR_VERIFY_HASH_ALGO);
	if (verify_result != VERIFY_GOOD) {
		ERROR("Signature verification failed (%d) while loading GuestOS config %s, skipping.",
				verify_result, cfg_file);
	} else if (guestos_mgr_add_from_file(cfg_file) < 0) {
		WARN("Could not add guest operating system from file %s.", cfg_file);
	} else
		res = 1;

	mem_free(cfg_file);
	mem_free(sig_file);
	mem_free(cert_file);
cleanup:
	mem_free(dir);
	return res;
}

static int
guestos_mgr_load_operatingsystems(void)
{
	if (dir_foreach(guestos_basepath, &guestos_mgr_load_operatingsystems_cb, NULL) < 0) {
		WARN("Could not open %s to load operating system", guestos_basepath);
		return -1;
	}

	if (!guestos_list) {
		// Seems we dont have any operating system on storage
		WARN("No guest OS found on storage.");
		return -1;
	}

	guestos_mgr_purge_obsolete();

	return 0;
}

/******************************************************************************/

int
guestos_mgr_init(const char *path)
{
	ASSERT(path);
	ASSERT(!guestos_basepath);

	if (mkdir(path, 0700) < 0 && errno != EEXIST)
		return -1;

	guestos_basepath = mem_strdup(path);

	return guestos_mgr_load_operatingsystems();
}

int
guestos_mgr_add_from_file(const char *file)
{
	ASSERT(file);

	guestos_t *os = guestos_new_from_file(file, guestos_basepath);
	if (!os) {
		return -1;
	}

	guestos_list = list_append(guestos_list, os);

	return 0;
}

void
guestos_mgr_delete(guestos_t *os)
{
	ASSERT(os);
	ASSERT(0); // TODO
	guestos_free(os);
}

/******************************************************************************/

static bool
guestos_mgr_is_guestos_used_by_containers(const char *os_name)
{
	ASSERT(os_name);
	int n = cmld_containers_get_count();
	for (int i=0; i<n; i++) {
		container_t *c = cmld_container_get_by_index(i);
		const char *container_os_name = guestos_get_name(container_get_os(c));
		if (!strcmp(container_os_name, os_name)) {
			return true;
		}
	}
	return false;
}

static void
download_complete_cb(bool complete, unsigned int count, guestos_t *os, UNUSED void *data)
{
	IF_NULL_RETURN_ERROR(os);

	if (!complete || count > 0) {
		container_t *a0 = cmld_containers_get_a0();
		IF_NULL_RETURN_WARN(a0);

		container_set_notification(
				a0,
				1,
				"guestos_mgr",
				"cmld",
				GUESTOS_MGR_UPDATE_TITLE,
				complete ? GUESTOS_MGR_UPDATE_SUCCESS : GUESTOS_MGR_UPDATE_FAILED,
				NULL);
		container_send_notification_from_cmld(a0);
	}
}


/**
 * Downloads, if necessary, the images for the latest (by version) available GuestOS with the given name.
 * @param name	name of the GuestOS
 */
static void
guestos_mgr_download_latest(const char *name)
{
	IF_NULL_RETURN(name);

	guestos_t *os = guestos_mgr_get_latest_by_name(name, false);
	IF_NULL_RETURN_WARN(os);
	if (!guestos_images_are_complete(os, false))
		guestos_images_download(os, download_complete_cb, NULL);
}

void
guestos_mgr_update_images(void)
{
	// TODO: iterate containers and then download latest os?
	size_t n = guestos_mgr_get_guestos_count();
	for (size_t i=0; i<n; i++) {
		guestos_t *os = guestos_mgr_get_guestos_by_index(i);
		const char *os_name = guestos_get_name(os);
		if (guestos_mgr_is_guestos_used_by_containers(os_name)) {
			guestos_mgr_download_latest(os_name);
		}
	}
}


static char *
write_to_tmpfile_new(unsigned char *buf, size_t buflen)
{
	char *file = mem_strdup("tmpXXXXXXXX");
	int fd = mkstemp(file);
	if (fd != -1) {
		int len = fd_write(fd, (char *) buf, buflen);
		close(fd);
		if (len >= 0 && (size_t)len == buflen)
			return file;
		ERROR("Failed to write entire data (%zu bytes) to temp file %s", buflen, file);
	} else {
		ERROR("Failed to create temp file.");
	}
	mem_free(file);
	return NULL;
}


static void
push_config_verify_cb(smartcard_crypto_verify_result_t verify_result,
		const char *cfg_file, const char *sig_file, const char *cert_file,
		UNUSED smartcard_crypto_hashalgo_t hash_algo, UNUSED void *data)
{
	INFO("Push GuestOS config (Phase 2)");

	if (verify_result != VERIFY_GOOD) {
		ERROR("Signature verification failed (%d) for pushed GuestOS config %s, skipping.",
				verify_result, cfg_file);
		goto cleanup_tmpfiles;
	}

	guestos_t *os = guestos_new_from_file(cfg_file, guestos_basepath);
	if (!os) {
		ERROR("Could not instantiate GuestOS from temp file %s", cfg_file);
		goto cleanup_tmpfiles;
	}

	const char *os_name = guestos_get_name(os);
	uint64_t os_ver = guestos_get_version(os);
	const guestos_t *old_os = guestos_mgr_get_latest_by_name(os_name, false);
	if (old_os) {
		// existing os of same name => verify and update
		uint64_t old_ver = guestos_get_version(old_os);
		if (os_ver <= old_ver) {
			WARN("Skipping update of GuestOS %s version %" PRIu64
					" to older/same version %" PRIu64 ".",
					os_name, old_ver, os_ver);
			goto cleanup_os;
		}
		DEBUG("Updating GuestOS config for %s from v%" PRIu64 " to v%" PRIu64 ".",
				os_name, old_ver, os_ver);
	} else {
		// Fresh install
		DEBUG("Installing GuestOS config for %s v%" PRIu64 ".", os_name, os_ver);
	}

	// 1. create new guestos folder
	const char *dir = guestos_get_dir(os);
	if (mkdir(dir, 00755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir GuestOS directory %s", dir);
		goto cleanup_purge;
	}

	// 2. save pushed config, signature and cert
	if (file_move(cfg_file, guestos_get_cfg_file(os), GUESTOS_MGR_FILE_MOVE_BLOCKSIZE) < 0) {
		ERROR_ERRNO("Failed to move GuestOS config %s to %s",
				cfg_file, guestos_get_cfg_file(os));
		goto cleanup_purge;
	}
	if (file_move(sig_file, guestos_get_sig_file(os), GUESTOS_MGR_FILE_MOVE_BLOCKSIZE) < 0) {
		ERROR_ERRNO("Failed to move GuestOS config signature %s to %s",
				sig_file, guestos_get_sig_file(os));
		goto cleanup_purge;
	}
	if (file_move(cert_file, guestos_get_cert_file(os), GUESTOS_MGR_FILE_MOVE_BLOCKSIZE) < 0) {
		ERROR_ERRNO("Failed to move GuestOS config certificate %s to %s",
				cert_file, guestos_get_cert_file(os));
		goto cleanup_purge;
	}

	// 3. register new os instance
	guestos_list = list_append(guestos_list, os);

	container_t *a0 = cmld_containers_get_a0();
	if (a0) {
		container_set_notification(
				a0,
				1,
				"guestos_mgr",
				"cmld",
				GUESTOS_MGR_UPDATE_TITLE,
				cmld_is_wifi_active() ? GUESTOS_MGR_UPDATE_DOWNLOAD : GUESTOS_MGR_UPDATE_DOWNLOAD_NO_WIFI,
				cmld_is_wifi_active() ? GUESTOS_MGR_UPDATE_DOWNLOAD_CUSTOM_ICON : NULL);
		container_send_notification_from_cmld(a0);
	}

	// 4. trigger image download if os is used by a container
	if (guestos_mgr_is_guestos_used_by_containers(os_name)) {
		guestos_mgr_download_latest(os_name);
	}
	return;

cleanup_purge:
	guestos_purge(os);
cleanup_os:
	guestos_free(os);
cleanup_tmpfiles:
	unlink(cfg_file);
	unlink(sig_file);
	unlink(cert_file);
}


int
guestos_mgr_push_config(unsigned char *cfg, size_t cfglen, unsigned char *sig, size_t siglen,
		unsigned char *cert, size_t certlen)
{
	INFO("Push GuestOS config (Phase 1)");

	char *tmp_cfg_file = write_to_tmpfile_new(cfg, cfglen);
	char *tmp_sig_file = write_to_tmpfile_new(sig, siglen);
	char *tmp_cert_file = write_to_tmpfile_new(cert, certlen);
	int res = -1;
	if (tmp_cfg_file && tmp_sig_file && tmp_cert_file) {
		res = smartcard_crypto_verify_file(tmp_cfg_file, tmp_sig_file, tmp_cert_file,
				GUESTOS_MGR_VERIFY_HASH_ALGO, push_config_verify_cb, NULL);
	}
	if (res < 0) {
		unlink(tmp_cfg_file);
		unlink(tmp_sig_file);
		unlink(tmp_cert_file);
	}
	mem_free(tmp_cfg_file);
	mem_free(tmp_sig_file);
	mem_free(tmp_cert_file);
	return res;
}


/******************************************************************************/

guestos_t *
guestos_mgr_get_latest_by_name(const char *name, bool complete)
{
	IF_NULL_RETVAL(name, NULL);

	uint64_t latest_version = 0;
	guestos_t *latest_os = NULL;
	for (list_t *l = guestos_list; l; l = l->next) {
		if (!strcmp(name, guestos_get_name(l->data))) {
			guestos_t *os = l->data;
			uint64_t version = guestos_get_version(os);
			// TODO cache image complete result in guestos instance and get rid of check here?
			if (complete && !guestos_images_are_complete(os, false)) {
				DEBUG("GuestOS %s v%" PRIu64 " is incomplete (missing images) or broken, skipping.",
						guestos_get_name(os), version);
				continue;
			}
			if (version > latest_version) {
				latest_version = version;
				latest_os = os;
			}
		}
	}
	return latest_os;
}


size_t
guestos_mgr_get_guestos_count(void)
{
	return list_length(guestos_list);
}


guestos_t *
guestos_mgr_get_guestos_by_index(size_t index)
{
	return list_nth_data(guestos_list, index);
}


#if 0
const guestos_mount_t *
guestos_get_mount(const guestos_t *os, size_t nth)
{
	ASSERT(os);
	if (nth >= os->mntc)
		return NULL;
	else
		return &os->mntv[nth];
}

size_t
guestos_get_mount_count(const guestos_t *os)
{
	ASSERT(os);
	return os->mntc;
}

const char *
guestos_mount_get_img(const guestos_mount_t *mnt)
{
	ASSERT(mnt);
	return mnt->img;
}

const char *
guestos_mount_get_dir(const guestos_mount_t *mnt)
{
	ASSERT(mnt);
	return mnt->dir;
}

const char *
guestos_mount_get_fs(const guestos_mount_t *mnt)
{
	ASSERT(mnt);
	return mnt->fs;
}

enum guestos_mount_type
guestos_mount_get_type(const guestos_mount_t *mnt)
{
	ASSERT(mnt);
	return mnt->type;
}
#endif
