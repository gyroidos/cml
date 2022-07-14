/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#include "guestos.h"
#include "guestos_config.h"

#include "hardware.h"
#include "download.h"
#include "cmld.h"
#include "crypto.h"
#include "tss.h"
#include "audit.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

struct guestos {
	char *dir;			       ///< directory where the guest OS'es files are stored
	char *cfg_file;			       ///< config file name
	char *sig_file;			       ///< config signature file name
	char *cert_file;		       ///< config certificate file name
	guestos_config_t *cfg;		       ///< pointer to GuestOS config struct
	guestos_verify_result_t verify_result; ///< result of guestos signature verification

	bool downloading; ///< indicates download in progress
};

#define GUESTOS_MAX_DOWNLOAD_ATTEMPTS 3
#define GUESTOS_FLASHED_FILE "flash_complete" // TODO check contents of partitions instead!
#define GUESTOS_FLASH_BLOCKSIZE 512	      // blocksize in bytes for flashing partitions
#define GUESTOS_VERIFY_BLOCKSIZE 4096	      // blocksize in bytes for verifying partitions

/******************************************************************************/

char *
guestos_get_cfg_file_new(const char *dir)
{
	return mem_printf("%s.conf", dir);
}

char *
guestos_get_sig_file_new(const char *dir)
{
	return mem_printf("%s.sig", dir);
}

char *
guestos_get_cert_file_new(const char *dir)
{
	return mem_printf("%s.cert", dir);
}

char *
guestos_get_ca_file_new(const char *dir)
{
	return mem_printf("%s.ca", dir);
}

/******************************************************************************/

/**
 * Internal constructor for guestos_t.
 * @param cfg	the underlying guestos_config_t object for this GuestOS
 * @param file	path of the corresponding file where this config is stored.
 *		Should be NULL to derive the filename automatically from the GuestOS name and version.
 * @param basepath  the base directory where GuestOSes and their configs are stored
 */
static guestos_t *
guestos_new_internal(guestos_config_t *cfg, const char *basepath)
{
	ASSERT(cfg);
	//ASSERT(file);
	ASSERT(basepath);
	// TODO: validate loaded config data?
	// check that name does not contain '/'
	const char *guestos_name = guestos_config_get_name(cfg);
	ASSERT(guestos_name);
	if (strchr(guestos_name, '/')) {
		WARN("Invalid character ('/') in GuestOS name %s.", guestos_name);
		guestos_config_free(cfg);
		return NULL;
	}
	guestos_t *os = mem_new(guestos_t, 1);
	os->dir = mem_printf("%s/%s-%" PRIu64 "", basepath, guestos_name,
			     guestos_config_get_version(cfg));
	os->cfg_file = guestos_get_cfg_file_new(os->dir);
	os->sig_file = guestos_get_sig_file_new(os->dir);
	os->cert_file = guestos_get_cert_file_new(os->dir);
	os->cfg = cfg;
	os->downloading = false;
	return os;
}

guestos_t *
guestos_new_from_file(const char *file, const char *basepath)
{
	ASSERT(file);
	ASSERT(basepath);
	DEBUG("Loading GuestOS from \"%s\".", file);

	guestos_config_t *cfg = guestos_config_new_from_file(file);
	if (!cfg) {
		ERROR("Failed loading GuestOS from file \"%s\".", file);
		return NULL;
	}
	return guestos_new_internal(cfg, basepath);
}

guestos_t *
guestos_new_from_buffer(unsigned char *buf, size_t buflen, const char *basepath)
{
	ASSERT(buf);
	ASSERT(basepath);
	DEBUG("Instantiating GuestOS from buffer %p (length=%zu).", buf, buflen);

	guestos_config_t *cfg = guestos_config_new_from_buffer(buf, buflen);
	if (!cfg) {
		ERROR("Failed to instantiate GuestOS from buffer %p (length=%zu).", buf, buflen);
		return NULL;
	}
	return guestos_new_internal(cfg, basepath);
}

/**
 * Free an operating system data structure. Does not remove the persistent
 * parts of the operating system, i.e. the configuration and the images.
 * @param os The operating system to be freed.
 */
void
guestos_free(guestos_t *os)
{
	IF_NULL_RETURN(os);
	mem_free0(os->cert_file);
	mem_free0(os->sig_file);
	mem_free0(os->cfg_file);
	mem_free0(os->dir);
	guestos_config_free(os->cfg);
	mem_free0(os);
}

/******************************************************************************/

typedef void (*check_mount_image_complete_cb)(guestos_check_mount_image_result_t res, guestos_t *os,
					      mount_entry_t *e, void *data);

typedef struct check_mount_image {
	guestos_t *os;
	mount_entry_t *e;
	char *img_path; // free me after use
	check_mount_image_complete_cb cb;
	void *data;
} check_mount_image_t;

static check_mount_image_t *
check_mount_image_new(guestos_t *os, mount_entry_t *e, char *img_path,
		      check_mount_image_complete_cb cb, void *data)
{
	check_mount_image_t *task = mem_new(check_mount_image_t, 1);
	task->os = os;
	task->e = e;
	task->cb = cb;
	task->img_path = mem_strdup(img_path);
	task->data = data;
	return task;
}

static void
check_mount_image_free(check_mount_image_t *task)
{
	IF_NULL_RETURN_WARN(task);
	mem_free0(task->img_path);
	mem_free0(task);
}

static void
check_mount_image_cb_sha256(const char *hash_string, UNUSED const char *hash_file,
			    UNUSED crypto_hashalgo_t hash_algo, void *data)
{
	check_mount_image_t *task = data;
	ASSERT(task);

	bool match = mount_entry_match_sha256(task->e, hash_string);
	task->cb(match ? CHECK_IMAGE_GOOD : CHECK_IMAGE_HASH_MISMATCH, task->os, task->e,
		 task->data);

	check_mount_image_free(task);
}

static void
check_mount_image_cb_sha1(const char *hash_string, UNUSED const char *hash_file,
			  UNUSED crypto_hashalgo_t hash_algo, void *data)
{
	check_mount_image_t *task = data;
	ASSERT(task);

	bool match = mount_entry_match_sha1(task->e, hash_string);
	if (match) {
		// compute next hash
		crypto_hash_file(task->img_path, SHA256, check_mount_image_cb_sha256, task);
		return;
	}
	task->cb(CHECK_IMAGE_HASH_MISMATCH, task->os, task->e, task->data);

	check_mount_image_free(task);
}

static uint8_t *
convert_hex_to_bin_new(const char *hex_str, int *out_length)
{
	int len = strlen(hex_str);
	int i = 0, j = 0;
	*out_length = (len + 1) / 2;

	uint8_t *bin = mem_alloc0(*out_length);

	if (len % 2 == 1) {
		// odd length -> we need to pad
		IF_FALSE_GOTO(sscanf(&(hex_str[0]), "%1hhx", &(bin[0])) == 1, err);
		i = j = 1;
	}

	for (; i < len; i += 2, j++) {
		IF_FALSE_GOTO(sscanf(&(hex_str[i]), "%2hhx", &(bin[j])) == 1, err);
	}

	return bin;
err:
	ERROR("Converstion of hex string to bin failed!");
	mem_free0(bin);
	return NULL;
}

guestos_check_mount_image_result_t
guestos_check_mount_image_block(const guestos_t *os, const mount_entry_t *e, bool thorough)
{
	ASSERT(os);
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	uint64_t img_size = mount_entry_get_size(e);

	char *img_path = mem_printf("%s/%s.img", guestos_get_dir(os), img_name);
	DEBUG("Checking image %s (%s, blocking)", img_path, thorough ? "thorough" : "quick");

	guestos_check_mount_image_result_t res = CHECK_IMAGE_GOOD;
	if (!file_exists(img_path)) {
		DEBUG("Checking image %s: file does not exist", img_path);
		res = CHECK_IMAGE_ACCESS_FAILED;
		goto cleanup;
	}
	uint64_t size = (uint64_t)file_size(img_path);
	if (size != img_size) {
		DEBUG("Checking image %s: invalid file size (actual size %" PRIu64
		      ", expected %" PRIu64 " bytes)",
		      img_path, size, img_size);
		res = CHECK_IMAGE_SIZE_MISMATCH;
		goto cleanup;
	}
	if (thorough) {
		bool match = false;
		if (mount_entry_get_sha256(e) == NULL) { // fallback to sha1
			char *sha1 = crypto_hash_file_block_new(img_path, SHA1);
			match = mount_entry_match_sha1(e, sha1);
			mem_free0(sha1);
		} else {
			char *sha256 = crypto_hash_file_block_new(img_path, SHA256);
			match = mount_entry_match_sha256(e, sha256);
			if (match) { // will only be executed if hash matches to signed config
				int sha256_bin_len;
				uint8_t *sha256_bin =
					convert_hex_to_bin_new(sha256, &sha256_bin_len);
				tss_ml_append(img_path, sha256_bin, sha256_bin_len, TSS_SHA256);
				mem_free0(sha256_bin);
			}
			mem_free0(sha256);
		}
		if (!match)
			res = CHECK_IMAGE_HASH_MISMATCH;
	}

cleanup:
	mem_free0(img_path);
	return res;
}

bool
guestos_images_are_complete(const guestos_t *os, bool thorough)
{
	ASSERT(os);
	INFO("Checking images of GuestOS %s v%" PRIu64 " (%s)", guestos_get_name(os),
	     guestos_get_version(os), thorough ? "thorough" : "quick");

	bool res = true;
	mount_t *mnt = mount_new();	   // need to get "mounts" to get image URLs... feels wrong
	guestos_fill_mount(os, mnt);	   // append mounts to be checked
	guestos_fill_mount_setup(os, mnt); // append setup mode mounts to be check
	size_t n = mount_get_count(mnt);
	for (size_t i = 0; i < n; i++) {
		mount_entry_t *e = mount_get_entry(mnt, i);
		enum mount_type t = mount_entry_get_type(e);
		if (t != MOUNT_TYPE_SHARED && t != MOUNT_TYPE_FLASH && t != MOUNT_TYPE_OVERLAY_RO &&
		    t != MOUNT_TYPE_SHARED_RW)
			continue;
		if (guestos_check_mount_image_block(os, e, thorough) != CHECK_IMAGE_GOOD) {
			res = false;
			break;
		}
	}
	mount_free(mnt);
	return res;
}

/**
 * Performs a thorough check on the integrity of a mount image and deliver the
 * result via the given callback.
 * The file exists, has the correct size and matching hash values.
 *
 * @param os the guestos
 * @param e the mount entry for the image to be verified
 * @param cb callback to deliver the result back to the caller
 * @param data data parameter passed to the callback
 */
static void
guestos_check_mount_image(guestos_t *os, mount_entry_t *e, check_mount_image_complete_cb cb,
			  void *data)
{
	ASSERT(os);
	ASSERT(e);
	ASSERT(cb);

	guestos_check_mount_image_result_t res = guestos_check_mount_image_block(os, e, false);
	if (res != CHECK_IMAGE_GOOD) {
		cb(res, os, e, data);
		return;
	}

	const char *img_name = mount_entry_get_img(e);
	char *img_path = mem_printf("%s/%s.img", guestos_get_dir(os), img_name);
	DEBUG("Checking image %s (thorough, non-blocking)", img_path);

	check_mount_image_t *task = check_mount_image_new(os, e, img_path, cb, data);
	crypto_hash_file(img_path, SHA1, check_mount_image_cb_sha1, task);

	mem_free0(img_path);
}

// ITERATE IMAGES

// internal task callback types
typedef struct iterate_images iterate_images_t;

typedef void (*iterate_images_callback_t)(iterate_images_t *task,
					  guestos_check_mount_image_result_t res, mount_entry_t *e);

typedef union {
	guestos_images_check_complete_cb_t check_complete;
	guestos_images_download_complete_cb_t download_complete;
} iterate_images_on_complete_cb_t;

struct iterate_images {
	// locals
	guestos_t *os;
	mount_t *mnt;
	size_t n, i;
	// iterator callback
	iterate_images_callback_t iter_cb;
	// callbacks to report back final result to caller
	iterate_images_on_complete_cb_t on_complete;
	void *complete_data;
	// download
	unsigned int dl_attempts;
	unsigned int dl_count;
	bool dl_started;
};

static iterate_images_t *
iterate_images_new(guestos_t *os, mount_t *mnt, size_t n, iterate_images_callback_t iter_cb,
		   iterate_images_on_complete_cb_t complete_cb, void *complete_data)
{
	iterate_images_t *task = mem_new(iterate_images_t, 1);
	task->os = os;
	task->mnt = mnt;
	task->n = n;
	task->i = 0;
	task->iter_cb = iter_cb;
	task->on_complete = complete_cb;
	task->complete_data = complete_data;
	task->dl_attempts = 0;
	task->dl_count = 0;
	task->dl_started = false;
	return task;
}

static void
iterate_images_free(iterate_images_t *task)
{
	IF_NULL_RETURN(task);
	mount_free(task->mnt);
	mem_free0(task);
}

static void
iterate_images_cb_check_image(guestos_check_mount_image_result_t res,
			      UNUSED guestos_t *os /*already in task*/, mount_entry_t *e,
			      void *data)
{
	iterate_images_t *task = data;
	ASSERT(task);
	ASSERT(task->os == os);

	task->iter_cb(task, res, e);
}

/**
 * Trigger image check for the next relevant (i.e. for SHARED or FLASH type) GuestOS image.
 *
 * @return true if next image was found and check for it was triggered, false otherwise.
 */
static bool
iterate_images_trigger_check(iterate_images_t *task)
{
	// look for next SHARED or FLASH type image
	while (task->i < task->n) {
		mount_entry_t *e = mount_get_entry(task->mnt, task->i);
		enum mount_type t = mount_entry_get_type(e);
		if (t == MOUNT_TYPE_SHARED || t == MOUNT_TYPE_FLASH || t == MOUNT_TYPE_OVERLAY_RO ||
		    t == MOUNT_TYPE_SHARED_RW) {
			DEBUG("Found next image %s.img for GuestOS %s v%" PRIu64
			      ", triggering check.",
			      mount_entry_get_img(e), guestos_get_name(task->os),
			      guestos_get_version(task->os));
			guestos_check_mount_image(task->os, e, iterate_images_cb_check_image, task);
			return true;
		}
		++task->i;
	}
	DEBUG("No more images to check for GuestOS %s v%" PRIu64 ", stopping iteration.",
	      guestos_get_name(task->os), guestos_get_version(task->os));
	return false;
}

/**
 * Iterate over all (SHARED and FLASH type) images that are provided by the GuestOS
 * and call the given iter_cb callback for each of them.
 * The final result of the operation is returned via the complete_cb, if given.
 *
 * @param   os the GuestOS
 * @param   iter_cb the callback called for each GuestOS image
 * @param   complete_cb the callback to report the final result
 * @param   complete_data data parameter passed to the final result callback
 * @return  true if iteration was started (iter_cb should be called at least once),
 *	    false otherwise (e.g. when there are no images to iterate over)
 */
static bool
iterate_images_start(guestos_t *os, iterate_images_callback_t iter_cb,
		     iterate_images_on_complete_cb_t on_complete, void *complete_data)
{
	ASSERT(os);

	DEBUG("Iterating through images of GuestOS %s v%" PRIu64 "...", guestos_get_name(os),
	      guestos_get_version(os));

	mount_t *mnt = mount_new(); // need to get "mounts" to get image URLs... feels wrong
	guestos_fill_mount(os, mnt);
	size_t n = mount_get_count(mnt);
	if (n == 0) {
		WARN("GuestOS %s v%" PRIu64 " has no mounts/images to iterate through.",
		     guestos_get_name(os), guestos_get_version(os));
		mount_free(mnt);
		return false;
	}

	iterate_images_t *task =
		iterate_images_new(os, mnt, n, iter_cb, on_complete, complete_data);
	if (iterate_images_trigger_check(task))
		return true;

	mount_free(mnt);
	iterate_images_free(task);
	return false;
}

// CHECK IMAGES

static void
iterate_images_cb_check(iterate_images_t *task, guestos_check_mount_image_result_t res,
			mount_entry_t *e)
{
	ASSERT(task);

	bool good = (res == CHECK_IMAGE_GOOD);
	if (good) {
		DEBUG("GuestOS %s v%" PRIu64 " image %s.img is GOOD, proceeding ...",
		      guestos_get_name(task->os), guestos_get_version(task->os),
		      mount_entry_get_img(e));
		task->i++;
		if (iterate_images_trigger_check(task))
			return;
		INFO("GuestOS %s v%" PRIu64 " is complete, all images are good.",
		     guestos_get_name(task->os), guestos_get_version(task->os));
	} else {
		DEBUG("GuestOS %s v%" PRIu64 " image %s.img is BAD, stopping ...",
		      guestos_get_name(task->os), guestos_get_version(task->os),
		      mount_entry_get_img(e));
	}

	// bad or last image: notify caller
	if (task->on_complete.check_complete)
		task->on_complete.check_complete(good, task->os, task->complete_data);

	// cleanup
	iterate_images_free(task);
}

void
guestos_images_check(guestos_t *os, guestos_images_check_complete_cb_t cb, void *data)
{
	ASSERT(os);
	ASSERT(cb);
	INFO("Checking images of GuestOS %s v%" PRIu64 " (thorough)", guestos_get_name(os),
	     guestos_get_version(os));
	// prepare image iteration
	if (!iterate_images_start(os, iterate_images_cb_check,
				  (iterate_images_on_complete_cb_t){ .check_complete = cb },
				  data)) {
		DEBUG("No images to check for GuestOS %s v%" PRIu64, guestos_get_name(os),
		      guestos_get_version(os));
		// notify caller and free
		if (cb)
			cb(true, os, data);
	}
}

// DOWNLOAD IMAGES
/* TODO do we need this (notify caller about result)?
typedef enum download_images_result {
	DOWNLOAD_IMAGES_STARTED,
	DOWNLOAD_IMAGES_ERROR,
	DOWNLOAD_IMAGES_INPROGRESS
} download_images_result_t;
*/
static void
iterate_images_cb_download_complete(download_t *dl, bool success, void *data);

static bool
iterate_images_trigger_download(iterate_images_t *task)
{
	ASSERT(task);

	mount_entry_t *e = mount_get_entry(task->mnt, task->i);
	const char *img_name = mount_entry_get_img(e);

	TRACE("dl_attempt = %u for %s.img", task->dl_attempts, img_name);
	if (task->dl_attempts >= GUESTOS_MAX_DOWNLOAD_ATTEMPTS) {
		WARN("Maximum download attempts (%d) exceeded for %s.img. Aborting image downloads.",
		     GUESTOS_MAX_DOWNLOAD_ATTEMPTS, img_name);
		return false;
	}
	task->dl_attempts++; // increase dl_attempt counter

	// check if guestos has update file server, use device.conf as fallback
	const char *update_base_url = guestos_config_get_update_base_url(task->os->cfg) ?
					      guestos_config_get_update_base_url(task->os->cfg) :
					      cmld_get_device_update_base_url();
	char *img_path = mem_printf("%s/%s.img", guestos_get_dir(task->os), img_name);
	char *img_url = mem_printf("%s/operatingsystems/%s/%s-%" PRIu64 "/%s.img", update_base_url,
				   hardware_get_name(), guestos_get_name(task->os),
				   guestos_get_version(task->os), img_name);
	// invoke downloader
	DEBUG("Downloading %s to %s (attempt=%u).", img_url, img_path, task->dl_attempts);
	download_t *dl = download_new(img_url, img_path, iterate_images_cb_download_complete, task);
	mem_free0(img_url);
	mem_free0(img_path);
	if (download_start(dl) < 0) {
		ERROR("Failed to start download for %s", download_get_url(dl));
		download_free(dl);
		return false;
	}
	return true;
}

static void
iterate_images_cb_download_complete(download_t *dl, bool success, void *data)
{
	iterate_images_t *task = data;
	ASSERT(task);

	if (success) {
		INFO("Download of %s succeeded!", download_get_url(dl));
		bool res = iterate_images_trigger_check(task);
		ASSERT(res);
	} else {
		WARN("Download of %s failed!", download_get_url(dl));
		if (!iterate_images_trigger_download(task)) {
			// notify caller
			if (task->on_complete.download_complete)
				task->on_complete.download_complete(false, task->dl_count, task->os,
								    task->complete_data);
			task->os->downloading = false;
			// cleanup
			iterate_images_free(task);
		}
	}
	download_free(dl);
}

static void
iterate_images_cb_download_check(iterate_images_t *task, guestos_check_mount_image_result_t res,
				 mount_entry_t *e)
{
	ASSERT(task);

	bool good = (res == CHECK_IMAGE_GOOD);
	if (good) {
		DEBUG("GuestOS %s v%" PRIu64 " image %s.img is GOOD, proceeding ...",
		      guestos_get_name(task->os), guestos_get_version(task->os),
		      mount_entry_get_img(e));
		task->dl_attempts = 0; // reset dl_attempt counter
		if (task->dl_started) {
			task->dl_count++;
			task->dl_started = false;
		}
		task->i++;
		if (iterate_images_trigger_check(task))
			return;
		INFO("GuestOS %s v%" PRIu64 " is now complete, all images have been downloaded.",
		     guestos_get_name(task->os), guestos_get_version(task->os));
	} else {
		// bad image: trigger actual download
		DEBUG("GuestOS %s v%" PRIu64 " image %s.img is BAD, triggering download ...",
		      guestos_get_name(task->os), guestos_get_version(task->os),
		      mount_entry_get_img(e));
		task->dl_started = true;
		if (iterate_images_trigger_download(task))
			return;
	}

	// notify caller
	if (task->on_complete.download_complete)
		task->on_complete.download_complete(good, task->dl_count, task->os,
						    task->complete_data);
	task->os->downloading = false;
	// cleanup
	iterate_images_free(task);
}

bool
guestos_images_download(guestos_t *os, guestos_images_download_complete_cb_t cb, void *data)
{
	ASSERT(os);
	//ASSERT(cb);
	const char *update_base_url = guestos_config_get_update_base_url(os->cfg) ?
					      guestos_config_get_update_base_url(os->cfg) :
					      cmld_get_device_update_base_url();
	if (!update_base_url) {
		audit_log_event(NULL, FSA, CMLD, GUESTOS_MGMT, "download-os-no-base-url",
				guestos_get_name(os), 0);
		WARN("Cannot download images for GuestOS %s since no device update base URL"
		     " was configured!",
		     guestos_get_name(os));
		return os->downloading;
	}

	// prevent bad things from happening when calling this function while already downloading
	if (os->downloading) {
		audit_log_event(NULL, FSA, CMLD, GUESTOS_MGMT, "download-os-already-in-progress",
				guestos_get_name(os), 0);
		DEBUG("Download for GuestOS %s v%" PRIu64 " already in progress, returning...",
		      guestos_get_name(os), guestos_get_version(os));
		return os->downloading;
	}
	// prepare image iteration
	os->downloading = true;
	if (!iterate_images_start(os, iterate_images_cb_download_check,
				  (iterate_images_on_complete_cb_t){ .download_complete = cb },
				  data)) {
		audit_log_event(NULL, SSA, CMLD, GUESTOS_MGMT, "download-os-nothing-to-download",
				guestos_get_name(os), 0);
		DEBUG("No images to download for GuestOS %s v%" PRIu64, guestos_get_name(os),
		      guestos_get_version(os));
		// notify caller
		if (cb)
			cb(true, 0, os, data);
		os->downloading = false;
		return os->downloading;
	}
	return os->downloading;
}

// FLASH IMAGES

typedef enum {
	VERIFY_PARTITION_MATCH,
	VERIFY_PARTITION_ERROR,
	VERIFY_PARTITION_MISMATCH,
} verify_partition_result_t;

/**
 * Verifies if the contents of the partition and image match.
 *
 * @param img_path path to the image file
 * @param part_path full path to the partition
 * @return whether the contents MATCH or MISMATCH, or ERROR if something goes wrong
 */
static verify_partition_result_t
verify_partition(const char *img_path, const char *part_path)
{
	ASSERT(img_path);
	ASSERT(part_path);

	verify_partition_result_t res = VERIFY_PARTITION_ERROR;
	int img = open(img_path, O_RDONLY);
	int part = open(part_path, O_RDONLY);
	if (img == -1) {
		WARN_ERRNO("Verifying partition %s: Cannot open image %s for reading.", part_path,
			   img_path);
		goto cleanup_files;
	}
	if (part == -1) {
		WARN_ERRNO("Verifying partition %s: Cannot open partition for reading.", part_path);
		goto cleanup_files;
	}

	char *img_buf = mem_alloc(GUESTOS_VERIFY_BLOCKSIZE);
	char *part_buf = mem_alloc(GUESTOS_VERIFY_BLOCKSIZE);
	ssize_t img_bytes, part_bytes;
	do {
		img_bytes = read(img, img_buf, GUESTOS_VERIFY_BLOCKSIZE);
		if (img_bytes < 0) {
			ERROR_ERRNO("Verifying partition %s: Cannot read from image %s.", part_path,
				    img_path);
			goto cleanup;
		}
		if (img_bytes == 0) {
			DEBUG("Verifying partition %s: Success. Content matches with image %s.",
			      part_path, img_path);
			res = VERIFY_PARTITION_MATCH;
			goto cleanup;
		}
		ASSERT(img_bytes <= GUESTOS_VERIFY_BLOCKSIZE);
		part_bytes = read(part, part_buf, img_bytes);
		if (part_bytes < 0) {
			ERROR_ERRNO("Verifying partition %s: Cannot read from partition.",
				    part_path);
			goto cleanup;
		}
	} while (img_bytes == part_bytes && !memcmp(img_buf, part_buf, img_bytes));

	DEBUG("Verifying partition %s: Failed. Content differs from image %s.", part_path,
	      img_path);
	res = VERIFY_PARTITION_MISMATCH;

cleanup:
	mem_free0(part_buf);
	mem_free0(img_buf);
cleanup_files:
	if (img != -1)
		close(img);
	if (part != -1)
		close(part);
	return res;
}

/**
 * Flashes a (FLASH type) mount entry if necessary and verifies the flashed data.
 *
 * @param os the GuestOS to which the mount entry belongs to
 * @param e the mount entry to flash (type must be FLASH)
 * @return -1 on error, 0 if there was nothing to flash, 1 if the image was successfully flashed
 */
static int
verify_flash_mount_entry(guestos_t *os, mount_entry_t *e)
{
	ASSERT(os);
	ASSERT(e);

	const char *img_name = mount_entry_get_img(e);
	const char *flash_partition = mount_entry_get_dir(e);
	ASSERT(img_name);
	ASSERT(flash_partition);

	if (mount_entry_get_type(e) != MOUNT_TYPE_FLASH) {
		WARN("Image %s of GuestOS %s is not a FLASH image. Skipping.", img_name,
		     guestos_get_name(os));
		return 0;
	}
	if (flash_partition[0] != '/') {
		ERROR("Invalid target partition %s for flashing %s for GuestOS %s", flash_partition,
		      img_name, guestos_get_name(os));
		return -1;
	}

	int res = -1;
	char *img_path = mem_printf("%s/%s.img", guestos_get_dir(os), img_name);
	char *flash_path =
		hardware_get_block_by_name_path() ?
			mem_printf("%s%s", hardware_get_block_by_name_path(), flash_partition) :
			mem_strdup(flash_partition);
	DEBUG("Flashing image %s to partition %s", img_path, flash_path);

	switch (verify_partition(img_path, flash_path)) {
	case VERIFY_PARTITION_MATCH:
		DEBUG("Skipping flashing of partition %s: Already up to date with image %s.",
		      flash_path, img_path);
		res = 0;
		break;
	case VERIFY_PARTITION_MISMATCH:
		DEBUG("Flashing partition %s with image %s.", flash_path, img_path);
		file_copy(img_path, flash_path, mount_entry_get_size(e), GUESTOS_FLASH_BLOCKSIZE,
			  0);

		switch (verify_partition(img_path, flash_path)) {
		case VERIFY_PARTITION_MATCH:
			DEBUG("Successfully flashed image %s to %s", img_path, flash_path);
			res = 1;
			break;
		default:
			ERROR("Failed to flash image %s to partition %s", img_path, flash_path);
			break;
		}
		break;
	default:
		ERROR("Failed to verify partition %s against image %s", flash_path, img_path);
		break;
	}

	mem_free0(flash_path);
	mem_free0(img_path);
	return res;
}

/**
 * Flash images without checking them first.
 *
 * @param os the GuestOS whose images to flash
 * @return -1 on error, number of flashed images otherwise
 */
static int
images_flash_no_check(guestos_t *os)
{
	INFO("Flashing images for GuestOS %s ...", guestos_get_name(os));
	mount_t *mnt = mount_new(); // need to get "mounts" to get image URLs... feels wrong
	guestos_fill_mount(os, mnt);

	int flashed = 0;
	size_t n = mount_get_count(mnt);
	for (size_t i = 0; i < n; i++) {
		mount_entry_t *e = mount_get_entry(mnt, i);
		if (mount_entry_get_type(e) != MOUNT_TYPE_FLASH)
			continue;

		int res = verify_flash_mount_entry(os, e);
		if (res < 0) {
			ERROR("Could not verify/flash partition %s with image %s, "
			      "aborting flash for GuestOS %s.",
			      mount_entry_get_dir(e), mount_entry_get_img(e), guestos_get_name(os));
			flashed = -1;
			goto cleanup;
		}
		flashed += res;
	}
	if (flashed > 0) {
		DEBUG("Images for GuestOS %s have been flashed.", guestos_get_name(os));
		// TODO notify caller about flash result?
	} else {
		DEBUG("Nothing to flash for GuestOS %s.", guestos_get_name(os));
	}

cleanup:
	mount_free(mnt);
	return flashed;
}

int
guestos_images_flash(guestos_t *os)
{
	ASSERT(os);
	INFO("Flashing images of GuestOS %s %" PRIu64, guestos_get_name(os),
	     guestos_get_version(os));

	if (!guestos_images_are_complete(os, true)) {
		ERROR("Cannot flash images for GuestOS %s: some images are corrupted!",
		      guestos_get_name(os));
		return -1;
	}

	return images_flash_no_check(os);
}

void
guestos_purge(guestos_t *os)
{
	ASSERT(os);
	DEBUG("Purging GuestOS %s v%" PRIu64, guestos_get_name(os), guestos_get_version(os));
	const char *dir = guestos_get_dir(os);
	// remove images
	mount_t *mnt = mount_new(); // need to get "mounts" to get image URLs... feels wrong (again)
	guestos_fill_mount(os, mnt);
	size_t n = mount_get_count(mnt);
	for (size_t i = 0; i < n; i++) {
		mount_entry_t *e = mount_get_entry(mnt, i);
		if (!e) {
			ERROR("Could not get mount entry %zu for %s", i, guestos_get_name(os));
			break;
		}
		const char *img_name = mount_entry_get_img(e);
		char *img_path = mem_printf("%s/%s.img", dir, img_name);

		if (file_exists(img_path) && unlink(img_path) < 0) {
			WARN_ERRNO("Failed to remove symlink %s", img_path);
		}
		mem_free0(img_path);
	}
	// remove config and signature file
	const char *file = guestos_get_cfg_file(os);
	if (unlink(file) < 0) {
		WARN_ERRNO("Failed to erase file %s", file);
	}
	file = guestos_get_sig_file(os);
	if (unlink(file) < 0) {
		WARN_ERRNO("Failed to erase file %s", file);
	}
	file = guestos_get_cert_file(os);
	if (unlink(file) < 0) {
		WARN_ERRNO("Failed to erase file %s", file);
	}

	// remove ca symlink
	char *symlink = guestos_get_ca_file_new(os->dir);
	if (unlink(symlink) < 0) {
		WARN_ERRNO("Failed to erase file %s", symlink);
	}
	mem_free0(symlink);

	// remove dir
	if (rmdir(dir) < 0) {
		WARN_ERRNO("Failed to remove directory %s", dir);
	}

	mount_free(mnt);
}

const char *
guestos_get_cfg_file(const guestos_t *os)
{
	ASSERT(os);
	return os->cfg_file;
}

const char *
guestos_get_sig_file(const guestos_t *os)
{
	ASSERT(os);
	return os->sig_file;
}

const char *
guestos_get_cert_file(const guestos_t *os)
{
	ASSERT(os);
	return os->cert_file;
}

const char *
guestos_get_dir(const guestos_t *os)
{
	ASSERT(os);
	return os->dir;
}

void *
guestos_get_raw_ptr(const guestos_t *os)
{
	ASSERT(os);
	return os->cfg;
}

/******************************************************************************/

void
guestos_fill_mount(const guestos_t *os, mount_t *mount)
{
	ASSERT(os);
	guestos_config_fill_mount(os->cfg, mount);
}

void
guestos_fill_mount_setup(const guestos_t *os, mount_t *mount)
{
	ASSERT(os);
	guestos_config_fill_mount_setup(os->cfg, mount);
}

const char *
guestos_get_name(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_name(os->cfg);
}

const char *
guestos_get_hardware(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_hardware(os->cfg);
}

uint64_t
guestos_get_version(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_version(os->cfg);
}

const char *
guestos_get_init(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_init(os->cfg);
}

char **
guestos_get_init_argv_new(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_init_argv_new(os->cfg);
}

char **
guestos_get_init_env(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_init_env(os->cfg);
}

size_t
guestos_get_init_env_len(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_init_env_len(os->cfg);
}

uint32_t
guestos_get_min_ram_limit(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_min_ram_limit(os->cfg);
}

uint32_t
guestos_get_def_ram_limit(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_def_ram_limit(os->cfg);
}

bool
guestos_get_feature_bg_booting(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_feature_bg_booting(os->cfg);
}

bool
guestos_get_feature_install_guest(const guestos_t *os)
{
	ASSERT(os);
	return guestos_config_get_feature_install_guest(os->cfg);
}

void
guestos_set_verify_result(guestos_t *os, guestos_verify_result_t verify_result)
{
	ASSERT(os);
	os->verify_result = verify_result;
}

guestos_verify_result_t
guestos_get_verify_result(const guestos_t *os)
{
	ASSERT(os);
	return os->verify_result;
}
