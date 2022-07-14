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

#ifndef GUESTOS_H
#define GUESTOS_H

/**
 * @file guestos.h
 *
 * The Guest OS module holds a list of available guest operating systems. A
 * guest operating system could be an AOSP, Firefox OS or Ubuntu for
 * Smartphones. Each guest operating system is represented by a config file
 * which is syncronized from the MDM. One guest operating system may be used
 * by zero, one or more containers. So, when the user creates a new container he
 * can choose from the list of available guest operating systems represented by
 * this module. Besides the config file, a guest operating system typically
 * requires one or more disk images, which are shared between multiple
 * containers and mounted read only, e.g. for /system. These images can be
 * downloaded from the MDM on request.
 */

#include "mount.h"

#include <stdbool.h>

/**
 * A structure to present an guest operating system
 */
typedef struct guestos guestos_t;

/******************************************************************************/

/**
 * Returns a new string with the full path of the GuestOS config file.
 * Must be free'd.
 * @param dir the GuestOS directory
 */
char *
guestos_get_cfg_file_new(const char *dir);

/**
 * Returns a new string with the full path of the GuestOS signature file.
 * Must be free'd.
 * @param dir the GuestOS directory
 */
char *
guestos_get_sig_file_new(const char *dir);

/**
 * Returns a new string with the full path of the GuestOS certificate file.
 * Must be free'd.
 * @param dir the GuestOS directory
 */
char *
guestos_get_cert_file_new(const char *dir);

/**
 * Returns a new string with the full path of the GuestOS CA symlink file.
 * Must be free'd.
 * @param dir the GuestOS directory
 * @return new string with the full path of the GuestOS CA symlink file
 */
char *
guestos_get_ca_file_new(const char *dir);

/******************************************************************************/

/**
 * Loads the indicated GuestOS config file with the specified basepath
 * under which it expects its associated files (e.g. images).
 * @param file the GuestOS config file to load
 * @param basepath the base path for GuestOSes
 * @return the loaded GuestOS instance or NULL on failure
 */
guestos_t *
guestos_new_from_file(const char *file, const char *basepath);

/**
 * Loads the GuestOS config from the given buffer with the specified basepath
 * under which it expects its associated files (e.g. images).
 * @param buf the buffer containing the GuestOS config
 * @param buflen the length of the config in the buffer
 * @param basepath the base path for GuestOSes
 * @return the loaded GuestOS instance or NULL on failure
 */
guestos_t *
guestos_new_from_buffer(unsigned char *buf, size_t buflen, const char *basepath);

/**
 * Frees the given GuestOS instance.
 * @param os the GuestOS to free
 * */
void
guestos_free(guestos_t *os);

/******************************************************************************/

/**
 * Result of checking a mount image.
 */
typedef enum guestos_check_mount_image_result {
	CHECK_IMAGE_GOOD,
	CHECK_IMAGE_ERROR,
	CHECK_IMAGE_ACCESS_FAILED,
	CHECK_IMAGE_SIZE_MISMATCH,
	CHECK_IMAGE_HASH_MISMATCH
} guestos_check_mount_image_result_t;

/**
 * Perform a quick or thorough check of a mount image and return the result (blocking).
 * The file exists and has correct size, and for a thorough check its hashes must be correct as well.
 *
 * @param os the guestos to which the mount entry belongs to
 * @param e the mount entry for the image to be checked
 * @param thorough indicates if a thorough (true) or quick (false) check should be performed
 * @return the state of the image
 */
guestos_check_mount_image_result_t
guestos_check_mount_image_block(const guestos_t *os, const mount_entry_t *e, bool thorough);

/**
 * Check the required image files for the given GuestOS and return the result (blocking).
 * The image files exists and have correct size, and for a thorough check their hashes
 * must be correct as well.
 *
 * @param os the GuestOS instance whose images to verify
 * @param thorough indicates if a thorough (true) or quick (false) check should be performed
 * @return true if all images are good, false otherwise
 */
bool
guestos_images_are_complete(const guestos_t *os, bool thorough);

/**
 * Callback type for guestos_images_check() to report whether all images of a GuestOS are complete.
 */
typedef void (*guestos_images_check_complete_cb_t)(bool complete, guestos_t *os, void *data);

/**
 * Thoroughly check the required image files for the given GuestOS (includes hash comparison)
 * and deliver the result via the given callback.
 *
 * @param os the GuestOS instance whose images to verify
 * @param cb callback to deliver the result back to the caller (canNOT be NULL)
 * @param data data parameter passed to the callback
 */
void
guestos_images_check(guestos_t *os, guestos_images_check_complete_cb_t cb, void *data);

/**
 * Callback type for guestos_images_download() to report whether all images of a GuestOS
 * have been downloaded completely.
 */
typedef void (*guestos_images_download_complete_cb_t)(bool complete, unsigned int count,
						      guestos_t *os, void *data);

/**
 * Check the required image files for the given GuestOS and download the missing/broken images.
 *
 * @param os the GuestOS instance whose images to verify and download
 * @param cb callback to deliver the result back to the caller (can be NULL if result is irrelevant)
 * @param data data parameter passed to the callback
 * @return true if image download is ongoing
 *
 */
bool
guestos_images_download(guestos_t *os, guestos_images_download_complete_cb_t cb, void *data);

/**
 * Flash the images for the given GuestOS
 *
 * @param os the GuestOS with images to be flashed
 * @return number of images that have been flashed, or -1 on error
 */
int
guestos_images_flash(guestos_t *os);

/******************************************************************************/

/**
 * Removes the files associated with the given GuestOS.
 * @param os the GuestOS instance whose files to delete
 */
void
guestos_purge(guestos_t *os);

/**
 * Returns a string with the full path of the GuestOS config file.
 * @param os the GuestOS instance
 */
const char *
guestos_get_cfg_file(const guestos_t *os);

/**
 * Returns a string with the full path of the GuestOS signature file.
 * @param os the GuestOS instance
 */
const char *
guestos_get_sig_file(const guestos_t *os);

/**
 * Returns a string with the full path of the GuestOS certificate file.
 * @param os the GuestOS instance
 */
const char *
guestos_get_cert_file(const guestos_t *os);

/**
 * Returns the GuestOS directory where its files are expected.
 * @param os the GuestOS instance
 */
const char *
guestos_get_dir(const guestos_t *os);

/**
 * Returns a pointer to the underlying GuestOS config.
 * @param os the GuestOS instance
 */
void *
guestos_get_raw_ptr(const guestos_t *os);

/******************************************************************************/
// Getters and setters (forwarded to guestos_config_t)

void
guestos_fill_mount(const guestos_t *os, mount_t *mnt);

void
guestos_fill_mount_setup(const guestos_t *os, mount_t *mnt);

const char *
guestos_get_name(const guestos_t *os);

const char *
guestos_get_hardware(const guestos_t *os);

uint64_t
guestos_get_version(const guestos_t *os);

const char *
guestos_get_init(const guestos_t *os);

char **
guestos_get_init_argv_new(const guestos_t *os);

char **
guestos_get_init_env(const guestos_t *os);

size_t
guestos_get_init_env_len(const guestos_t *os);

uint32_t
guestos_get_min_ram_limit(const guestos_t *os);

uint32_t
guestos_get_def_ram_limit(const guestos_t *os);

bool
guestos_get_feature_bg_booting(const guestos_t *os);

bool
guestos_get_feature_install_guest(const guestos_t *os);

/**
 * Result of guestos config verification process.
 */
typedef enum guestos_verify_result {
	GUESTOS_SIGNED,
	GUESTOS_LOCALLY_SIGNED,
	GUESTOS_UNSIGNED,
} guestos_verify_result_t;

void
guestos_set_verify_result(guestos_t *os, guestos_verify_result_t verify_result);

guestos_verify_result_t
guestos_get_verify_result(const guestos_t *os);

#endif /* GUESTOS_H */
