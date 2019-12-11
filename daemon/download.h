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

#ifndef DOWNLOAD_H
#define DOWNLOAD_H

/**
 * @file downloader.h Defines an API to download files.
 * Uses 'wget' for now to do the actual work.
 */

#include <stdbool.h>

/**
 * A structure representing a download.
 */
typedef struct download download_t;

/**
 * Callback type for functions called after a download has been completed/aborted.
 */
typedef void (*download_callback_t)(download_t *dl, bool success, void *data);

/**
 * Instantiates a new download that will, once started, download from the given URL
 * to the given file and call the given callback on completion passing the data parameter.
 * @param url the URL to download form
 * @param file the file to download to
 * @param on_complete the callback to call after the download is finished/aborted
 * @param data custom parameter passed to the on_complete callback
 * @return the download_t instance or NULL on error
 */
download_t *
download_new(const char *url, const char *file, download_callback_t on_complete, void *data);

/**
 * Frees the given download instance.
 * @param dl the download instance to free
 */
void
download_free(download_t *dl);

/**
 * Starts the download for the given download instance.
 * @param dl the download instance to start
 * @return 0 if the download has been started sucessfully, -1 otherwise
 */
int
download_start(download_t *dl);

/**
 * Returns the URL of the given download instance.
 */
const char *
download_get_url(const download_t *dl);

/**
 * Returns the file of the given download instance.
 */
const char *
download_get_file(const download_t *dl);

#endif // DOWNLOAD_H
