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

#ifndef GUESTOS_MGR_H
#define GUESTOS_MGR_H

/**
 * @file guestos_mgr.h
 *
 * The Guest OS Manager module manages the list of available guest operating systems.
 */

#include "guestos.h"

#include <stdbool.h>

/**
 * A structure to present a guest operating system
 */
typedef struct guestos guestos_mgr_t;

/**
 * Initialize the operating system list by loading all information from storage.
 * @param path The directory where operating systems are stored.
 */
int
guestos_mgr_init(const char *path);

/**
 * Add an operating system WITHOUT checking its signature.
 * @param file The name of the guest OS config file.
 * @return 0 if the guest OS was successfully added, -1 on error.
 */
int
guestos_mgr_add_from_file(const char *file);

/**
 * Delete an operating system persistently from disk, i.e. remove its configuration and
 * its images. this does not free the operating system object, this must be done
 * separately by the module that called operatingsystem_new in the first place.
 * @param os The operating system to be deleted.
 */
void
guestos_mgr_delete(guestos_t *os);

/******************************************************************************/


/**
 * Installs the given new or updated GuestOS config.
 * @param cfg	    buffer with the new/updated GuestOS config to install
 * @param cfglen    length of the given GuestOS config in the buffer
 * @param sig	    buffer with the signature on the given GuestOS config
 * @param siglen    length of the given GuestOS config signature in the buffer
 * @param cert	    buffer with the software signing certificate
 * @param certlen   length of the given software signing cert in the buffer
 * @return -1 on error, 0 if installation was started (does NOT imply successful completion!)
 */
int
guestos_mgr_push_config(unsigned char *cfg, size_t cfglen, unsigned char *sig, size_t siglen,
		unsigned char *cert, size_t certlen);

/**
 * Downloads (if necessary) the images for the latest versions of the installed GuestOSes
 * that are in use by any of the installed containers.
 */
void
guestos_mgr_update_images(void);

/**
 * Writes the provided cacert to the location expected by scd
 * to verify signatures. Once the certificate is registered no new
 * certificate register attempt will be allowed.
 */
int
guestos_mgr_register_localca(unsigned char *cacert, size_t cacertlen);


/******************************************************************************/

/**
 * Returns the latest (by version) GuestOS with the given name.
 * If 'complete' is set, only complete GuestOS instances are considered,
 * i.e. all shared images belonging to the GuestOS must be available on the device.
 * Otherwise, all registered GuestOSes with the given name are considered.
 * @param name	    the name of the GuestOS
 * @param complete  whether to only consider complete GuestOSes with all images available on the device
 * @return  a pointer to the found GuestOS instance or NULL if no matching GuestOS was found
 *	    (Note: The returned pointer should NOT be free'd by the caller.)
 */
guestos_t *
guestos_mgr_get_latest_by_name(const char *name, bool complete);

/**
 * Returns the number of installed/loaded GuestOSes.
 */
size_t
guestos_mgr_get_guestos_count(void);

/**
 * Gets the i-th GuestOS in the list of installed GuestOSes.
 * @param i the index of the GuestOS to get
 * @return the i-th GuestOS
 */
guestos_t *
guestos_mgr_get_guestos_by_index(size_t i);

/******************************************************************************/

#endif /* GUESTOS_MGR_H */

