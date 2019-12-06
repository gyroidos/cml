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
  * @file loopdev.h
  *
  * Contains functions to create and manage loop devices, such as
  * getting a free loop device, waiting for it to appear in the file system,
  * or to set it up for an image file. It is e.g. used while mounting images.
  */

#ifndef LOOPDEV_H
#define LOOPDEV_H

/**
 * Get a free loop device.
 * @return The path of the loop device or NULL in case of an error.
 */

char *
loopdev_new(void);

/**
 * Free the device path of a loop device.
 * @param dev The device string, e.g. /dev/loop0 as returned by loopdev_new().
 */

void
loopdev_free(char *dev);

/**
 * Wait until the loop device appears in the dev file system.
 * @param dev The path for the loop device, e.g. /dev/loop0.
 * Call loopdev_new() to get one.
 * @param timeout The timeout in milliseconds.
 * @return 0 if the loop device appeared, else -1.
 */

int
loopdev_wait(const char *dev, unsigned timeout);

/**
 * Setup a loop device for an image file.
 * @param img The path to an image file.
 * @param dev The path for the loop device, e.g. /dev/loop0.
 * Call loopdev_new() to get one.
 * @return A file descriptor for the loop device or -1 in case of an
 * error. The caller must close the file descriptor after calling mount.
 */

int
loopdev_setup_device(const char *img, const char *dev);

#endif /* LOOPDEV_H */
