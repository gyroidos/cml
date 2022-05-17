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
 * Setup a loop device for an image file.
 * @param loop_fd The file descriptor for the newly created loop device
 * @param img The path to an image file.
 * @param readonly 1 for readonly, 0 for read-write
 * @param blocksize The blocksize of the device
 *
 * @return The path to the newly created loop device on success,
 * otherwise NULL
 */
char *
loopdev_create_new(int *loop_fd, const char *img, int readonly, size_t blocksize);

/**
 * Free the device path of a loop device.
 * @param dev The device string, e.g. /dev/loop0 as returned by loopdev_create_new().
 */
void
loopdev_free(char *dev);

#endif /* LOOPDEV_H */
