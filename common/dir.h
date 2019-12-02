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
 * @file dir.h
 * This module covers functions for operations on directories. For example,
 * it is possible to iterate over a folder and to trigger a callback function
 * for each contained element.
 */

#ifndef DIR_H
#define DIR_H

#include <sys/stat.h>
#include <sys/types.h>

/**
 * Read a directory and call a callback for each entry.
 * If the callback returns a value < 0 no further callbacks will be called.
 * @param path The path of the directory.
 * @param func The callback to be called for each directory entry. Return <0 to stop calling callbacks
 * and >0 to increment the return value of dir_foreach by one.
 * @param data A data object given to each callback function.
 * @returns -1 on error and the number of callbacks which returned a value > 0 on success.
 */
int dir_foreach(const char *path, int (*func)(const char *path, const char *file, void *data), void *data);

int dir_mkdir_p(const char *path, mode_t mode);

int dir_delete_folder(const char *path, const char *dir_name);

#endif /* DIR_H */
