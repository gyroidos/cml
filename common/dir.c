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

#include "dir.h"

#include "macro.h"
#include "logf.h"
#include "mem.h"

#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

int
dir_foreach(const char *path, int (*func)(const char *path, const char *file, void *data),
	    void *data)
{
	struct dirent *dp;
	DIR *dirp;
	int n = 0;

	IF_NULL_RETVAL(path, -1);
	IF_NULL_RETVAL(func, -1);

	dirp = opendir(path);
	if (!dirp) {
		WARN_ERRNO("Could not open dir %s", path);
		return -1;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0)
			continue;
		if (strcmp(dp->d_name, "..") == 0)
			continue;

		TRACE("Found directory %s/%s", path, dp->d_name);

		int ret = func(path, dp->d_name, data);
		if (ret < 0) {
			DEBUG("Callback of dir_foreach returned %d", ret);
			n = -1;
			break;
		} else if (ret > 0) {
			n++;
		}
	}

	closedir(dirp);

	return n;
}

int
dir_mkdir_p(const char *path, mode_t mode)
{
	ASSERT(path);
	char *c, *p = mem_printf("%s", path);
	c = p;
	int ret = 0;

	//DEBUG("Doing mkdir -p on path %s", p);
	mode_t old_mask = umask(0);

	if (c[0] == '/') {
		c++;
	}

	c = strchr(c, '/');
	while (c) {
		*c = '\0';
		//DEBUG("Doing mkdir on path %s", p);
		if (mkdir(p, mode) < 0 && errno != EEXIST) {
			ERROR_ERRNO("Could not mkdir %s", p);
			ret = -1;
			goto out;
		}
		*c = '/';
		c = strchr(c + 1, '/');
	}
	if (mkdir(p, mode) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Could not mkdir %s", p);
		ret = -1;
	}
out:
	umask(old_mask);
	mem_free(p);
	return ret;
}

static int
dir_unlink_folder_contents_cb(const char *path, const char *name, UNUSED void *data)
{
	struct stat stat_buffer;
	int ret = 0;
	char *file_to_remove = mem_printf("%s/%s", path, name);
	if (stat(file_to_remove, &stat_buffer) == 0 && !S_ISDIR(stat_buffer.st_mode)) {
		DEBUG("Unlinking file %s", file_to_remove);
		if (unlink(file_to_remove) == -1) {
			ERROR_ERRNO("Could not delete file %s", file_to_remove);
			ret--;
		}
	} else {
		DEBUG("Path %s is dir", file_to_remove);
		if (dir_foreach(file_to_remove, &dir_unlink_folder_contents_cb, NULL) < 0) {
			ERROR_ERRNO("Could not delete all dir contents in %s", file_to_remove);
			ret--;
		}
		DEBUG("Removing now empty dir %s", file_to_remove);
		if (rmdir(file_to_remove) < 0) {
			ERROR_ERRNO("Could not delete dir %s", file_to_remove);
			ret--;
		}
	}
	mem_free(file_to_remove);
	return ret;
}

int
dir_delete_folder(const char *path, const char *dir_name)
{
	int ret = 0;
	char *dir_to_remove = mem_printf("%s/%s", path, dir_name);

	DEBUG("Deleting %s", dir_to_remove);
	if (dir_foreach(dir_to_remove, &dir_unlink_folder_contents_cb, NULL) < 0) {
		ERROR_ERRNO("Could not delete all dir contents in %s", dir_to_remove);
		ret--;
	}
	DEBUG("Removing now empty dir %s", dir_to_remove);
	if (rmdir(dir_to_remove) < 0) {
		ERROR_ERRNO("Could not delete dir %s", dir_to_remove);
		ret--;
	}
	mem_free(dir_to_remove);

	return ret;
}
