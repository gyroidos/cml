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

#include "util.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <libtar.h>
#include <sys/wait.h>
#include <stdint.h>

#include <openssl/sha.h>

#define OPENSSLBIN_PATH "openssl"
#define MKSQUASHFS_PATH "mksquashfs"
#define MKSQUASHFS_COMP "gzip"
#define MKSQUASHFS_BSIZE "131072"

#define SIGN_HASH_BUFFER_SIZE 4096

#define PKIGENSCRIPT_PATH UTIL_PKI_PATH "ssig_pki_generator.sh"
#define PKIGENCONF_PATH UTIL_PKI_PATH "ssig_pki_generator.conf"

extern tartype_t gztype;

int
util_fork_and_execvp(const char *path, const char * const *argv)
{
	ASSERT(path);
	//ASSERT(argv);	    // on some OSes, argv can be NULL...

	pid_t pid = fork();
	if (pid == -1) {    // error
		ERROR_ERRNO("Could not fork '%s'", path);
	} else if (pid == 0) {	    // child
		// cast away const from char (!) for compatibility with legacy (not so clever) execv API
		// see discussion at http://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html#tag_16_111_08
		execvp(path, (char * const *)argv);
		ERROR_ERRNO("Could not execv '%s'", path);
		exit(-1);
	} else {
		// parent
		int status;
		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%s'", path);
		} else if (!WIFEXITED(status)) {
			ERROR("Child '%s' terminated abnormally", path);
		} else {
			// child terminated normally return exit status
			return WEXITSTATUS(status);
		}
	}
	return -1;
}

//static int
//str_hash(void *key)
//{
//    return hashmapHash(key, strlen(key));
//}
//
//static bool
//str_equals(void *key_a, void *key_b)
//{
//    return (strcmp(key_a, key_b) == 0);
//}
//
//static void
//update_pseudofile_map(Hashmap *pseudo_file_map, const char *file_name, const char *owner_info)
//{
//    char name[PROP_NAME_MAX];
//    char value[PROP_VALUE_MAX];
//
//    char *old_owner_info = hashmapGet(pseudo_file_map, file_name);
//    if (!old_owner_info) {
//    	char *key = mem_strdup(file_name);
//    	char value = mem_strdup(owner_info);
//    	hashmapPut(pseudo_file_map, key, value);
//    } else {
//	mem_free(old_owner_info);
//	*old_owner_info = owner_info;
//    }
//}

int
util_tar_extract(const char *tar_filename, const char* index_file, const char* out_dir)
{
	TAR *tar = NULL;

	int ret = tar_open(&tar, tar_filename, &gztype, O_RDONLY, 0, TAR_GNU);
	if (ret != 0) {
		ERROR_ERRNO("Fail to open tarfile: %s\n", tar_filename);
		return ret;
	}
	//ret = tar_extract_all(tar, tar_prefix);
	while (th_read(tar) == 0) {
		char *archive_filename = th_get_pathname(tar);
		char *out_filename = mem_printf("%s/%s", out_dir, archive_filename);

		char *mode = mem_alloc0(4*sizeof(char));
		int_to_oct(th_get_mode(tar), mode, (int)(4*sizeof(char)));
		uid_t uid = th_get_uid(tar);
		gid_t gid = th_get_gid(tar);

		INFO("Writing file %s to %s", archive_filename, out_filename);
		if (TH_ISCHR(tar)) {
			// writing file attributes to index file (TODO use hashmap to handle duplicates)
			file_printf_append(index_file, "%s c %s %d %d %d %d\n",
				archive_filename, mode, uid, gid,
				th_get_devmajor(tar),
				th_get_devminor(tar));
		} else if (TH_ISBLK(tar)) {
			// writing file attributes to index file (TODO use hashmap to handle duplicates)
			file_printf_append(index_file, "%s b %s %d %d %d %d\n",
				archive_filename, mode, uid, gid,
				th_get_devmajor(tar),
				th_get_devminor(tar));
		} else {
			if (tar_extract_file(tar, out_filename) != 0) {
				INFO_ERRNO("Skipping file: %s", archive_filename);
			} else {
				// writing file attributes to index file (TODO use hashmap to handle duplicates)
				file_printf_append(index_file, "%s m %s %d %d\n",
					archive_filename, mode, uid, gid);
			}
		}

		mem_free(mode);
		mem_free(out_filename);
	}

	ret |= tar_close(tar);
	return ret;
}

static char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	char *hex = mem_alloc0(sizeof(char)*length*2 + 1);

	for (int i=0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex+i*2, 3, "%.2x", bin[i]);
	}

	return hex;
}

char *
util_hash_sha_image_file_new(const char *image_file)
{
	FILE *fp = NULL;
	SHA_CTX ctx;
	SHA1_Init(&ctx);

	if (!(fp = fopen(image_file, "rb"))) {
		ERROR_ERRNO("Error in file hasing, cannot open %s", image_file);
		return NULL;
	}

	int len = 0;
	unsigned char buf[SIGN_HASH_BUFFER_SIZE];

	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA1_Update(&ctx, buf, len);
	}
	fclose(fp);

	SHA1_Final(buf, &ctx);
	return convert_bin_to_hex_new(buf, SHA_DIGEST_LENGTH);
}

char *
util_hash_sha256_image_file_new(const char *image_file)
{
	FILE *fp = NULL;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	if (!(fp = fopen(image_file, "rb"))) {
		ERROR_ERRNO("Error in file hasing, cannot open %s", image_file);
		return NULL;
	}

	int len = 0;
	unsigned char buf[SIGN_HASH_BUFFER_SIZE];

	while ((len = fread(buf, 1, sizeof(buf), fp)) > 0) {
		SHA256_Update(&ctx, buf, len);
	}
	fclose(fp);

	SHA256_Final(buf, &ctx);
	return convert_bin_to_hex_new(buf, SHA256_DIGEST_LENGTH);
}

int
util_squash_image(const char *dir, const char *pseudo_file, const char *image_file)
{
	const char * const argv[] = {MKSQUASHFS_PATH, dir, image_file, "-noappend", "-all-root", "-comp", MKSQUASHFS_COMP, "-b", MKSQUASHFS_BSIZE, "-pf", pseudo_file, NULL};
	return util_fork_and_execvp(MKSQUASHFS_PATH, argv);
}

int
util_sign_guestos(const char *sig_file, const char *cfg_file, const char *key_file)
{
	const char * const argv[] = { OPENSSLBIN_PATH, "dgst", "-sha512",
		"-sign", key_file, "-out", sig_file, cfg_file, NULL };
	return util_fork_and_execvp(argv[0], argv);
}

int
util_gen_pki(void)
{
	const char * const argv[] = { "bash", PKIGENSCRIPT_PATH, PKIGENCONF_PATH, NULL };
	return util_fork_and_execvp(argv[0], argv);
}
