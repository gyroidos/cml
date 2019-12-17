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
#include "common/proc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <stdint.h>

#include <openssl/sha.h>

#define OPENSSLBIN_PATH "openssl"
#define TAR_PATH "tar"
#define MKSQUASHFS_PATH "mksquashfs"
#define MKSQUASHFS_COMP "gzip"
#define MKSQUASHFS_BSIZE "131072"

#define SIGN_HASH_BUFFER_SIZE 4096

#define PKIGENSCRIPT_PATH UTIL_PKI_PATH "ssig_pki_generator.sh"
#define PKIGENCONF_PATH UTIL_PKI_PATH "ssig_pki_generator.conf"

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
util_tar_extract(const char *tar_filename, const char *out_dir)
{
	const char *const argv[] = { TAR_PATH, "-xvf", tar_filename, "-C", out_dir, NULL };
	return proc_fork_and_execvp(argv[0], argv);
}

static char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	char *hex = mem_alloc0(sizeof(char) * length * 2 + 1);

	for (int i = 0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex + i * 2, 3, "%.2x", bin[i]);
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
util_squash_image(const char *dir, const char *image_file)
{
	const char *const argv[] = { MKSQUASHFS_PATH, dir,  image_file,       "-noappend", "-comp",
				     MKSQUASHFS_COMP, "-b", MKSQUASHFS_BSIZE, NULL };
	return proc_fork_and_execvp(MKSQUASHFS_PATH, argv);
}

int
util_sign_guestos(const char *sig_file, const char *cfg_file, const char *key_file)
{
	const char *const argv[] = { OPENSSLBIN_PATH, "dgst",   "-sha512", "-sign", key_file,
				     "-out",	  sig_file, cfg_file,  NULL };
	return proc_fork_and_execvp(argv[0], argv);
}

int
util_gen_pki(void)
{
	const char *const argv[] = { "bash", PKIGENSCRIPT_PATH, PKIGENCONF_PATH, NULL };
	return proc_fork_and_execvp(argv[0], argv);
}
