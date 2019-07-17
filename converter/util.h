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

#ifndef UTIL_H
#define UTIL_H

#include <unistd.h>

#define b64_ntop __b64_ntop
#define b64_pton __b64_pton

#define UTIL_PKI_PATH "/pki_generator/"

int b64_ntop(unsigned char const *src, size_t srclength,
		             char *target, size_t targsize);
int b64_pton(char const *src, unsigned char *target, size_t targsize);

int
util_fork_and_execvp(const char *path, const char * const *argv);

char *
util_hash_sha_image_file_new(const char *image_file);

char *
util_hash_sha256_image_file_new(const char *image_file);

int
util_tar_extract(const char *tar_filename, const char* out_dir);

int
util_squash_image(const char *dir, const char *image_file);

int
util_sign_guestos(const char *sig_file, const char *cfg_file, const char *key_file);

int
util_gen_pki(void);

#endif /* UTIL_H */
