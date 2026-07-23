/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2026 Fraunhofer AISEC
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * \mainpage gydisk: The GyroidOS Disk Encryptor.
 *
 * gydisk is a tool to setup disk encryption for block devices,
 * using a hardware-based key store such as the CAAM/SEC module
 * of NXP.
 */

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/cryptfs.h"
#include "common/logf.h"

#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>

#ifndef LOGFILE_DIR
#define LOGFILE_DIR "/data/logs"
#endif

#define GYDISK_CAAM_BLOB "/boot/gydiskcrypt.blob"
#define GYDISK_CAAM_ALGO "capi:cbc(paes)-plain64" // only supported mode for protected keys in CAAM
#define GYDISK_CAAM_KEYLEN 32
#define CAAM_BLOB_OVERHEAD 48
#define CAAM_PKEY_HEADER 4
// this size is needed for the dm-crypt key string
#define GYDISK_CAAM_BLOB_LEN (CAAM_PKEY_HEADER + GYDISK_CAAM_KEYLEN + CAAM_BLOB_OVERHEAD)

#define GYDISK_KEY_NAME "gydiskcrypt"
#define GYDISK_KEY_KEYRING KEY_SPEC_USER_KEYRING
#define GYDISK_KEY_TYPE "trusted"

/******************************************************************************/
// syscall wrappers for add_key and keyctl

typedef int32_t key_serial_t;

static key_serial_t
add_key(const char *type, const char *description, const void *payload, size_t size,
	key_serial_t keyring)
{
	return syscall(__NR_add_key, type, description, payload, size, keyring);
}

static long
keyctl_read(key_serial_t key, char *buf, size_t size)
{
	return syscall(__NR_keyctl, KEYCTL_READ, key, buf, size, 0);
}

/******************************************************************************/

static void
main_core_dump_enable(void)
{
	struct rlimit core_limit;

	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	if (setrlimit(RLIMIT_CORE, &core_limit) < 0)
		ERROR_ERRNO("Could not set rlimits for core dump generation");
}
char *
gydisk_keyctl_pipe_blob_new(key_serial_t key_id)
{
	char *key_blob = NULL;
	long key_len = -1;

	// just get size
	if ((key_len = keyctl_read(key_id, 0, 0)) < 0) {
		ERROR_ERRNO("Failed to get size of key blob");
		return NULL;
	}

	key_blob = mem_alloc0(key_len + 1);

	// read actual encrypted key from kernel
	if (keyctl_read(key_id, key_blob, key_len) != key_len) {
		mem_free0(key_blob);
		ERROR("Key size mismatch for retrieving blob!");
		return NULL;
	}

	return key_blob;
}

int
gydisk_dm_setup_caam(const char *device_path)
{
	int ret = 0;

	IF_TRUE_RETVAL(device_path == NULL || !file_exists(device_path), -1);

	char *dev_name = basename(device_path);

	// overwrite internal crypto type in cryptfs module
	cryptfs_set_crypto_type(GYDISK_CAAM_ALGO);

	char *ascii_key =
		mem_printf(":%u:%s:%s", GYDISK_CAAM_BLOB_LEN, GYDISK_KEY_TYPE, GYDISK_KEY_NAME);

	INFO("Setting up crypto device mapping for %s to %s", device_path, dev_name);

	char *mapped_path = cryptfs_setup_volume_new(dev_name, device_path, ascii_key, NULL,
						     CRYPTFS_MODE_ENCRYPT_ONLY);

	if (mapped_path == NULL) {
		ERROR("Failed to setup device mapping for %s", device_path);
		ret = -1;
	}

	mem_free0(mapped_path);
	mem_free0(ascii_key);

	return ret;
}

static void
print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s <blk device>\n", cmd);
	printf("\n");
	printf("example:\n");
	printf("   %s /dev/loop2\n"
	       "        creates an encrypted mapper device on /dev/mapper/loop2\n\n",
	       cmd);
	printf("\n");
}

int
main(int argc, char **argv)
{
	char *device_path = NULL;
	char *payload_str = NULL;
	char *blob = NULL;

	logf_register(&logf_file_write, stdout);

	void *logfile_p = logf_file_new(LOGFILE_DIR "/gydisk");
	logf_handler_t *logfile_handler = logf_register(&logf_file_write, logfile_p);
	logf_handler_set_prio(logfile_handler, LOGF_PRIO_TRACE);

	main_core_dump_enable();

	// need at least one more argument (i.e. device path)
	if (argc < 2) {
		print_usage(argv[0]);
		goto error;
	}

	device_path = mem_strdup(argv[1]);

	IF_TRUE_GOTO_ERROR((device_path == NULL || !file_exists(device_path)), error);

	if (file_exists(GYDISK_CAAM_BLOB)) {
		/*
		 * add encrypted blob into key ring
		 */
		INFO("Going to load existing key %s from blob %s.", GYDISK_KEY_NAME,
		     GYDISK_CAAM_BLOB);

		blob = file_read_new(GYDISK_CAAM_BLOB, 4096);
		if (blob == NULL) {
			ERROR_ERRNO("Could not read encrypted blob from %s!", GYDISK_CAAM_BLOB);
			goto error;
		}
		// payload_str = mem_printf("load %s", blob);
		payload_str = mem_printf("load %s pk key_enc_algo=1", blob);
		key_serial_t keyid = add_key(GYDISK_KEY_TYPE, GYDISK_KEY_NAME, payload_str,
					     strlen(payload_str), GYDISK_KEY_KEYRING);
		if (keyid < 0) {
			ERROR_ERRNO("Failed to load existing blob into keyring!");
			goto error;
		}
	} else {
		/*
		 * gen new key and store blob in filesystem
		 */
		INFO("Going to generate new key %s.", GYDISK_KEY_NAME);

		// payload_str = mem_printf("new %u", GYDISK_CAAM_KEYLEN);
		payload_str = mem_printf("new %u pk key_enc_algo=1", GYDISK_CAAM_KEYLEN);
		key_serial_t keyid = add_key(GYDISK_KEY_TYPE, GYDISK_KEY_NAME, payload_str,
					     strlen(payload_str), GYDISK_KEY_KEYRING);
		if (keyid < 0) {
			ERROR("Failed to generate new %s in keyring!", GYDISK_KEY_NAME);
			goto error;
		}
		blob = gydisk_keyctl_pipe_blob_new(keyid);
		if (NULL == blob) {
			ERROR_ERRNO("Failed to read encrypted blob from keyring!");
			goto error;
		}
		if (file_write(GYDISK_CAAM_BLOB, blob, strlen(blob)) == -1) {
			ERROR_ERRNO("Could not store encrypted blob for subsequent boot!");
			goto error;
		}
	}

	if (gydisk_dm_setup_caam(device_path)) {
		ERROR("Failed to setup encrypted block device %s!", device_path);
		goto error;
	}

	mem_free0(blob);
	mem_free0(payload_str);

	logf_file_close(logfile_p);

	mem_free(device_path);

	return 0;

error:
	if (blob)
		mem_free0(blob);
	if (payload_str)
		mem_free0(payload_str);

	logf_file_close(logfile_p);

	if (device_path)
		mem_free(device_path);

	return -1;
}
