/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.

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

#include "oci.h"

#include "container.h"
#include "crypto.h"

#include "common/file.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/hex.h"

#include <unistd.h>

#define MOD_NAME "c_oci"

#define TOKEN_KEY_LEN 96 // actual encryption key + hmac key

typedef struct c_oci {
	container_t *container; //!< container which the c_user struct is associated to
	char *key_file;		//!< file for generated container key
} c_oci_t;

static int
c_oci_start_pre_clone(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	IF_NULL_RETVAL(oci_get_oci_container_by_container(oci->container), 0);

	// TODO decide location of key e.g. in hardware TPM
	char *ascii_key = NULL;
	if (file_exists(oci->key_file)) {
		ascii_key = file_read_new(oci->key_file, file_size(oci->key_file));
	} else {
		unsigned char key[TOKEN_KEY_LEN];
		int keylen = crypto_random_get_bytes(key, sizeof(key));
		ascii_key = convert_bin_to_hex_new(key, keylen);
		mem_memset0(key, sizeof(key));
		// include terminating null byte into file
		file_write(oci->key_file, ascii_key, strlen(ascii_key) + 1);
	}

	if (ascii_key) {
		container_set_key(oci->container, ascii_key);

		// delete key from RAM
		mem_memset0(ascii_key, strlen(ascii_key));
		mem_free0(ascii_key);
		return 0;
	}

	ERROR("Failed to execute start early clone hook for oci");
	return -COMPARTMENT_ERROR_VOL;
}

static int
c_oci_start_child(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	IF_NULL_RETVAL(oci_get_oci_container_by_container(oci->container), 0);

	return oci_do_hooks_create_container(oci->container);
}

static int
c_oci_start_pre_exec_child(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	IF_NULL_RETVAL(oci_get_oci_container_by_container(oci->container), 0);

	// pause container after OCI_CREATE util OCI_START
	pause();

	DEBUG("%s %s", CSERVICE_TARGET, file_exists(CSERVICE_TARGET) ? "exists" : "does not exist");

	return oci_do_hooks_start_container(oci->container);
}

static int
c_oci_start_post_clone(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	IF_NULL_RETVAL(oci_get_oci_container_by_container(oci->container), 0);

	return oci_do_hooks_create_runtime(oci->container);
}

static int
c_oci_start_post_exec(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	IF_NULL_RETVAL(oci_get_oci_container_by_container(oci->container), 0);

	return oci_do_hooks_prestart(oci->container);
}

/**
 * This function allocates a new c_oci_t instance, associated to a specific container object.
 * @return the c_oci_t user structure which holds oci spcific information for a container.
 */
static void *
c_oci_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_oci_t *oci = mem_new0(c_oci_t, 1);
	oci->container = compartment_get_extension_data(compartment);

	oci->key_file = mem_printf("%s-oci.key", container_get_images_dir(oci->container));

	return oci;
}

static void
c_oci_free(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	oci_container_t *oci_container = oci_get_oci_container_by_container(oci->container);
	// free oci wrapping structure
	if (oci_container)
		oci_container_free(oci_container);

	if (oci->key_file)
		mem_free0(oci->key_file);

	mem_free0(oci);
}

static void
c_oci_destroy(void *ocip)
{
	c_oci_t *oci = ocip;
	ASSERT(oci);

	if (file_exists(oci->key_file) && unlink(oci->key_file))
		WARN("Could not remove %s!", oci->key_file);
}

static compartment_module_t c_oci_module = {
	.name = MOD_NAME,
	.compartment_new = c_oci_new,
	.compartment_free = c_oci_free,
	.compartment_destroy = c_oci_destroy,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_oci_start_pre_clone,
	.start_post_clone = c_oci_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = c_oci_start_post_exec,
	.start_child = c_oci_start_child,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = c_oci_start_pre_exec_child,
	.stop = NULL,
	.cleanup = NULL,
	.join_ns = NULL,
};

static void INIT
c_oci_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_oci_module);
}
