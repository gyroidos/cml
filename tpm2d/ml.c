/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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

#include "attestation.pb-c.h"
#include "ml.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"
#include "common/file.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define CONTAINER_PCR_INDEX 11

#define BINARY_RUNTIME_MEASUREMENTS "/sys/kernel/security/ima/binary_runtime_measurements"

typedef struct ml_elem {
	char *filename;
	TPM_ALG_ID algid;
	int hash_len;
	uint8_t *datahash;
	tpm2d_pcr_t *template;
} ml_elem_t;

static list_t *measurement_list = NULL;
static size_t measurement_list_len = 0;

int
ml_measurement_list_append(const char *filename, TPM_ALG_ID algid, const uint8_t *datahash,
			   size_t datahash_len)
{
	// input checks
	IF_NULL_RETVAL(filename, -1);
	IF_NULL_RETVAL(datahash, -1);
	IF_FALSE_RETVAL((datahash_len > 0), -1);

	// check if filehash is in list
	for (list_t *l = measurement_list; l; l = l->next) {
		ml_elem_t *ml_elem = l->data;
		if (NULL == ml_elem)
			continue;
		if ((0 == memcmp(ml_elem->datahash, datahash, datahash_len)) &&
		    (0 == memcmp(ml_elem->filename, filename, strlen(filename)))) {
			return 0; // container image with that name alread in list
		}
	}
	INFO("Appending new hash for %s len=%zu", filename, datahash_len);
	// new hash to be added
	ml_elem_t *new_ml_elem = mem_new0(ml_elem_t, 1);
	new_ml_elem->filename = mem_strdup(filename);
	new_ml_elem->hash_len = datahash_len;
	new_ml_elem->datahash = mem_new0(uint8_t, datahash_len);
	memcpy(new_ml_elem->datahash, datahash, datahash_len);

	new_ml_elem->algid = algid;

	// extend to TPM
	int ret = tpm2_pcrextend(CONTAINER_PCR_INDEX, TPM2D_HASH_ALGORITHM, datahash, datahash_len);
	if (ret) {
		ERROR("tpm extend failed");
	}
	// store the template as in the ML elem
	new_ml_elem->template = tpm2_pcrread_new(CONTAINER_PCR_INDEX, TPM2D_HASH_ALGORITHM);

	measurement_list = list_append(measurement_list, new_ml_elem);
	measurement_list_len++;

	return 0;
}

static const char *
halg_id_to_ima_string(TPM_ALG_ID alg_id)
{
	switch (alg_id) {
	case TPM_ALG_SHA1:
		return "sha1";
	case TPM_ALG_SHA256:
		return "sha256";
	case TPM_ALG_SHA384:
		return "sha384";
	default:
		return "none";
	}
}

uint8_t *
ml_get_ima_list_new(size_t *len)
{
	int fd = 0;

	fd = open(BINARY_RUNTIME_MEASUREMENTS, O_RDONLY);
	if (fd < 0) {
		DEBUG("Could not open file %s", BINARY_RUNTIME_MEASUREMENTS);
		*len = 0;
		return NULL;
	}

	int ret = 0;
	uint8_t *buf = NULL;
	size_t l = 0;

	// The binary measurement file in /sys is a special file where the file size cannot
	// be determined. Therefore it must be read byte by byte
	while (true) {
		buf = (uint8_t *)mem_realloc(buf, l + 1);
		ret = read(fd, buf + l, 1);

		if (ret == 0) {
			goto out;
		}
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				TRACE("Reading from fd %d: Blocked, retrying...", fd);
				continue;
			}
			mem_free0(buf);
			l = 0;
			ERROR("Failed to read binary_runtime_measurements");
			goto out;
		}
		l++;
	}

out:
	close(fd);
	*len = l;
	return buf;
}

void
ml_container_list_free(MlContainerEntry **entries, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		mem_free0(entries[i]->filename);
		mem_free0(entries[i]->template_hash_alg);
		mem_free0(entries[i]->template_hash.data);
		mem_free0(entries[i]->data_hash_alg);
		mem_free0(entries[i]->data_hash.data);
	}
	mem_free0(entries);
}

MlContainerEntry **
ml_get_container_list_new(size_t *len)
{
	MlContainerEntry **entries = mem_new(MlContainerEntry *, measurement_list_len);
	*len = measurement_list_len;

	size_t i = 0;
	for (list_t *l = measurement_list; l; l = l->next, i++) {
		ml_elem_t *ml_elem = l->data;
		MlContainerEntry *entry = mem_new(MlContainerEntry, 1);
		ml_container_entry__init(entry);
		entry->pcr_index = CONTAINER_PCR_INDEX;
		entry->filename = mem_strdup(ml_elem->filename);
		entry->template_hash_alg =
			mem_strdup(halg_id_to_ima_string(ml_elem->template->halg_id));
		entry->template_hash.data =
			mem_memcpy(ml_elem->template->pcr_value, ml_elem->template->pcr_size);
		entry->template_hash.len = ml_elem->template->pcr_size;
		entry->data_hash_alg = mem_strdup(halg_id_to_ima_string(ml_elem->algid));
		entry->data_hash.data = mem_memcpy(ml_elem->datahash, ml_elem->hash_len);
		entry->data_hash.len = ml_elem->hash_len;

		if (i >= measurement_list_len) {
			WARN("Measurement List out of range. Abort");
			break;
		}

		entries[i] = entry;
	}

	return entries;
}
