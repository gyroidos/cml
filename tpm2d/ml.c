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

#include "ml.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/list.h"

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#define CONTAINER_PCR_INDEX 11

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
ml_measurement_list_append(const char *filename, TPM_ALG_ID algid, const uint8_t *datahash, size_t datahash_len)
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

static list_t *
ml_get_ima_ml_string_list_new(void)
{
	FILE *fp;
	char *line = NULL; // will be malloced by getline
	size_t line_len = 0;

	fp = fopen("/sys/kernel/security/ima/ascii_runtime_measurements", "r");
	IF_NULL_RETVAL(fp, NULL);

	list_t *ima_list = NULL;
	while (-1 != getline(&line, &line_len, fp)) {
		line[line_len - 1] = '\0'; // overwrite '\n'
		ima_list = list_append(ima_list, mem_strdup(line));
	}

	fclose(fp);
	if (line)
		mem_free(line);
	return ima_list;
}

char **
ml_get_measurement_list_strings_new(size_t *strings_len)
{
	list_t *ima_strings_list = ml_get_ima_ml_string_list_new();
	*strings_len = measurement_list_len + list_length(ima_strings_list);
	char **strings = mem_new0(char *, *strings_len);

	int i = 0;
	for (list_t *l = ima_strings_list; l; l = l->next, ++i) {
		char *ima_ml_string = l->data;
		strings[i] = ima_ml_string;
		INFO("ML (%d): %s", i, strings[i]);
	}
	list_delete(ima_strings_list); // only deletes the list elements not the element's data

	for (list_t *l = measurement_list; l; l = l->next, ++i) {
		ml_elem_t *ml_elem = l->data;
		char *hex_datahash = convert_bin_to_hex_new(ml_elem->datahash, ml_elem->hash_len);
		const char *halg_string = halg_id_to_ima_string(ml_elem->algid);
		char *hex_template = convert_bin_to_hex_new(ml_elem->template->pcr_value, ml_elem->template->pcr_size);
		strings[i] = mem_printf("%d %s ima-ng %s:%s %s", CONTAINER_PCR_INDEX, hex_template, halg_string,
					hex_datahash, ml_elem->filename);
		INFO("ML (%d): %s", i, strings[i]);
		mem_free(hex_datahash);
		mem_free(hex_template);
	}

	return strings;
}
