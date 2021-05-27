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

#ifndef ML_H
#define ML_H

#include "tpm2d.h"

int
ml_measurement_list_append(const char *filename, TPM_ALG_ID algid, const uint8_t *datahash,
			   size_t datahash_len);

/**
 * Return the IMA measurement list in binary format as a buffer
 * @param len A pointer to the variable where the length of the list should be stored in
 * @return The binary measurement list buffer
 */
uint8_t *
ml_get_ima_list_new(size_t *len);

/**
 * Return the container measurement list in protobuf format
 * @param len A pointer to the variable where the length of the list should be stored in
 * @return The protobuf measurement list
 */
MlContainerEntry **
ml_get_container_list_new(size_t *len);

/**
 * Free the container measurement list allocated by ml_get_container_list_new
 * @param entries The list to be freed
 * @param len The length of the list
 */
void
ml_container_list_free(MlContainerEntry **entries, size_t len);

#endif /* ML_H */
