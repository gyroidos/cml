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

#ifndef TSS_H
#define TSS_H

#include <stdint.h>
#include <stdbool.h>

/*
 * type of supported hashes
 */
typedef enum { TSS_SHA1 = 0, TSS_SHA256, TSS_SHA384 } tss_hash_algo_t;

/**
 * Initializes the tss subsystem (starts the corresponding daemon)
 * @param start_daemon Fork and execute the tpm2d daemon
 * @return 0 on success, -1 on error
 */
int
tss_init(bool start_daemon);

/**
 * Cleanup the tss submodule, mainly stop tpm2d daemon.
 */
void
tss_cleanup(void);

void
tss_ml_append(char *filename, uint8_t *filehash, int filehash_len, tss_hash_algo_t hashalgo);

#endif /* TSS_H */
