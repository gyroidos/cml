/*
 * This file is part of GyroidOS
 * Copyright(c) 2026 Fraunhofer AISEC
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

#include "tpm2d.h"

#include <stdio.h>

void
tss2_print_all(const char *string, const unsigned char *buff, uint32_t length)
{
	if (buff == NULL) {
		printf(" %s null\n", string);
		return;
	}

	printf(" %s length %u\n ", string, length);
	for (uint32_t i = 0; i < length; i++) {
		if (i != 0 && (i % 16) == 0) {
			printf("\n ");
		}
		printf("%.2x ", buff[i]);
	}
	printf("\n");
}
