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

#include "guestos.stub.h"
#include "common/macro.h"

void
guestos_mgr_update_images(void)
{
	// TODO
	return;
}

int
guestos_mgr_push_config(UNUSED unsigned char *cfg, UNUSED size_t cfglen, UNUSED unsigned char *sig,
			UNUSED size_t siglen, UNUSED unsigned char *cert, UNUSED size_t certlen)
{
	// TODO
	return 0;
}

size_t
guestos_mgr_get_guestos_count(void)
{
	// TODO
	return 0;
}

guestos_t *
guestos_mgr_get_guestos_by_index(UNUSED size_t index)
{
	// TODO
	return NULL;
}

void *
guestos_get_raw_ptr(const guestos_t *os)
{
	// TODO
	ASSERT(os);
	return NULL;
}
