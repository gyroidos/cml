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

/**
 * @file guestos.stub.h
 *
 * Stub for the guestos module used for (control module) unit tests.
 * providing minimal (dummy) functionality.
 */
#ifndef GUESTOS_STUB_H
#define GUESTOS_STUB_H

#include "guestos.h"

void
guestos_mgr_update_images(void);

int
guestos_mgr_push_config(unsigned char *cfg, size_t cfglen, unsigned char *sig, size_t siglen,
			unsigned char *cert, size_t certlen);

size_t
guestos_mgr_get_guestos_count(void);

guestos_t *
guestos_mgr_get_guestos_by_index(size_t index);

void *
guestos_get_raw_ptr(const guestos_t *os);

#endif // GUESTOS_STUB_H
