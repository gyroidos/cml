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
#ifndef TOKENCONTROL_H
#define TOKENCONTROL_H
#include "common/list.h"
#include "token.h"

typedef struct tokencontrol tctrl_t;

tctrl_t *
tokencontrol_new(const token_t *token);

void
tokencontrol_free(tctrl_t *tctrl);
#endif // TOKENCONTROL_H