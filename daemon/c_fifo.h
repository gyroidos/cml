/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2020 Fraunhofer AISEC
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

#ifndef C_FIFO_H
#define C_FIFO_H

#include "container.h"

typedef struct c_fifo c_fifo_t;

void
c_fifo_cleanup(void *fifo);

void
c_fifo_free(c_fifo_t *fifo);

int
c_fifo_start_child(c_fifo_t *fifo);

int
c_fifo_start_post_clone(c_fifo_t *fifo);

c_fifo_t *
c_fifo_new(container_t *container, list_t *fifo_list);

#endif /* C_FIFO_H */
