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
#ifndef C_USER_H
#define C_USER_H

#include "container.h"

/**
 * Opaque c_user_t type for containers with usernamspace
 */
typedef struct c_user c_user_t;

/**
 * This function allocates a new c_user_t instance, associated to a specific container object.
 * @return the c_user_t user structure which holds user namespace information for a container.
 */
c_user_t *
c_user_new(container_t *container, bool user_ns);

/**
 * Returns the uid of the root user in the user namspace.
 */
int
c_user_get_uid(const c_user_t *user);

/**
 * Reserves a mapping for uids and gids of the user namespace in rootns
 */
int
c_user_start_pre_clone(c_user_t *user);

/**
 * Shifts mount tree using parent ids for shifted ids for this c_user_t
 *
 * Call this before entering the new user_ns, this function will spawn the
 * new user_ns by itself.
 */
int
c_user_start_child(const c_user_t *user);

/**
 * Setup mapping for uids and gids of the user namespace in rootns
 */
int
c_user_start_post_clone(c_user_t *user);

/**
 * Cleans up the c_user_t struct.
 */
void
c_user_cleanup(c_user_t *user, bool is_rebooting);

/**
 * Frees the c_net_t structure
 */
void
c_user_free(c_user_t *user);

/**
 * Shifts or sets uid/gids of path using the parent ids for this c_user_t
 *
 * Call this inside the parent user_ns.
 */
int
c_user_shift_ids(c_user_t *user, const char *path, bool is_root);

/**
 * Mounts all directories with shifted ids for this c_user_t
 */
int
c_user_shift_mounts(const c_user_t *user);

/**
 * Become root in userns
 */
int
c_user_setuid0(const c_user_t *user);

/**
 * Rejoin existing userns on reboots where userns is kept active
 */
int
c_user_join_userns(const c_user_t *user);

#endif /* C_USER_H */
