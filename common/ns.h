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

/**
 * @file ns.h
 * This module provides functions to execute a given function in the namespaces of a given process.
 */

#ifndef NS_H
#define NS_H

#include <unistd.h>

/**
 * This function tries to gain root priviledges.
 * @returns 0 if root priviledges were sucessfully aquired
 */
int
namespace_setuid0();

/**
 * This function forks a new child, joins the given namespaces and executes the given function
 * The namespaces to join are specified using the flags of the clone call
 *
 * @param ns_pid pid of the namespace to join
 * @param namespaces clone-flags of the namespaces to join
 * @param become_root indicates if setuid(0) should be executed after joinin the namespaces
 * @param func function pointer that gets executed inside the given namespaces
 * @param data array that is passed as a parameter to func
 * @returns 0 if the forked child exited cleanly, -1 otherwise.
 */
int
namespace_exec(pid_t ns_pid, const int namespaces, bool become_root, int (*func)(void **),
	       const void **data);

#endif //NS_H
