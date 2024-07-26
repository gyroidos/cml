/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file ns.h
 * This module provides functions to execute a given function in the namespaces of a given process.
 */

#ifndef NS_H
#define NS_H

#define _GNU_SOURCE
#include <sched.h>
#include <stdbool.h>
#include <unistd.h>

#define CLONE_NEWALL                                                                               \
	(CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWPID |              \
	 CLONE_NEWUSER | CLONE_NEWTIME)

/**
 * This function tries to gain root privileges.
 * @returns 0 if root privileges were successfully acquired
 */
int
namespace_setuid0();

/**
 * This function forks a new child, joins the given namespaces and executes the given function
 * The namespaces to join are specified using the flags of the clone call
 *
 * @param ns_pid pid of the namespace to join
 * @param namespaces clone-flags of the namespaces to join
 * @param uid indicates if setuid(uid) should be executed after joining the namespaces
 * @param cap keep system-wide capability after setuid
 * @param func function pointer that gets executed inside the given namespaces
 * @param data pointer that is passed as a parameter to func
 * @returns 0 if the forked child exited cleanly, -1 otherwise.
 */
int
namespace_exec(pid_t namespace_pid, const int namespaces, int uid, int cap,
	       int (*func)(const void *), const void *data);

/**
 * This function joins the current process to all namespaces of a process given
 * by its pid. The userns is joined only if switch userns is true.
 * Do not use this function in main process of cmld directly!
 * Fork or clone a child beforehand and execute this in the child.
 *
 * @param pid pid of the namespace to join
 * @param userns switch for joining userns
 * @returns 0 if all namespaces are changed successfully, -1 otherwise.
 */
int
ns_join_all(pid_t pid, bool userns);

/**
 * Bind mount ns e.g. "net" to ns_path, which keeps the corresponding
 * namespace alive even if last process in namespace of pid dies.
 *
 * @param ns namespace type e.g. "net"
 * @param pid pid of the namespace to be bound in the file system
 * @param ns_path target path for the bind mount of the ns file
 * @returns 0 if namespace is bound to file system path successfully, -1 otherwise.
 */
int
ns_bind(char *ns, pid_t pid, char *ns_path);

/**
 * Release a bound ns e.g. "net" in the file system on path ns_path.
 *
 * @param ns_path target path for the bind mount of the ns file
 * @returns 0 if namespace file is unbound successfully, -1 otherwise.
 */
int
ns_unbind(const char *ns_path);

/**
 * Joins current process to a namespace defined by a bound path in the
 * file system.
 *
 * @param ns_path path of the bound namespace to be joined
 * @returns 0 if process successfully joined the namespace, -1 otherwise.
 */
int
ns_join_by_path(const char *ns_path);

/**
 * Compare the pidns refernce of two pids
 *
 * This function checks if the pidns reference in /proc/<pid>/ns/pidns
 * are equal ore not. If so pid1 and pid2 are in the same pidns.
 *
 * @param pid1 pid of a process
 * @param pid2 pid of another process
 * @return true if pid1 and pid2 have the same reference, false otherwise.
 */
bool
ns_cmp_pidns_by_pid(pid_t pid1, pid_t pid2);

#endif //NS_H
