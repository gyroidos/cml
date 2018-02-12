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
 * @file sock.h
 *
 * Provides utility functions to work with UNIX (TODO and INET) sockets.
 */

#ifndef SOCK_H
#define SOCK_H

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <errno.h>

#ifdef ANDROID
#include <cutils/sockets.h>
#endif

/* Add missing defines from linux/net.h: */
/* Flags for socket, socketpair, accept4 */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC	O_CLOEXEC
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK	O_NONBLOCK
#endif

/**
 * Macro to get the path for a socket name.
 */
#ifdef ANDROID
#define SOCK_PATH(name) ANDROID_SOCKET_DIR"/cml-"#name
#else
#define SOCK_PATH(name) "/dev/cml-"#name
#endif

/**
 * Creates a new UNIX socket of the given type.
 *
 * @param type  type of the socket (e.g. SOCK_STREAM, SOCK_SEQPACKET, ...);
 *              (bitwise OR with SOCK_NONBLOCK saves extra call to fcntl)
 * @return  the new UNIX socket file descriptor, or -1 on error
 */
int
sock_unix_create(int type);

/**
 * Binds the given UNIX socket to the specified path.
 *
 * @param sock  the UNIX socket file descriptor to bind
 * @param path  path of the socket file to bind the socket to
 * @return  0 on success, -1 on error
 */
int
sock_unix_bind(int sock, const char *path);

/**
 * Connects the given UNIX socket to the specified path.
 *
 * @param sock  the UNIX socket file descriptor to bind
 * @param path  path of the socket file to bind the socket to
 * @return      0 on success, -1 on error
 */
int
sock_unix_connect(int sock, const char *path);

/**
 * Creates a new UNIX socket and binds it to the specified path.
 *
 * @param type  type of the socket (e.g. SOCK_STREAM, SOCK_SEQPACKET, ...);
 *              (bitwise OR with SOCK_NONBLOCK saves extra call to fcntl)
 * @param path  path of the socket file to bind the socket to
 * @return  the new and bound UNIX socket file descriptor, or -1 on error
 */
int
sock_unix_create_and_bind(int type, const char *path);

/**
 * Creates a new UNIX socket and connects it to the specified socket file.
 *
 * @param type  type of the socket (e.g. SOCK_STREAM, SOCK_SEQPACKET, ...)
 *              (bitwise OR with SOCK_NONBLOCK saves extra call to fcntl)
 * @param path  path of the socket file to connect to
 * @return      the new and connected UNIX socket file descriptor, or -1 on error
 */
int
sock_unix_create_and_connect(int type, const char *path);

/**
 * Listens for connections on the given UNIX socket by marking it as a
 * passive socket. The queue of pending connections is set to 128.
 *
 * @param sock the UNIX socket file descriptor to mark as a passive socket
 * @return 0 on success, -1 on error
 */
int
sock_unix_listen(int sock);

/**
 * Accepts a connection on the given UNIX socket.
 *
 * @param sock the UNIX socket file descriptor to accept a connection on
 * @return non-negative descriptor for the accepted socket, or -1 on error
 */
int
sock_unix_accept(int sock);

/**
 * Creates a new AF_INET socket of the given type.
 *
 * @param type  type of the socket (e.g. SOCK_STREAM, SOCK_SEQPACKET, ...);
 * @return  the new AF_INET socket file descriptor, or -1 on error
 */
int
sock_inet_create(int type);

/**
 * Connects a given AF_INET socket fd to an remote server.
 * If you make the fd non blocking the return value will likly be 1,
 * as the operating system will wait for a timeout till connect.
 * You have to use epoll or event_io submodule to trac till fd becomes
 * writable. Afterwards check status with getsockopts.
 *
 * @param sock the AF_INET socket file descriptor
 * @param ip the remote host's ip address as String, e.g. "127.0.0.1"
 * @param port the remot host's port number.
 * @return 0 on success,
 *         1 on EINPROGRESS,
 *        -1 on error
 */
int
sock_inet_connect(int sock, const char *ip, int port);

/**
 * Creates a new INET socket of the given type and connects it to the specified host/port.
 * Note that this function is agnostic to the IP version, i.e. it can open a IPv6
 * connection as well as an IPv4 connection transparently.
 * If there are multiple hosts behind a node/service combination it connects to the
 * first returned by getaddrinfo.
 *
 * @param type  type of the socket (e.g. SOCK_STREAM, SOCK_SEQPACKET, ...)
 *              (bitwise OR with SOCK_NONBLOCK saves extra call to fcntl)
 * @param node  host to connect to as used in getaddrinfo
 * @param service port number or port name
 * @return      the new and connected inet socket file descriptor, or -1 on error
 */
int
sock_inet_create_and_connect(int type, const char *node, const char *service);

#endif // SOCK_H
