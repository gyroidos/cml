/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE

#include "sock.h"

#include "macro.h"
#include "mem.h"

#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h> // inet_addr
#include <netdb.h>

#define MAKE_SOCKADDR_UN(addr, path)                                                               \
	struct sockaddr_un addr = { .sun_family = AF_UNIX };                                       \
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);                                   \
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0'

#define MAKE_SOCKADDR_IN(addr, server_ip, server_port)                                             \
	struct sockaddr_in addr = { .sin_family = AF_INET };                                       \
	addr.sin_addr.s_addr = inet_addr(server_ip);                                               \
	addr.sin_port = htons(server_port)

int
sock_unix_bind(int sock, const char *path)
{
	unlink(path);
	MAKE_SOCKADDR_UN(addr, path);
	int res = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (-1 == res)
		WARN_ERRNO("Failed to bind UNIX socket to %s.", path);
	return res;
}

int
sock_unix_connect(int sock, const char *path)
{
	MAKE_SOCKADDR_UN(addr, path);
	int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (-1 == res)
		WARN_ERRNO("Failed to connect UNIX socket to %s.", path);
	return res;
}

int
sock_unix_create(int type)
{
	int sock = socket(AF_UNIX, type, 0);
	if (-1 == sock)
		WARN_ERRNO("Failed to create UNIX socket.");
	return sock;
}

int
sock_unix_create_and_bind(int type, const char *path)
{
	int sock = sock_unix_create(type);
	if (-1 != sock) {
		if (-1 == sock_unix_bind(sock, path)) {
			close(sock);
			sock = -1;
		}
	}
	return sock;
}

int
sock_unix_create_and_connect(int type, const char *path)
{
	int sock = sock_unix_create(type);
	if (-1 != sock) {
		if (-1 == sock_unix_connect(sock, path)) {
			close(sock);
			sock = -1;
		}
	}
	return sock;
}

int
sock_unix_listen(int sock)
{
	int res = listen(sock, 128);
	if (-1 == res)
		WARN_ERRNO("Failed to listen on UNIX socket %d.", sock);
	return res;
}

int
sock_unix_accept(int sock)
{
	int res = accept(sock, NULL, NULL);
	if (-1 == res)
		WARN_ERRNO("Failed to accept on UNIX socket %d.", sock);
	return res;
}

int
sock_unix_close(int sock)
{
	int res = close(sock);
	if (-1 == res)
		WARN_ERRNO("Failed to listen on UNIX socket %d.", sock);
	return res;
}

int
sock_unix_close_and_unlink(int sock, const char *path)
{
	if (-1 != sock_unix_close(sock)) {
		if (-1 != unlink(path)) {
			return 0;
		} else {
			WARN_ERRNO("Failed to unlink socket file at path %s", path);
		}
	} else {
		WARN_ERRNO("Failed to close on UNIX socket %d.", sock);
	}
	return -1;
}

int
sock_inet_create(int type)
{
	int sock = socket(AF_INET, type, 0);
	if (-1 == sock)
		WARN_ERRNO("Failed to create INET socket.");
	return sock;
}

int
sock_inet_bind(int sock, const char *ip, int port)
{
	MAKE_SOCKADDR_IN(addr, ip, port);
	int res = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (-1 == res)
		WARN_ERRNO("Failed to bind INET socket to %s:%d.", ip, port);
	return res;
}

int
sock_inet_create_and_bind(int type, const char *ip, int port)
{
	int sock = sock_inet_create(type);
	if (-1 != sock) {
		if (-1 == sock_inet_bind(sock, ip, port)) {
			close(sock);
			sock = -1;
		}
	}
	return sock;
}

int
sock_inet_connect(int sock, const char *ip, int port)
{
	MAKE_SOCKADDR_IN(addr, ip, port);
	int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (-1 == res && errno != EINPROGRESS) {
		WARN_ERRNO("Failed to connect INET socket to %s:%d.", ip, port);
		return -1;
	}
	if (-1 == res && errno == EINPROGRESS)
		return 1;

	return 0;
}

static int
sock_inet_connect_addrinfo(struct addrinfo *addrinfo)
{
	IF_NULL_RETVAL(addrinfo, -1);

	char addr_str[INET6_ADDRSTRLEN] = { 0 };
	void *addr_ptr = NULL;

	if (addrinfo->ai_family == AF_INET) {
		addr_ptr = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
	} else if (addrinfo->ai_family == AF_INET6) {
		addr_ptr = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
	}

	if (addr_ptr) {
		inet_ntop(addrinfo->ai_family, addr_ptr, addr_str, sizeof(addr_str));
		INFO("Trying to connect to IPv%d address: %s (%s)",
		     addrinfo->ai_family == PF_INET6 ? 6 : 4, addr_str, addrinfo->ai_canonname);
	} else {
		INFO("Trying to connect to unknown protocol address on %s", addrinfo->ai_canonname);
	}

	int sock = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
	if (sock == -1) {
		WARN_ERRNO("Could not create socket");
		return -1;
	}

	if (connect(sock, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
		WARN_ERRNO("Could not connect socket");
		close(sock);
		return -1;
	}

	INFO("Successfully connected to %s", addrinfo->ai_canonname);

	return sock;
}

int
sock_inet_create_and_connect(int type, const char *node, const char *service)
{
	struct addrinfo hints, *res = NULL;
	int sock = -1;

	mem_memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // allow for ipv6 and ipv4
	hints.ai_socktype = type;
	hints.ai_flags |= AI_CANONNAME;

	INFO("Trying to open socket to node (host) %s on service (port) %s", node, service);

	int status = getaddrinfo(node, service, &hints, &res);
	if (status) {
		WARN("getaddrinfo error: %s", gai_strerror(status));
		sock = -1;
		goto out;
	}

	struct addrinfo *cur = res;

	/* iterate over the linked list until a connect succeeds */
	while (cur) {
		sock = sock_inet_connect_addrinfo(cur);
		if (sock != -1) {
			break;
		}
		cur = cur->ai_next;
	}

out:
	/* free the linked list returned by getaddrinfo */
	if (res != NULL) {
		freeaddrinfo(res);
	}

	return sock;
}

int
sock_unix_get_peer_uid(int sock, uint32_t *peer_uid)
{
	IF_NULL_RETVAL(peer_uid, -1);

	struct ucred ucred;

	uint32_t len = sizeof(struct ucred);
	IF_TRUE_RETVAL((getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1), -1);

	*peer_uid = ucred.uid;
	return 0;
}

int
sock_unix_get_peer_pid(int sock, uint32_t *peer_pid)
{
	IF_NULL_RETVAL(peer_pid, -1);

	struct ucred ucred;

	uint32_t len = sizeof(struct ucred);
	IF_TRUE_RETVAL((getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == -1), -1);

	*peer_pid = ucred.pid;
	return 0;
}
