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

#include "nl.h"
#include <sys/uio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "macro.h"
#include "mem.h"

/**
 * Default values for message and socket allocation
 */
#define NL_MSG_DEFAULT_SIZE (2 * sysconf(_SC_PAGESIZE))
#define NL_DEFAULT_SOCK_RCVBUF_SIZE 32768
#define NL_DEFAULT_SOCK_SNDBUF_SIZE 32768
#define NL_UEVENT_SOCK_RCVBUF_SIZE (256 * 1024)

// only trust udev messages from this pid
static pid_t trusted_udevd_pid = -1;

enum udev_monitor_netlink_group {
	UDEV_MONITOR_NONE,
	UDEV_MONITOR_KERNEL,
	UDEV_MONITOR_UDEV,
};

/**
 * Netlink socket
 */
struct nl_sock {
	int fd;			  //!< Netlink filedescriptor
	struct sockaddr_nl local; //!< corresponding local sockaddress
};

/**
 * Netlink message
 */
struct nl_msg {
	size_t size;		  //!< Size of the message
	struct nlmsghdr nlmsghdr; //!< Netlink message header
};

/**
 * Sets the pointer of a netlink message header to the top end of the given netlink message.
 * NLMSG_ALIGN rounds the length of a netlink message up to align it properly.
 * @param A pointer to a netlink message header
 */
static inline void *
nl_msg_top(const struct nlmsghdr *hdr)
{
	return (void *)(((char *)hdr) + NLMSG_ALIGN(hdr->nlmsg_len));
}

/**
 * NLMSG_LENGTH(len) adds the length given by len to
 * the size of structure nlmsghdr.
 */
static int
nl_msg_set_len(nl_msg_t *msg, const size_t len)
{
	ASSERT(msg);

	msg->nlmsghdr.nlmsg_len = NLMSG_LENGTH(len);

	return 0;
}

/**
 * Adds an attribute with optional payload data to a nl message
 * @return failure: -1, success: 0
 */
static int
nl_msg_add_attr(nl_msg_t *msg, const int type, const void *data, const size_t size)
{
	ASSERT((msg && !(size > 0 && !data)));

	/* get length required for data of size bytes + header */
	const int len = RTA_LENGTH(size);
	struct nlmsghdr *nlmsg;
	struct rtattr *rta = NULL;

	nlmsg = &msg->nlmsghdr;

	/* Check for overflow in message buffer */
	if (NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(len) > msg->size) {
		TRACE("aligend size: %u len %d, msg->size %zu",
		      NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(len), len, msg->size);
		errno = EOVERFLOW;
		return -1;
	}

	/* Set the attribute metadata */
	rta = (struct rtattr *)nl_msg_top(nlmsg);
	rta->rta_type = type;
	rta->rta_len = len;

	/* Copy the attribute payload */
	if (data != NULL)
		memcpy(RTA_DATA(rta), data, len);

	/* Adjust message length */
	nlmsg->nlmsg_len = NLMSG_ALIGN(nlmsg->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

/**
 * Configures a created nl_sock as a default socket for kernel communication
 * @param nl_sock The socket to be configured
 * @return failure: -1, success: 0
 */
static int
nl_sock_conf_route_sock(nl_sock_t *sock)
{
	ASSERT(sock);

	const int sndbuf_size = NL_DEFAULT_SOCK_SNDBUF_SIZE;
	const int rcvbuf_size = NL_DEFAULT_SOCK_RCVBUF_SIZE;

	/* Set send buffer size */
	if (setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size)) < 0)
		return -1;

	/* Set receive buffer size */
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0)
		return -1;

	/* Declare as a unicast socket, don't listen to multicast groups */
	sock->local.nl_family = AF_NETLINK;
	sock->local.nl_groups = 0;

	return 0;
}

static inline uint32_t
nl_mgrp(uint32_t group)
{
	if (group > 31) {
		FATAL("Group exeeds uint32, Use setsockopt for this group %d\n", group);
	}
	return group ? (1 << (group - 1)) : 0;
}

/**
 * Configures a created nl_sock as xfrm nl socket for receiving sa specific kernel msg's
 * @param nl_sock The socket to be configured
 * @return failure: -1, success: 0
 */
static int
nl_sock_conf_xfrm_sock(nl_sock_t *sock)
{
	ASSERT(sock);

	// use default netlink conf
	if (nl_sock_conf_route_sock(sock) < 0)
		return -1;

	// subscribe to sa related events
	sock->local.nl_groups =
		nl_mgrp(XFRMNLGRP_ACQUIRE) | nl_mgrp(XFRMNLGRP_EXPIRE) | nl_mgrp(XFRMNLGRP_SA);
	return 0;
}

/**
 * Configures a created nl_sock as a uevent nl socket for receiving all kernel msg's
 * @param nl_sock The socket to be configured
 * @return failure: -1, success: 0
 */
static int
nl_sock_conf_uevent_sock(nl_sock_t *sock)
{
	ASSERT(sock);
	int passcreds = 1;
	const int sndbuf_size = NL_DEFAULT_SOCK_SNDBUF_SIZE;
	const int rcvbuf_size = NL_UEVENT_SOCK_RCVBUF_SIZE;

	/* Set send buffer size */
	if (setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size, sizeof(sndbuf_size)) < 0) {
		TRACE_ERRNO("Failed to set SO_SNDBUF!");
		return -1;
	}

	/* Set receive buffer size */
	if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size)) < 0) {
		TRACE_ERRNO("Failed to set SO_RECVBUF!");
		return -1;
	}

	/* Set SO_PASSCRED option in order to receive credentials (maybe the containers need this) */
	if (setsockopt(sock->fd, SOL_SOCKET, SO_PASSCRED, &passcreds, sizeof(passcreds)) < 0) {
		TRACE_ERRNO("Failed to set SO_PASSCRED!");
		return -1;
	}

	sock->local.nl_family = AF_NETLINK;
	sock->local.nl_groups = 0xffffffff;

	return 0;
}

/**
 * Creates a new netlink socket of a specified protocol.
 * Currently supported protocols:
 * 	NETLINK_KOBJECT_UEVENT, NETLINK_ROUTE, NETLINK_XFRM.
 * Should be called only by nl_sock_*_new functions.
 * @param protocol Netlink Protocol Family
 */
static nl_sock_t *
nl_sock_new(int protocol)
{
	socklen_t socklen;
	nl_sock_t *ret = NULL;

	ret = mem_new0(nl_sock_t, 1);

	if (!ret)
		return NULL;

	/* Get a netlink socket */
	ret->fd = socket(AF_NETLINK, SOCK_RAW, protocol);

	TRACE("Socket created, fd: %d", ret->fd);

	if (ret->fd < 0)
		goto err;

	if (protocol == NETLINK_KOBJECT_UEVENT) {
		if (nl_sock_conf_uevent_sock(ret))
			goto err;
	} else if (protocol == NETLINK_ROUTE) {
		if (nl_sock_conf_route_sock(ret))
			goto err;
	} else if (protocol == NETLINK_XFRM) {
		if (nl_sock_conf_xfrm_sock(ret))
			goto err;
	}

	/* Bind on the local socket. Kernel sets address pid automatically. */
	if (bind(ret->fd, (struct sockaddr *)&ret->local, sizeof(ret->local)) < 0)
		goto err;

	socklen = sizeof(ret->local);

	/* Get updated socket address (nl_pid is set now) */
	if (getsockname(ret->fd, (struct sockaddr *)&ret->local, &socklen) < 0)
		goto err;

	TRACE("Socket initialization done, sockaddr groups: %u, port id: %u", ret->local.nl_groups,
	      ret->local.nl_pid);

	/* Sanity check */
	if (socklen != sizeof(ret->local) || ret->local.nl_family != AF_NETLINK)
		goto err;

	return ret;

err:
	nl_sock_free(ret);
	return NULL;
}

nl_sock_t *
nl_sock_uevent_new(pid_t udevd_pid)
{
	TRACE("Creating uevent nl socket");
	trusted_udevd_pid = udevd_pid;
	return nl_sock_new(NETLINK_KOBJECT_UEVENT);
}

nl_sock_t *
nl_sock_routing_new()
{
	TRACE("Creating routing nl socket");
	return nl_sock_new(NETLINK_ROUTE);
}

nl_sock_t *
nl_sock_xfrm_new()
{
	TRACE("Creating xfrm nl socket");
	return nl_sock_new(NETLINK_XFRM);
}

nl_sock_t *
nl_sock_default_new(int protocol)
{
	if (protocol == NETLINK_KOBJECT_UEVENT || protocol == NETLINK_ROUTE)
		WARN("The default sock constructor should not be used with uevent or routing "
		     "parameters. Use the proper uevent/routing_new functions instead");

	TRACE("Creating default nl socket");
	return nl_sock_new(protocol);
}

int
nl_sock_get_fd(const nl_sock_t *sock)
{
	ASSERT(sock);

	return sock->fd;
}

void
nl_sock_free(nl_sock_t *nl)
{
	IF_NULL_RETURN(nl);
	close(nl->fd);
	mem_free(nl);
}

struct rtattr *
nl_msg_start_nested_attr(nl_msg_t *msg, int type)
{
	ASSERT(msg);

	struct rtattr *nested = NULL;

	/* Get pointer to the tail of the message payload.
	 * nl_msg_add_attr assures that the message's size is large
	 * enough to host the nested attribute. */
	nested = (struct rtattr *)nl_msg_top(&msg->nlmsghdr);

	/* Create an additional attribute with a NULL payload */
	if (nl_msg_add_attr(msg, type, NULL, 0))
		return NULL;

	return nested;
}

int
nl_msg_end_nested_attr(nl_msg_t *msg, struct rtattr *attr)
{
	ASSERT(msg && attr);

	attr->rta_len = (size_t)((long)nl_msg_top(&msg->nlmsghdr) - (long)attr);

	return 0;
}

int
nl_msg_add_buffer(nl_msg_t *msg, int type, const char *buffer, size_t len)
{
	ASSERT(msg && buffer);

	return nl_msg_add_attr(msg, type, buffer, len);
}

int
nl_msg_add_string(nl_msg_t *msg, const int type, const char *str)
{
	ASSERT(msg && str);

	return nl_msg_add_attr(msg, type, str, strlen(str) + 1);
}

int
nl_msg_add_u32(nl_msg_t *msg, int type, uint32_t val)
{
	ASSERT(msg);

	return nl_msg_add_attr(msg, type, (const void *)&val, sizeof(uint32_t));
}

int
nl_msg_send_kernel(const nl_sock_t *nl, const nl_msg_t *msg)
{
	ASSERT(nl && msg);

	struct sockaddr_nl nladdr; /* Destination address (kernel) */
	struct nlmsghdr *nlmsg;

	nlmsg = (struct nlmsghdr *)&msg->nlmsghdr;

	/* Sequence number of the message is set to socket fd, i.e. receiver knows sender socket */
	nlmsg->nlmsg_seq = nl->fd;

	DEBUG("Sending message on socket with fd %d to kernel", nl->fd);

	TRACE("Message for transmission:");
	TRACE("nl_msg{size:%zu,nlmsghdr:nlmsg_len: %u, nlmsg_type: %u,nlmsg_flags: %u, "
	      "nlmsg_seq: %u, nlmsg_pid: %d",
	      msg->size, msg->nlmsghdr.nlmsg_len, msg->nlmsghdr.nlmsg_type,
	      msg->nlmsghdr.nlmsg_flags, msg->nlmsghdr.nlmsg_seq, msg->nlmsghdr.nlmsg_pid);

	TRACE("Socket for transmisstion:");
	TRACE("nl_sock{fd:%d, local: nl_family: %u, nl_pad:%u, nl_pid: %d, nl_groups: %u}", nl->fd,
	      nl->local.nl_family, nl->local.nl_pad, nl->local.nl_pid, nl->local.nl_groups);

	/* Prepare scatter/gather transmission */
	struct iovec iov = { .iov_base = (void *)nlmsg, .iov_len = nlmsg->nlmsg_len };

	struct msghdr m = {
		.msg_name = &nladdr, .msg_namelen = sizeof(nladdr), .msg_iov = &iov, .msg_iovlen = 1
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;    /* Kernel has port id 0*/
	nladdr.nl_groups = 0; /* Unicast, no groups */

	TRACE("Transmit to this address:");
	TRACE("sockaddr_nl{nl_family: %u, nl_pad:%u, nl_pid: %d, nl_groups: %u}", nladdr.nl_family,
	      nladdr.nl_pad, nladdr.nl_pid, nladdr.nl_groups);

	return sendmsg(nl->fd, &m, 0);
}

static int
nl_verify_uevent_source(struct msghdr *uevent_msg, struct sockaddr_nl nladdr)
{
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(uevent_msg);

	if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
		/* ignoring netlink message with no sender credentials */
		return -1;
	}

	struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
	if (cred->uid != 0) {
		/* ignoring netlink message from non-root user */
		return -1;
	}

	if (nladdr.nl_groups == 0) {
		/* ignoring unicast netlink message */
		return -1;
	}
	if ((nladdr.nl_groups == UDEV_MONITOR_KERNEL) && (nladdr.nl_pid != 0)) {
		/* ignoring unicast netlink message */
		return -1;
	}
	// FIXME in case of shared network namspace pid of udevd can be faked
	if ((nladdr.nl_groups == UDEV_MONITOR_UDEV) &&
	    (trusted_udevd_pid != (pid_t)nladdr.nl_pid)) {
		/* ignoring udev events not from our init  */
		return -1;
	}

	return 0;
}

int
nl_msg_receive_kernel(const nl_sock_t *nl, char *buf, const size_t len, bool receive_uevent)
{
	int received;
	struct sockaddr_nl nladdr;
	char control[CMSG_SPACE(sizeof(struct ucred))];

	/* Prepare scatter/gather transmission */
	struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };

	struct msghdr m = { .msg_name = (void *)&nladdr,
			    .msg_namelen = sizeof(nladdr),
			    .msg_iov = &iov,
			    .msg_iovlen = 1,
			    .msg_control = control,
			    .msg_controllen = sizeof(control) };

	while (1) {
		errno = 0;
		received = recvmsg(nl->fd, &m, 0);

		/* Check if we were interrupted */
		if (received < 0) {
			if (errno == EINTR)
				continue;
			goto error;
		}
		break;
	}

	if (receive_uevent && nl_verify_uevent_source(&m, nladdr)) {
		TRACE("Detected possibly malicious uevent");
		goto error;
	}

	TRACE("Received a message from kernel");

	TRACE("Sent from this address:");
	TRACE("sockaddr_nl{nl_family: %u, nl_pad:%u, nl_pid: %u, nl_groups: %u}", nladdr.nl_family,
	      nladdr.nl_pad, nladdr.nl_pid, nladdr.nl_groups);

	TRACE("Arrived on this socket");
	TRACE("nl_sock{fd:%d, local: nl_family: %u, nl_pad:%u, nl_pid: %u, nl_groups: %u}", nl->fd,
	      nl->local.nl_family, nl->local.nl_pad, nl->local.nl_pid, nl->local.nl_groups);

	/* Check for truncated messages */
	if (m.msg_flags & MSG_TRUNC) {
		goto error;
	}

	/* Check if protocol family fits */
	if (nladdr.nl_family != AF_NETLINK) {
		goto error;
	}

	return received;

error:
	TRACE("Purged netlink message, as it did not pass sanity checks");
	memset(buf, 0, len);
	errno = EIO;
	return -1;
}

/**
 * This function may possibly block!
 */
static int
nl_eval_ack(const nl_sock_t *nl)
{
	ASSERT(nl);

	char *buf = NULL;
	int rcvd;

	buf = mem_new0(char, NL_DEFAULT_SOCK_RCVBUF_SIZE);

	if (!buf)
		return -1;

	rcvd = nl_msg_receive_kernel(nl, buf, NL_DEFAULT_SOCK_RCVBUF_SIZE, false);

	TRACE("Evaluating response of size: %d", rcvd);

	if (rcvd > 0) {
		/* Check if the msg was received in the right order */
		struct nlmsghdr *msg;

		/* This code is able to decode multipart nl messages with the NLM_F_MULTI flag set.
		 * When this loop is passed without ACK found, return -1 */
		for (msg = (struct nlmsghdr *)buf; NLMSG_OK(msg, (unsigned int)rcvd);
		     msg = NLMSG_NEXT(msg, rcvd)) {
			/* Check pid and sequence number of the received message:
			 * ACK has same port id as socket and same seq number */

			TRACE("Trying to match port id and sequence number");

			TRACE("Message header received:");
			TRACE("nlmsghdr{nlmsg_len: %u, nlmsg_type: %u, nlmsg_flags: %u, "
			      "nlmsg_seq: %u, nlmsg_pid: %d}",
			      msg->nlmsg_len, msg->nlmsg_type, msg->nlmsg_flags, msg->nlmsg_seq,
			      msg->nlmsg_pid);

			/* Check if message can be an ACK, i.e. pid is set to
			 * local address and  sequence number is echoed */
			if (nl->local.nl_pid != msg->nlmsg_pid ||
			    msg->nlmsg_seq != (unsigned int)nl->fd)
				continue;

			TRACE("Message comes from previous request");

			/* This is the last part of a multipart message, can't be the ACK */
			if (msg->nlmsg_type == NLMSG_DONE)
				break;

			/* Check the response message for errors:
			 * An ACK must be an error message with the error flag set to zero */

			if (msg->nlmsg_type == NLMSG_ERROR) {
				TRACE("Message is a response from previous request");

				/* ACK found, evaluate it */
				struct nlmsgerr *errack = NLMSG_DATA(msg);

				TRACE("Previous request header:");
				TRACE("nlmsghdr{nlmsg_len: %u, nlmsg_type: %u,nlmsg_flags: %u , "
				      "nlmsg_seq: %u, nlmsg_pid: %d}",
				      errack->msg.nlmsg_len, errack->msg.nlmsg_type,
				      errack->msg.nlmsg_flags, errack->msg.nlmsg_seq,
				      errack->msg.nlmsg_pid);

				if (errack->error) {
					errno = -(errack->error);
					ERROR_ERRNO("ACK reports an error!");
					break;
				} else {
					DEBUG("ACK successfully found");
					mem_free(buf);
					return 0;
				}
			}
		}
	}

	/* ACK could not be validated */
	ERROR("Message could not be received/decoded or was not an ACK response");
	mem_free(buf);
	return -1;
}

/**
  * This function may possibly block
  */
int
nl_msg_send_kernel_verify(const nl_sock_t *nl_sock, const nl_msg_t *req)
{
	ASSERT((nl_sock && req));

	if (!(req->nlmsghdr.nlmsg_flags & NLM_F_ACK)) {
		ERROR("nl request message must have the NLM_F_ACK flag set");
		return -1;
	}

	/* Send request message and wait for the response ACK message */
	if (nl_msg_send_kernel(nl_sock, req) < 0)
		return -1;

	DEBUG("Netlink message sent, waiting for ACK");

	/* Wait for and receive acknowledgment */
	return nl_eval_ack(nl_sock);
}

nl_msg_t *
nl_msg_new()
{
	nl_msg_t *ret = NULL;
	size_t size = NL_MSG_DEFAULT_SIZE;

	/* Take padding bytes after the nlmsghdr and the payload into
	 * account */
	const size_t len = NLMSG_ALIGN(size) + NLMSG_ALIGN(sizeof(struct nl_msg));

	ret = (nl_msg_t *)mem_new0(char, len);

	if (!ret)
		return NULL;

	/* Set length. Other attributes are set in setters and send */
	if (nl_msg_set_len(ret, size) != 0) {
		nl_msg_free(ret);
		return NULL;
	}

	/* Remember the size of the message */
	ret->size = NLMSG_ALIGN(size);

	TRACE("Netlink message allocated, size: %d", ret->nlmsghdr.nlmsg_len);

	return ret;
}

void
nl_msg_free(nl_msg_t *msg)
{
	IF_NULL_RETURN(msg);
	mem_free(msg);
}

int
nl_msg_expand_len(nl_msg_t *msg, const size_t len)
{
	ASSERT(msg);

	msg->nlmsghdr.nlmsg_len += len;

	return 0;
}

int
nl_msg_set_type(nl_msg_t *msg, const uint16_t type)
{
	ASSERT(msg);

	msg->nlmsghdr.nlmsg_type = type;

	return 0;
}

int
nl_msg_set_flags(nl_msg_t *msg, const uint16_t flags)
{
	ASSERT(msg);

	msg->nlmsghdr.nlmsg_flags = flags;

	return 0;
}

int
nl_msg_set_link_req(nl_msg_t *msg, const struct ifinfomsg *ifmsg)
{
	ASSERT(msg);

	int size = sizeof(struct ifinfomsg);
	memcpy(NLMSG_DATA(&msg->nlmsghdr), ifmsg, size);

	return nl_msg_set_len(msg, size);
}

int
nl_msg_set_ip_req(nl_msg_t *msg, const struct ifaddrmsg *ifmsg)
{
	ASSERT(msg);

	int size = sizeof(struct ifaddrmsg);
	memcpy(NLMSG_DATA(&msg->nlmsghdr), ifmsg, size);

	return nl_msg_set_len(msg, size);
}

int
nl_msg_set_rt_req(nl_msg_t *msg, const struct rtmsg *rtmsg)
{
	ASSERT(msg);

	int size = sizeof(struct rtmsg);
	memcpy(NLMSG_DATA(&msg->nlmsghdr), rtmsg, size);

	return nl_msg_set_len(msg, size);
}

int
nl_msg_set_buf_unaligned(nl_msg_t *msg, char *buf, size_t size)
{
	ASSERT(msg);

	/* Check for overflow in message buffer */
	if (NLMSG_LENGTH(size) > msg->size) {
		TRACE("size: %zu, msg->size %zu", size, msg->size);
		errno = EOVERFLOW;
		return -1;
	}
	memcpy(NLMSG_DATA(&msg->nlmsghdr), buf, size);

	return nl_msg_set_len(msg, size);
}

int
nl_msg_receive_and_check_kernel(const nl_sock_t *nl)
{
	ASSERT(nl);

	char *buf = NULL;
	int ret = 0;

	buf = mem_new0(char, NL_DEFAULT_SOCK_RCVBUF_SIZE);
	IF_NULL_RETVAL_TRACE(buf, -1);

	if (nl_msg_receive_kernel(nl, buf, NL_DEFAULT_SOCK_RCVBUF_SIZE, false) < 0) {
		mem_free(buf);
		return -1;
	}

	struct nlmsghdr *msg = (struct nlmsghdr *)buf;
	if (msg->nlmsg_type == NLMSG_ERROR) {
		TRACE("Message is a response from previous request");
		struct nlmsgerr *err = NLMSG_DATA(msg);
		if (err->error != 0) {
			errno = -err->error;
			ret = -1;
		}
	}
	mem_free(buf);
	return ret;
}
