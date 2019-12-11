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

/* @file nl.test.c
 * Unit Test for nl.c. Sends a request message to the kernel and gets the ACK
 */
#define SCM_CREDENTIALS (0x02)

#if PLATFORM_VERSION_MAJOR >= 5
#include <sys/types.h>
/* User visible structure for SCM_CREDENTIALS message */
struct ucred {
	pid_t pid; /* PID of sending process.  */
	uid_t uid; /* UID of sending process.  */
	gid_t gid; /* GID of sending process.  */
};
#endif

#include "nl.c"
#define VETH_INFO_PEER (0x01)

/**
 * Print a nl_sock object. Could be used in nl.c for debugging
 */
static void
print_sock(nl_sock_t *sock)
{
	if (!sock)
		return;

	DEBUG("nl_sock{fd:%d, local: nl_family: %u, nl_pad:%u, nl_pid: %d, nl_groups: %u}",
	      sock->fd, sock->local.nl_family, sock->local.nl_pad, sock->local.nl_pid,
	      sock->local.nl_groups);
}

/**
 * Print a sockaddr_nl object. Could be used in nl.c for debugging
 */
static void
print_addr(struct sockaddr_nl *addr)
{
	if (!addr)
		return;

	DEBUG("sockaddr_nl{nl_family: %u, nl_pad:%u, nl_pid: %d, nl_groups: %u}", addr->nl_family,
	      addr->nl_pad, addr->nl_pid, addr->nl_groups);
}

/**
 * Print a nl_msg object. Could be used in nl.c for debugging
 */
static void
print_msg(nl_msg_t *msg)
{
	if (!msg)
		return;

	DEBUG("nl_msg{size:%u,nlmsghdr:nlmsg_len: %u, nlmsg_type: %u,nlmsg_flags: %u, nlmsg_seq: %u, "
	      "nlmsg_pid: %d",
	      msg->size, msg->nlmsghdr.nlmsg_len, msg->nlmsghdr.nlmsg_type,
	      msg->nlmsghdr.nlmsg_flags, msg->nlmsghdr.nlmsg_seq, msg->nlmsghdr.nlmsg_pid);
}

/**
 * Print a nlmsghdr object. Could be used in nl.c for debugging
 */
static void
print_msghdr(struct nlmsghdr *msg)
{
	if (!msg)
		return;

	DEBUG("nlmsghdr{nlmsg_len: %u, nlmsg_type: %u, nlmsg_flags: %u,nlmsg_seq: %u, nlmsg_pid: %d}",
	      msg->nlmsg_len, msg->nlmsg_type, msg->nlmsg_flags, msg->nlmsg_seq, msg->nlmsg_pid);
}

/**
 * The kernel will return an operation not permitted error, because
 * we don't have necessary permissions for this request.
 * Anyway, this checks the basic send, receive, allocate functionality.
 */
int
main(void)
{
	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: nl.test.c");

	/* Open two sockets in order to check if message transmission works though */
	DEBUG("Open two sockets");
	nl_sock_t *sock1 = nl_sock_routing_new();
	nl_sock_t *sock2 = nl_sock_routing_new();
	ASSERT(sock1 && sock2);

	DEBUG("Check socket properties");

	/* main point: different pids of the fd's */
	ASSERT(sock1->fd != sock2->fd);
	ASSERT(sock1->local.nl_family == AF_NETLINK);
	ASSERT(sock1->local.nl_pid == (unsigned int)getpid());
	ASSERT(sock1->local.nl_pid != sock2->local.nl_pid);
	print_sock(sock1);
	print_sock(sock2);

	/* Allocate a request message */
	nl_msg_t *msg1 = nl_msg_new(NL_MSG_DEFAULT_SIZE);
	ASSERT(msg1);
	ASSERT(msg1->nlmsghdr.nlmsg_seq == 0 && msg1->nlmsghdr.nlmsg_pid == 0);
	print_msghdr(&msg1->nlmsghdr);

	DEBUG("Request message allocated, preparing now...");
	/* Prepare request message */
	{
		char *veth1 = "veth0";
		char *veth2 = "veth1";

		struct ifinfomsg link_req = { .ifi_family = AF_INET };

		struct rtattr *attr1, *attr2, *attr3;

		/* Fill netlink message header */
		ASSERT(nl_msg_set_type(msg1, RTM_NEWLINK) == 0);

		/* Set appropriate flags for request, creating new object, exclusive access and acknowledgment response */
		ASSERT(nl_msg_set_flags(msg1, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL |
						      NLM_F_ACK) == 0);

		/* Fill link request header of request message */
		ASSERT(nl_msg_set_link_req(msg1, &link_req) == 0);

		DEBUG("Print linked/lengthed msg:");
		print_msg(msg1);

		/* Add the corresponding attributes to the netlink header */
		attr1 = nl_msg_start_nested_attr(msg1, IFLA_LINKINFO);
		ASSERT(attr1);

		/* Set link type */
		ASSERT(nl_msg_add_string(msg1, IFLA_INFO_KIND, "veth") == 0);

		/* Add nested attributes for INFO and PEER */
		attr2 = nl_msg_start_nested_attr(msg1, IFLA_INFO_DATA);
		ASSERT(attr2);

		attr3 = nl_msg_start_nested_attr(msg1, VETH_INFO_PEER);
		ASSERT(attr3);

		/* VETH_INFO_PEER carries struct ifinfomsg plus optional IFLA
		   attributes. A minimal size of sizeof(struct ifinfomsg) must be
		   enforced or we may risk accessing that struct beyond the limits
		   of the netlink message */
		ASSERT(nl_msg_expand_len(msg1, sizeof(struct ifinfomsg)) == 0);

		/* Set veth2 name */
		ASSERT(nl_msg_add_string(msg1, IFLA_IFNAME, veth2) == 0);

		/* Close nested attributes */
		ASSERT(nl_msg_end_nested_attr(msg1, attr3) == 0);
		ASSERT(nl_msg_end_nested_attr(msg1, attr2) == 0);
		ASSERT(nl_msg_end_nested_attr(msg1, attr1) == 0);

		/* Set veth1 name */
		ASSERT(nl_msg_add_string(msg1, IFLA_IFNAME, veth1) == 0);
	}

	DEBUG("Send and rec. this completely initialized msg.:");
	print_msg(msg1);

	/* Send request message and wait for the response message */
	nl_msg_send_kernel_verify(sock2, msg1);

	DEBUG("Message should have nlmsg_pid and nlmsg_seq set after transmission");
	print_msg(msg1);
	/* seq. number set to socket fd to associate socket to message */
	ASSERT(msg1->nlmsghdr.nlmsg_seq == (unsigned int)sock2->fd);

	DEBUG("Sent and received, errno is: %d", errno);
	ASSERT(errno == 1);

	DEBUG("uevent shall be creatable but not configurable, as the permissions are not given:");
	nl_sock_t *sock3 = nl_sock_uevent_new();
	ASSERT(sock3 == NULL);

	// free socks&msg
	nl_msg_free(msg1);
	nl_sock_free(sock1);
	nl_sock_free(sock2);

	return 0;
}
