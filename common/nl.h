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

/* @file nl.h
 * Interface for netlink socket communication.
 * Collection of netlink functions to forge netlink messages
 * and to transmit them over a netlink socket.
 * Abstracts through a socket and message structure.
 * Its main purpose is to support networking configuration.
 */
#ifndef NL_H_
#define NL_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <stdbool.h>

/* Define some missing netlink defines in BIONIC */
#ifndef VETH_INFO_PEER
#define VETH_INFO_PEER (0x01)
#endif

typedef struct nl_sock nl_sock_t;
typedef struct nl_msg nl_msg_t;

/**
 * Allocates, opens and returns a nl_sock object of family NETLINK_KOBJECT_UEVENT with various netlink options.
 * Depending on the protocol, the socket options are implicitly set.
 * @return Pointer to nl_sock; NULL in case of failure
 */
nl_sock_t *
nl_sock_uevent_new(pid_t udevd_pid);

/**
 * Allocates, opens and returns a nl_sock object of family NETLINK_ROUTE with various netlink options.
 * Depending on the protocol, the socket options are implicitly set.
 * Priviledges are required, because this socket is using a RCVBUFFORCE flag option overwriting
 * the max recv-buf file.
 * @return Pointer to nl_sock; NULL in case of failure
 */
nl_sock_t *
nl_sock_routing_new();

/**
 * Allocates, opens and returns a nl_sock object of family NETLINK_XFRM with various netlink options.
 * Depending on the protocol, the socket options are implicitly set.
 * Priviledges are required, because this socket is using a RCVBUFFORCE flag option overwriting
 * the max recv-buf file.
 * @return Pointer to nl_sock; NULL in case of failure
 */
nl_sock_t *
nl_sock_xfrm_new();

/**
 * Allocates, opens and returns a nl_sock object of family NETLINK_ROUTING with various netlink options.
 * The socket is subscribed to RTMGRP_IPV4_IFADDR and RTMGRP_IPV6_IFADDR events.
 * Priviledges are required, because this socket is using a RCVBUFFORCE flag option overwriting
 * the max recv-buf file.
 * @return Pointer to nl_sock; NULL in case of failure
 */
nl_sock_t *
nl_sock_ifaddr_new();

/**
 * Allocates, opens and returns a nl_sock object of a different netlink family than the other
 * sock_*_new functions without specific netlink options.
 * @return Pointer to nl_sock; NULL in case of failure
 */
nl_sock_t *
nl_sock_default_new(int protocol);

/**
 * Getter for fd of a nl_sock struct.
 * @return Filedescriptor associated to the netlink socket
 */
int
nl_sock_get_fd(const nl_sock_t *sock);

/**
 * Close an open netlink socket
 */
void
nl_sock_free(nl_sock_t *sock);

/**
 * Send a netlink message over a socket to the kernel
 * @return In case of failure, return -1/errno, in case of success, return number of bytes sent
 */
int
nl_msg_send_kernel(const nl_sock_t *sock, const nl_msg_t *msg);

/**
 * Receive a netlink message from the kernel.
 * This is a blocking function, thus this function should be only
 * called when you know that there is a message on the socket.
 * @param buf Netlink message header, which must be preallocated and large enough.
 * The buffer is filled with the message content
 * @return In case of failure, return -1, in case of success, return num of bytes received
 */
int
nl_msg_receive_kernel(const nl_sock_t *sock, char *buf, size_t len, bool receive_uevent);

/**
 * Transmit a message with ACKNOWLEDGEMENT flag
 * and check the ACK response for success.
 * This is a blocking function, as it calls the nl_receive_kernel function.
 * In case the netlink request failed, the errnor is set to the ACK error.
 * @return In case of failure, return -1, in case of success, return 0
 */
int
nl_msg_send_kernel_verify(const nl_sock_t *sock, const nl_msg_t *req);

/**
 * Allocates a raw netlink message, which can be completed
 * with the set/add functions.
 * @return In case of failure, return NULL,
 *	    in case of success, return the allocated message.
 */
nl_msg_t *
nl_msg_new();

/**
 * Free a netlink message
 */
void
nl_msg_free(nl_msg_t *msg);

/**
 * Sets the request to according to the given payload struct.
 * The message length is adapted accordingly.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_link_req(nl_msg_t *msg, const struct ifinfomsg *ifmsg);

/**
 * Sets the request to according to the given payload struct.
 * The message length is adapted accordingly.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_ip_req(nl_msg_t *msg, const struct ifaddrmsg *ifmsg);

/**
 * Sets the request to according to the given payload struct.
 * The message length is adapted accordingly.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_rt_req(nl_msg_t *msg, const struct rtmsg *rtmsg);

/**
 * Sets the request according to the given routing rule payload struct.
 * The message length is adapted accordingly.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_rule_req(nl_msg_t *msg, const struct fib_rule_hdr *rule);

/**
 * Sets the nl message type attribute
 * @return failure: -1, success: 0
 */
int
nl_msg_set_type(nl_msg_t *msg, uint16_t type);

/**
 * Sets the nl message flags. Using the send_and_check_ack function
 * for transmission, the NLM_F_ACK flag should be set here
 * @return failure: -1, success: 0
 */
int
nl_msg_set_flags(nl_msg_t *msg, uint16_t flags);

/**
 * Adds the attribute header that identifies the
 * beginning of an attribute nest.
 * @param type Type of the nested attribute
 * @return failure: NULL, success: pointer to the rtattr struct
 */
struct nlattr *
nl_msg_start_nested_attr(nl_msg_t *msg, int type);

/**
 * Adjusts the attribute header's length. Should be applied after
 * adding attributes to the nest.
 * @return failure: -1, success: 0
 */
int
nl_msg_end_nested_attr(nl_msg_t *msg, struct nlattr *attr);

/**
 * Expands the length of the netlink message by a len bytes
 * @return failure: -1, success: 0
 */
int
nl_msg_expand_len(nl_msg_t *msg, size_t len);

/**
 * This function adds a buffer attribute of a certain type
 * to the netlink message
 * @return failure: -1, success: 0
 */
int
nl_msg_add_buffer(nl_msg_t *msg, int type, const char *buffer, size_t len);

/**
 * This function adds a string attribute of a certain type
 * to the netlink message
 * @return failure: -1, success: 0
 */
int
nl_msg_add_string(nl_msg_t *msg, int type, const char *str);

/**
 * This function adds a uint32_t attribute of a certain type
 * to the netlink message
 * @return failure: -1, success: 0
 */
int
nl_msg_add_u32(nl_msg_t *msg, int type, uint32_t val);

/**
 * Sets the message payload unaligned according to the given buffer.
 * The message length is adapted accordingly to the size argument.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_buf_unaligned(nl_msg_t *msg, char *buf, size_t size);

/**
 * Sets the request according to the given struct genlmsghdr
 * The message length is adapted accordingly.
 * @return failure: -1, success: 0
 */
int
nl_msg_set_genl_hdr(nl_msg_t *msg, const struct genlmsghdr *hdr);

/**
 * Receives and checks a response from the netlink socket nl
 * The errno is set accordingly, if the recevied message had an error code set.
 * @return failure: -1, success: 0
 */
int
nl_msg_receive_and_check_kernel(const nl_sock_t *nl);

/**
 * Probes the kernel for the given generic netlink family name and returns
 * the corresponding id.
 * @return family id, -1 on error
 * */
uint16_t
nl_genl_family_getid(const char *family_name);

#endif /* NL_H_ */
