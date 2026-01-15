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

//#define LOGF_LOG_MIN_PRIO 2
#define _GNU_SOURCE

#include "network.h"
#include "nl.h"
#include "macro.h"
#include "mem.h"
#include "file.h"
#include "proc.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#define IPTABLES_PATH "iptables"
#define IP_PATH "ip"
#define NSENTER_PATH "nsenter"

/* routing */
#define IP_ROUTE_LOCALNET_PATH "/proc/sys/net/ipv4/conf/%s/route_localnet"

#if PLATFORM_VERSION_MAJOR < 5
#define IP_ROUTING_TABLE "main"
#else
//#define IP_ROUTING_TABLE "legacy_system"
//TODO make table lookup by name work
#define IP_ROUTING_TABLE "99"
#endif

#define IP_FORWARD_FILE "/proc/sys/net/ipv4/ip_forward"

/* Name of the loopback device */
#define LOOPBACK_NAME "lo"
#define LOOPBACK_OLD_PREFIX 8
#define LOOPBACK_PREFIX 16
#define LOCALHOST_IP "127.0.0.1"

/**
 * Parses an IP address string and detects its address family.
 *
 * @param addr_str The IP address string to parse
 * @param addr Output buffer for parsed address
 * @param family Output: AF_INET or AF_INET6
 * @param addr_size Input: size of the buffer, Output: size of the address (4 for IPv4, 16 for IPv6)
 * @return 0 on success, -1 on failure (including if buffer is too small)
 */
static int
network_parse_addr(const char *addr_str, void *addr, int *family, size_t *addr_size)
{
	IF_TRUE_RETVAL(*addr_size < sizeof(struct in6_addr), -1);

	if (inet_pton(AF_INET, addr_str, addr) == 1) {
		*family = AF_INET;
		*addr_size = sizeof(struct in_addr);
		return 0;
	} else if (inet_pton(AF_INET6, addr_str, addr) == 1) {
		*family = AF_INET6;
		*addr_size = sizeof(struct in6_addr);
		return 0;
	}
	return -1;
}

static int
network_call_ip(const char *addr, uint32_t subnet, const char *interface, char *action)
{
	char *net = mem_printf("%s/%i", addr, subnet);
	const char *const argv[] = { IP_PATH, "addr", action, net, "dev", interface, NULL };
	int ret = proc_fork_and_execvp(argv);
	mem_free0(net);
	return ret;
}

int
network_move_link_ns(pid_t src_pid, pid_t dest_pid, const char *interface)
{
	char *src_pid_str = mem_printf("%d", src_pid);
	char *dest_pid_str = mem_printf("%d", dest_pid);
	const char *const argv[] = { NSENTER_PATH, "-t",	 src_pid_str, "-n",
				     IP_PATH,	   "link",	 "set",	      interface,
				     "netns",	   dest_pid_str, NULL };
	DEBUG("NSENTER:");
	for (int i = 0; argv[i]; i++)
		DEBUG("-- %s", argv[i]);
	int ret = proc_fork_and_execvp(argv);
	mem_free0(src_pid_str);
	mem_free0(dest_pid_str);
	return ret;
}

int
network_list_link_ns(pid_t pid, list_t **link_list)
{
	char *command = mem_printf("%s -t %d -n %s link", NSENTER_PATH, pid, IP_PATH);
	FILE *fp;
	size_t line_size = 1024;
	char *line = mem_new0(char, line_size);

	fp = popen(command, "r");
	mem_free0(command);
	if (fp == NULL) {
		mem_free0(line);
		return -1;
	}

	while (getline(&line, &line_size, fp) != -1) {
		int ifindex;
		if (sscanf(line, "%d: %*s", &ifindex) == 1) {
			// found line with ifindex at beginning, create new list entry
			TRACE("Adding interface with ifindex: %d to list", ifindex);
			*link_list = list_append(*link_list, mem_strdup(line));
		} else if (*link_list != NULL) {
			// no new interface just append string in existing list entry
			list_t *list_end = list_tail(*link_list);
			char *_line = list_end->data;
			list_end->data = mem_printf("%s%s", _line, line);
			mem_free0(_line);
		}
	}
	pclose(fp);
	mem_free0(line);
	return 0;
}

int
network_set_ip_addr_of_interface(const char *addr, uint32_t subnet, const char *interface)
{
	DEBUG("About to configure network interface %s with ip %s and subnet %i", interface, addr,
	      subnet);
	return network_call_ip(addr, subnet, interface, "add");
}

int
network_remove_ip_addr_from_interface(const char *addr, uint32_t subnet, const char *interface)
{
	DEBUG("About to remove ip %s and subnet %i from network interface %s", addr, subnet,
	      interface);
	return network_call_ip(addr, subnet, interface, "del");
}

int
network_setup_default_route(const char *gateway, bool add)
{
	ASSERT(gateway);
	DEBUG("%s default route via %s", add ? "Adding" : "Deleting", gateway);

	const char *const argv[] = { IP_PATH, "route", add ? "replace" : "del", "default", "via",
				     gateway, NULL };
	return proc_fork_and_execvp(argv);
}

int
network_setup_default_route_table(const char *table_id, const char *gateway, bool add)
{
	ASSERT(gateway);
	DEBUG("%s default route via %s", add ? "Adding" : "Deleting", gateway);

	const char *const argv[] = { IP_PATH,	"route",  add ? "replace" : "del",
				     "default", "via",	  gateway,
				     "table",	table_id, NULL };
	return proc_fork_and_execvp(argv);
}

int
network_setup_route_table(const char *table_id, const char *net_dst, const char *dev, bool add)
{
	ASSERT(net_dst);
	ASSERT(dev);
	DEBUG("%s route to %s via %s", add ? "Adding" : "Deleting", net_dst, dev);

	const char *const argv[] = { IP_PATH, "route",	add ? "replace" : "del",
				     net_dst, "dev",	dev,
				     "table", table_id, NULL };
	return proc_fork_and_execvp(argv);
}

int
network_setup_route(const char *net_dst, const char *dev, bool add)
{
	ASSERT(net_dst);
	ASSERT(dev);
	DEBUG("%s route to %s via %s", add ? "Adding" : "Deleting", net_dst, dev);

	const char *const argv[] = { IP_PATH, "route", add ? "replace" : "del", net_dst, "dev",
				     dev,     "table", IP_ROUTING_TABLE,	NULL };
	return proc_fork_and_execvp(argv);
}

int
network_add_routing_rule(uint32_t table_id, int family, uint32_t priority)
{
	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;

	DEBUG("Adding routing policy rule: from all lookup %u priority %u (family %s)", table_id,
	      priority, (family == AF_INET6) ? "inet6" : "inet");

	nl_sock = nl_sock_routing_new();
	if (!nl_sock) {
		ERROR("Failed to create netlink routing socket");
		return -1;
	}

	req = nl_msg_new();
	if (!req) {
		ERROR("Failed to allocate netlink message for routing rule");
		goto err;
	}

	struct fib_rule_hdr rule = { .family = family,
				     .dst_len = 0,
				     .src_len = 0,
				     .tos = 0,
				     .table = RT_TABLE_UNSPEC,
				     .action = FR_ACT_TO_TBL,
				     .flags = 0 };

	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, RTM_NEWRULE), err);
	IF_TRUE_GOTO_ERROR(
		nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_rule_req(req, &rule), err);

	if (nl_msg_add_u32(req, FRA_TABLE, table_id) < 0) {
		ERROR("Failed to add FRA_TABLE attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, FRA_PRIORITY, priority) < 0) {
		ERROR("Failed to add FRA_PRIORITY attribute");
		goto err;
	}

	if (nl_msg_send_kernel_verify(nl_sock, req) < 0) {
		if (errno == EEXIST) {
			DEBUG("Routing rule for table %u already exists (family %s), continuing",
			      table_id, (family == AF_INET6) ? "inet6" : "inet");
		} else {
			ERROR("Failed to add routing rule for table %u", table_id);
			goto err;
		}
	}

	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return 0;

err:
	if (req)
		nl_msg_free(req);
	if (nl_sock)
		nl_sock_free(nl_sock);
	return -1;
}

int
network_remove_routing_rule(uint32_t table_id, int family, uint32_t priority)
{
	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;

	DEBUG("Removing routing policy rule: from all lookup %u priority %u (family %s)", table_id,
	      priority, (family == AF_INET6) ? "inet6" : "inet");

	nl_sock = nl_sock_routing_new();
	if (!nl_sock) {
		ERROR("Failed to create netlink routing socket");
		return -1;
	}

	req = nl_msg_new();
	if (!req) {
		ERROR("Failed to create netlink message for rule deletion");
		goto err;
	}

	struct fib_rule_hdr rule = { .family = family,
				     .dst_len = 0,
				     .src_len = 0,
				     .tos = 0,
				     .table = RT_TABLE_UNSPEC,
				     .action = FR_ACT_TO_TBL,
				     .flags = 0 };

	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, RTM_DELRULE), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_rule_req(req, &rule), err);

	if (nl_msg_add_u32(req, FRA_TABLE, table_id) < 0) {
		ERROR("Failed to add FRA_TABLE attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, FRA_PRIORITY, priority) < 0) {
		ERROR("Failed to add FRA_PRIORITY attribute");
		goto err;
	}

	if (nl_msg_send_kernel_verify(nl_sock, req) < 0) {
		if (errno == ENOENT || errno == ESRCH) {
			DEBUG("Routing rule for table %u doesn't exist (family %s), continuing",
			      table_id, (family == AF_INET6) ? "inet6" : "inet");
		} else {
			WARN("Failed to delete routing rule for table %u", table_id);
			goto err;
		}
	}

	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return 0;

err:
	if (req)
		nl_msg_free(req);
	if (nl_sock)
		nl_sock_free(nl_sock);
	return -1;
}

int
network_add_route_to_table(uint32_t table_id, const char *dest_network, uint8_t prefix_len,
			   const char *gateway, const char *dev)
{
	ASSERT(dest_network);
	ASSERT(gateway);
	ASSERT(dev);

	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;
	int family;
	size_t addr_size = sizeof(struct in6_addr);
	struct in6_addr dst_addr, gw_addr;

	if (network_parse_addr(dest_network, &dst_addr, &family, &addr_size) < 0) {
		ERROR("Invalid destination network address: %s", dest_network);
		return -1;
	}

	if (inet_pton(family, gateway, &gw_addr) != 1) {
		ERROR("Invalid gateway address %s (expected %s)", gateway,
		      (family == AF_INET) ? "IPv4" : "IPv6");
		return -1;
	}

	unsigned int if_index = if_nametoindex(dev);
	if (if_index == 0) {
		ERROR("Failed to get interface index for %s", dev);
		return -1;
	}

	DEBUG("Adding route %s/%u via %s dev %s to table %u", dest_network, prefix_len, gateway,
	      dev, table_id);

	nl_sock = nl_sock_routing_new();
	if (!nl_sock) {
		ERROR("Failed to create netlink routing socket");
		return -1;
	}

	req = nl_msg_new();
	if (!req) {
		ERROR("Failed to allocate netlink message for route");
		goto err;
	}

	struct rtmsg rtmsg = { .rtm_family = family,
			       .rtm_dst_len = prefix_len,
			       .rtm_src_len = 0,
			       .rtm_tos = 0,
			       .rtm_table = RT_TABLE_UNSPEC,
			       .rtm_protocol = RTPROT_STATIC,
			       .rtm_scope = RT_SCOPE_UNIVERSE,
			       .rtm_type = RTN_UNICAST,
			       .rtm_flags = 0 };

	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, RTM_NEWROUTE), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE |
							 NLM_F_REPLACE),
			   err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_rt_req(req, &rtmsg), err);

	if (nl_msg_add_buffer(req, RTA_DST, (const char *)&dst_addr, addr_size) < 0) {
		ERROR("Failed to add RTA_DST attribute");
		goto err;
	}
	if (nl_msg_add_buffer(req, RTA_GATEWAY, (const char *)&gw_addr, addr_size) < 0) {
		ERROR("Failed to add RTA_GATEWAY attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, RTA_OIF, if_index) < 0) {
		ERROR("Failed to add RTA_OIF attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, RTA_TABLE, table_id) < 0) {
		ERROR("Failed to add RTA_TABLE attribute");
		goto err;
	}

	if (nl_msg_send_kernel_verify(nl_sock, req) < 0) {
		ERROR("Failed to add route to table %u", table_id);
		goto err;
	}

	nl_msg_free(req);
	nl_sock_free(nl_sock);
	DEBUG("Successfully added route %s/%u via %s dev %s to table %u", dest_network, prefix_len,
	      gateway, dev, table_id);
	return 0;

err:
	if (req)
		nl_msg_free(req);
	if (nl_sock)
		nl_sock_free(nl_sock);
	return -1;
}

int
network_remove_route_from_table(uint32_t table_id, const char *dest_network, uint8_t prefix_len,
				const char *gateway, const char *dev)
{
	ASSERT(dest_network);
	ASSERT(gateway);
	ASSERT(dev);

	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;
	int family;
	size_t addr_size = sizeof(struct in6_addr);
	struct in6_addr dst_addr, gw_addr;

	if (network_parse_addr(dest_network, &dst_addr, &family, &addr_size) < 0) {
		ERROR("Invalid destination network address: %s", dest_network);
		return -1;
	}

	if (inet_pton(family, gateway, &gw_addr) != 1) {
		ERROR("Invalid gateway address %s (expected %s)", gateway,
		      (family == AF_INET) ? "IPv4" : "IPv6");
		return -1;
	}

	unsigned int if_index = if_nametoindex(dev);
	if (if_index == 0) {
		ERROR_ERRNO("Failed to get interface index for %s", dev);
		return -1;
	}

	DEBUG("Removing route %s/%u via %s dev %s from table %u", dest_network, prefix_len, gateway,
	      dev, table_id);

	nl_sock = nl_sock_routing_new();
	if (!nl_sock) {
		ERROR("Failed to create netlink routing socket");
		return -1;
	}

	req = nl_msg_new();
	if (!req) {
		ERROR("Failed to create netlink message");
		goto err;
	}

	struct rtmsg rtmsg = { .rtm_family = family,
			       .rtm_dst_len = prefix_len,
			       .rtm_src_len = 0,
			       .rtm_tos = 0,
			       .rtm_table = RT_TABLE_UNSPEC,
			       .rtm_protocol = RTPROT_STATIC,
			       .rtm_scope = RT_SCOPE_UNIVERSE,
			       .rtm_type = RTN_UNICAST,
			       .rtm_flags = 0 };

	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, RTM_DELROUTE), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK), err);
	IF_TRUE_GOTO_ERROR(nl_msg_set_rt_req(req, &rtmsg), err);

	if (nl_msg_add_buffer(req, RTA_DST, (const char *)&dst_addr, addr_size) < 0) {
		ERROR("Failed to add RTA_DST attribute");
		goto err;
	}
	if (nl_msg_add_buffer(req, RTA_GATEWAY, (const char *)&gw_addr, addr_size) < 0) {
		ERROR("Failed to add RTA_GATEWAY attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, RTA_OIF, if_index) < 0) {
		ERROR("Failed to add RTA_OIF attribute");
		goto err;
	}
	if (nl_msg_add_u32(req, RTA_TABLE, table_id) < 0) {
		ERROR("Failed to add RTA_TABLE attribute");
		goto err;
	}

	if (nl_msg_send_kernel_verify(nl_sock, req) < 0) {
		ERROR("Failed to delete route from table %u", table_id);
		goto err;
	}

	nl_msg_free(req);
	nl_sock_free(nl_sock);
	DEBUG("Successfully deleted route %s/%u from table %u", dest_network, prefix_len, table_id);
	return 0;

err:
	if (req)
		nl_msg_free(req);
	if (nl_sock)
		nl_sock_free(nl_sock);
	return -1;
}

int
network_iptables(const char *table, const char *chain, const char *net_src, const char *jmp_target,
		 bool add)
{
	ASSERT(table);
	ASSERT(chain);
	ASSERT(net_src);
	ASSERT(jmp_target);

	const char *const argv[] = { IPTABLES_PATH, "-t",    table, add ? "-I" : "-D", chain,
				     "-s",	    net_src, "-j",  jmp_target,	       NULL };
	return proc_fork_and_execvp(argv);
}

int
network_setup_port_forwarding(const char *srcip, uint16_t srcport, const char *dstip,
			      uint16_t dstport, bool enable)
{
	ASSERT(srcip);
	ASSERT(dstip);

	char *src_port = mem_printf("%" PRIu16, srcport);
	char *dst_port = mem_printf("%" PRIu16, dstport);
	char *dst = mem_printf("%s:%" PRIu16, dstip, dstport);

	DEBUG("%s port forwarding from %s to %s", enable ? "Enabling" : "Disabling", src_port, dst);

	// forward public port to destination:port
	const char *const argv[] = { IPTABLES_PATH, "-t", "nat",      enable ? "-I" : "-D",
				     "PREROUTING",  "-p", "tcp",      "--dport",
				     src_port,	    "-m", "addrtype", "--dst-type",
				     "LOCAL",	    "-j", "DNAT",     "--to-destination",
				     dst,	    NULL };
	int error = proc_fork_and_execvp(argv);

	// change source address for forwarded packets
	const char *const argv2[] = { IPTABLES_PATH, "-t",	    "nat",    enable ? "-I" : "-D",
				      "POSTROUTING", "-d",	    dstip,    "-p",
				      "tcp",	     "--dport",	    dst_port, "-j",
				      "SNAT",	     "--to-source", srcip,    NULL };
	error |= proc_fork_and_execvp(argv2);

	mem_free0(src_port);
	mem_free0(dst_port);
	mem_free0(dst);

	return error;
}

int
network_setup_masquerading(const char *subnet, bool enable)
{
	ASSERT(subnet);

	DEBUG("%s IP forwarding from %s", enable ? "Enabling" : "Disabling", subnet);

	// outgoing
	int error = network_iptables("nat", "POSTROUTING", subnet, "MASQUERADE", enable);
	error |= network_iptables("filter", "FORWARD", subnet, "ACCEPT", enable);
	// incoming
	const char *const argv[] = { IPTABLES_PATH,
				     "-t",
				     "filter",
				     enable ? "-I" : "-D",
				     "FORWARD",
				     "-d",
				     subnet,
				     "-m",
				     "state",
				     "--state",
				     "RELATED,ESTABLISHED",
				     "-j",
				     "ACCEPT",
				     NULL };
	error |= proc_fork_and_execvp(argv);

	if (error) {
		ERROR("Failed to setup IP forwarding from %s", subnet);
		return -1;
	}

	return 0;
}

int
network_delete_link(const char *dev)
{
	ASSERT(dev);
	DEBUG("Destroying network interface %s", dev);

	const char *const argv[] = { IP_PATH, "link", "delete", dev, NULL };
	return proc_fork_and_execvp(argv);
}

void
network_enable_ip_forwarding(void)
{
	// enable IP forwarding
	if (file_write(IP_FORWARD_FILE, "1", 1) <= 0) {
		ERROR_ERRNO("Could not enable IP forwarding.");
		return;
	}
	INFO("IP forwarding enabled!");
}

/**
 * This function brings the network interface ifi_name either ip or down,
 * using either the flag IFF_UP or IFF_DOWN
 * with a netlink message using the netlink socket.
 */
int
network_set_flag(const char *ifi_name, const uint32_t flag)
{
	ASSERT(ifi_name && (flag == IFF_UP || flag == IFF_DOWN));

	DEBUG("Bringing %s interface \"%s\"", flag == IFF_UP ? "up" : "down", ifi_name);

	nl_sock_t *nl_sock = NULL;
	unsigned int ifi_index;
	nl_msg_t *req = NULL;

	/* Get the interface index of the interface name */
	if (!(ifi_index = if_nametoindex(ifi_name))) {
		ERROR("net interface name '%s' could not be resolved", ifi_name);
		return -1;
	}

	/* Open netlink socket */
	if (!(nl_sock = nl_sock_routing_new())) {
		ERROR("failed to allocate netlink socket");
		return -1;
	}

	/* Create netlink message */
	if (!(req = nl_msg_new())) {
		ERROR("failed to allocate netlink message");
		nl_sock_free(nl_sock);
		return -1;
	}

	/* Prepare the request message */
	struct ifinfomsg link_req = { .ifi_family = AF_INET,
				      .ifi_index = ifi_index, /* The index of the interface */
				      .ifi_change = flag,
				      .ifi_flags = flag };

	/* Fill netlink message header */
	if (nl_msg_set_type(req, RTM_NEWLINK))
		goto msg_err;

	/* Set appropriate flags for request, creating new object, exclusive access and acknowledgment response */
	if (nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK))
		goto msg_err;

	/* Fill link request header of request message */
	if (nl_msg_set_link_req(req, &link_req))
		goto msg_err;

	/* Send request message and wait for the response message */
	if (nl_msg_send_kernel_verify(nl_sock, req))
		goto msg_err;

	nl_msg_free(req);
	nl_sock_free(nl_sock);

	return 0;

msg_err:
	ERROR("failed to create/send netlink message");
	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return -1;
}

#ifdef USE_LOCALNET_ROUTING
/**
 * Enable or disable localnet routing for the given interface.
 */
static int
network_route_localnet(const char *interface, bool enable)
{
	char *route_localnet_file = mem_printf(IP_ROUTE_LOCALNET_PATH, interface);
	int error = 0;
	if (file_write(route_localnet_file, enable ? "1" : "0", 1) <= 0) {
		ERROR_ERRNO("Could not %s localnet routing for %s", enable ? "enable" : "disable",
			    interface);
		error = -1;
	}
	mem_free0(route_localnet_file);
	return error;
}
#endif

/**
 * Bring up the loopback interface and shrink its subnet.
 */
int
network_setup_loopback()
{
	int ret = 0;

	// bring interface up (no additional route necessary)
	if (network_set_flag(LOOPBACK_NAME, IFF_UP))
		return -1;
#ifdef USE_LOCALNET_ROUTING
	(void)network_remove_ip_addr_from_interface(LOCALHOST_IP, LOOPBACK_OLD_PREFIX,
						    LOOPBACK_NAME);
	ret = network_set_ip_addr_of_interface(LOCALHOST_IP, LOOPBACK_PREFIX, LOOPBACK_NAME);

	// enable localnet routing for all interfaces
	ret |= network_route_localnet("all", true);
#endif

	return ret;
}

int
network_routing_rules_set_all_main(bool flush)
{
	if (flush) {
		DEBUG("Flushing all ip routing rules!");
		const char *const argv[] = { IP_PATH, "rule", "flush", NULL };
		if (proc_fork_and_execvp(argv))
			WARN("Failed to flush routing rules");
	}

	DEBUG("Set rule to route all traffic through table %s", IP_ROUTING_TABLE);

	const char *const argv2[] = { IP_PATH,	"rule",		  "add", "from", "all",
				      "lookup", IP_ROUTING_TABLE, NULL };
	return proc_fork_and_execvp(argv2);
}

bool
network_interface_is_wifi(const char *if_name)
{
	bool ret;
	char *phy_path;

	phy_path = mem_printf("/sys/class/net/%s/phy80211", if_name);
	ret = file_exists(phy_path);
	mem_free0(phy_path);

	return ret;
}

list_t *
network_get_interfaces_new()
{
	struct if_nameindex *if_ni, *i;
	if_ni = if_nameindex();

	IF_NULL_RETVAL_ERROR_ERRNO(if_ni, NULL);

	list_t *if_name_list = NULL;

	for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
		if_name_list = list_append(if_name_list, mem_strdup(i->if_name));
	}
	if_freenameindex(if_ni);
	return if_name_list;
}

list_t *
network_get_physical_interfaces_new()
{
	struct if_nameindex *if_ni, *i;
	if_ni = if_nameindex();

	IF_NULL_RETVAL_ERROR_ERRNO(if_ni, NULL);

	list_t *if_name_list = NULL;

	for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
		char *dev_drv_path = mem_printf("/sys/class/net/%s/device/driver", i->if_name);
		if (file_exists(dev_drv_path) && i->if_name != NULL) {
			DEBUG("Adding %s to the physical device list", i->if_name);
			if_name_list = list_append(if_name_list, mem_strdup(i->if_name));
		} else if (file_exists(dev_drv_path)) {
			DEBUG("Skipping unnamed network interface with index %d", i->if_index);
		} else {
			DEBUG("Skipping %d: Not a physical network interface", i->if_index);
		}
		mem_free0(dev_drv_path);
	}
	if_freenameindex(if_ni);
	return if_name_list;
}

/**
 * lookup the index of the phy interface coresponding to
 * the wifi interface with if_name, e.g. wlan0
 */
static int
network_nl80211_get_index(const char *if_name)
{
	int phy_index = -1;
	char *phy_file = NULL;
	char *dev_phy_path = mem_printf("/sys/class/net/%s/phy80211/index", if_name);

	phy_file = file_read_new(dev_phy_path, 128);
	IF_NULL_GOTO_ERROR(phy_file, out);

	phy_index = atoi(phy_file);

out:
	mem_free0(phy_file);
	mem_free0(dev_phy_path);
	return phy_index;
}

int
network_nl80211_move_ns(const char *if_name, const pid_t pid)
{
	ASSERT(if_name);

	DEBUG("Move %s interface to netns of pid %d", if_name, pid);

	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;

	int if_index = network_nl80211_get_index(if_name);
	IF_TRUE_RETVAL_ERROR(if_index < 0, -1);

	int nl80211_id = nl_genl_family_getid(NL80211_GENL_NAME);
	IF_TRUE_RETVAL_ERROR(nl80211_id < GENL_MIN_ID, -1);

	/* Open netlink socket */
	nl_sock = nl_sock_default_new(NETLINK_GENERIC);
	IF_NULL_RETVAL_ERROR(nl_sock, -1);

	/* Create netlink message */
	req = nl_msg_new();
	IF_NULL_GOTO_ERROR(req, msg_err);

	/* Prepare the generic netlink message header */
	struct genlmsghdr hdr = {
		.cmd = NL80211_CMD_SET_WIPHY_NETNS,
		.version = 1,
	};

	/* Fill netlink message header */
	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, nl80211_id), msg_err);

	/* Set appropriate flags for request, creating new object,
	 * exclusive access and acknowledgment response */
	IF_TRUE_GOTO_ERROR(nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK), msg_err);

	/* Fill generic netlink message header */
	IF_TRUE_GOTO_ERROR(nl_msg_set_genl_hdr(req, &hdr), msg_err);

	/* Set generic netlink attributes */
	IF_TRUE_GOTO_ERROR(nl_msg_add_u32(req, NL80211_ATTR_WIPHY, if_index), msg_err);
	IF_TRUE_GOTO_ERROR(nl_msg_add_u32(req, NL80211_ATTR_PID, pid), msg_err);

	/* Send request message and wait for the response message */
	IF_TRUE_GOTO_ERROR(nl_msg_send_kernel_verify(nl_sock, req), msg_err);

	nl_msg_free(req);
	nl_sock_free(nl_sock);

	return 0;

msg_err:
	ERROR("failed to create/send netlink message");
	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return -1;
}

int
network_rtnet_move_ns(const char *ifi_name, const pid_t pid)
{
	ASSERT(ifi_name);

	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;

	/* Get the interface index of the interface name */
	unsigned int ifi_index = if_nametoindex(ifi_name);
	IF_FALSE_RETVAL_ERROR(ifi_index, -1);

	/* Open netlink socket */
	nl_sock = nl_sock_routing_new();
	IF_NULL_RETVAL_ERROR(nl_sock, -1);

	/* Create netlink message */
	req = nl_msg_new();
	IF_NULL_GOTO_ERROR(req, msg_err);

	/* Prepare the request message */
	struct ifinfomsg link_req = {
		.ifi_family = AF_INET, .ifi_index = ifi_index /* The index of the interface */
	};

	/* Fill netlink message header */
	IF_TRUE_GOTO_ERROR(nl_msg_set_type(req, RTM_NEWLINK), msg_err);

	/* Set appropriate flags for request, creating new object,
	 * exclusive access and acknowledgment response */
	IF_TRUE_GOTO_ERROR(nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK), msg_err);

	/* Fill link request header of request message */
	IF_TRUE_GOTO_ERROR(nl_msg_set_link_req(req, &link_req), msg_err);

	/* Set the PID in the netlink header */
	IF_TRUE_GOTO_ERROR(nl_msg_add_u32(req, IFLA_NET_NS_PID, pid), msg_err);

	/* Send request message and wait for the response message */
	IF_TRUE_GOTO_ERROR(nl_msg_send_kernel_verify(nl_sock, req), msg_err);

	nl_msg_free(req);
	nl_sock_free(nl_sock);

	return 0;

msg_err:
	ERROR("failed to create/send netlink message");
	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return -1;
}

int
network_rename_ifi(const char *old_ifi_name, const char *new_ifi_name)
{
	ASSERT(old_ifi_name && new_ifi_name);

	nl_sock_t *nl_sock = NULL;
	unsigned int ifi_index_old;
	nl_msg_t *req = NULL;

	/* Get the interface index of the interface name */
	if (!(ifi_index_old = if_nametoindex(old_ifi_name))) {
		ERROR("veth interface name could not be resolved");
		return -1;
	}

	/* Open netlink socket */
	if (!(nl_sock = nl_sock_routing_new())) {
		ERROR("failed to allocate netlink socket");
		return -1;
	}

	/* Create netlink message */
	if (!(req = nl_msg_new())) {
		ERROR("failed to allocate netlink message");
		nl_sock_free(nl_sock);
		return -1;
	}

	struct ifinfomsg link_req = { .ifi_family = AF_INET, .ifi_index = ifi_index_old };

	/* Fill netlink message header */
	if (nl_msg_set_type(req, RTM_NEWLINK))
		goto msg_err;

	/* Set appropriate flags for request, creating new object,
	 *  exclusive access and acknowledgment response */
	if (nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK))
		goto msg_err;

	/* Fill link request header of request message */
	if (nl_msg_set_link_req(req, &link_req))
		goto msg_err;

	/* Set the PID in the netlink header */
	if (nl_msg_add_string(req, IFLA_IFNAME, new_ifi_name))
		goto msg_err;

	/* Send request message and wait for the response message */
	if (nl_msg_send_kernel_verify(nl_sock, req))
		goto msg_err;

	nl_msg_free(req);
	nl_sock_free(nl_sock);

	return 0;

msg_err:
	ERROR("failed to create/send netlink message");
	nl_msg_free(req);
	nl_sock_free(nl_sock);
	return -1;
}

int
network_str_to_mac_addr(const char *mac_str, uint8_t mac[6])
{
	IF_NULL_RETVAL(mac_str, -1);

	int ret =
		sscanf(mac_str,
		       "%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8,
		       &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	IF_TRUE_RETVAL((ret == EOF || ret < 6), -1);

	return 0;
}

char *
network_mac_addr_to_str_new(uint8_t mac[6])
{
	return mem_printf("%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8 ":%02" SCNx8
			  ":%02" SCNx8,
			  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int
network_get_mac_by_ifname(const char *ifname, uint8_t mac[6])
{
	IF_NULL_RETVAL(ifname, -1);
	IF_NULL_RETVAL(mac, -1);

	char *dev_addr_path = mem_printf("/sys/class/net/%s/address", ifname);
	char *mac_str = file_read_new(dev_addr_path, 128);
	mem_free0(dev_addr_path);

	IF_NULL_RETVAL(mac_str, -1);

	mem_memset(mac, 0, 6);
	int ret = network_str_to_mac_addr(mac_str, mac);

	mem_free0(mac_str);
	return ret;
}

char *
network_get_ifname_by_addr_new(uint8_t mac[6])
{
	IF_NULL_RETVAL(mac, NULL);

	struct if_nameindex *if_ni, *i;
	if_ni = if_nameindex();

	IF_NULL_RETVAL(if_ni, NULL);

	uint8_t mac_i[6];

	for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
		char *dev_addr_path, *dev_bridge_path, *mac_str;

		// check whether matching device is a bridge
		dev_bridge_path = mem_printf("/sys/class/net/%s/bridge", i->if_name);

		if (file_is_dir(dev_bridge_path)) {
			DEBUG("Matched bridge interface, continue searching");
			mem_free0(dev_bridge_path);

			continue;
		}
		mem_free0(dev_bridge_path);

		dev_addr_path = mem_printf("/sys/class/net/%s/address", i->if_name);
		mac_str = file_read_new(dev_addr_path, 128);
		mem_free0(dev_addr_path);

		if (mac_str == NULL)
			continue;

		mem_memset(mac_i, 0, 6);

		if ((0 == network_str_to_mac_addr(mac_str, mac_i)) &&
		    (0 == memcmp(mac, mac_i, 6))) {
			mem_free0(mac_str);
			return mem_strdup(i->if_name);
		}

		mem_free0(mac_str);
	}

	return NULL;
}

int
network_create_bridge(const char *name)
{
	IF_NULL_RETVAL_ERROR(name, -1);

	const char *const argv[] = { IP_PATH, "link", "add", "name", name, "type", "bridge", NULL };
	int ret = proc_fork_and_execvp(argv);
	return ret;
}

/**
 * Adds an interface to a bridge.
 */
int
network_bridge_add_port(const char *br_name, const char *prt_name)
{
	IF_NULL_RETVAL_ERROR(br_name, -1);
	IF_NULL_RETVAL_ERROR(prt_name, -1);

	const char *const argv[] = { IP_PATH,  "link",	 "set",	  "dev",
				     prt_name, "master", br_name, NULL };
	int ret = proc_fork_and_execvp(argv);
	return ret;
}

int
network_bridge_remove_port(const char *br_name)
{
	IF_NULL_RETVAL_ERROR(br_name, -1);

	const char *const argv[] = { IP_PATH, "link", "set", br_name, "nomaster", NULL };
	int ret = proc_fork_and_execvp(argv);
	return ret;
}

int
network_bridge_set_up(const char *br_name)
{
	IF_NULL_RETVAL_ERROR(br_name, -1);

	const char *const argv[] = { IP_PATH, "link", "set", "dev", br_name, "up", NULL };
	int ret = proc_fork_and_execvp(argv);
	return ret;
}

int
network_delete_bridge(const char *name)
{
	IF_NULL_RETVAL_ERROR(name, -1);

	const char *const argv[] = { IP_PATH, "link", "delete", name, "type", "bridge", NULL };
	int ret = proc_fork_and_execvp(argv);
	return ret;
}

int
network_iptables_phys_deny(const char *chain, const char *netif, bool add)
{
	ASSERT(netif);

	const char *const argv[] = { IPTABLES_PATH, add ? "-I" : "-D",
				     chain,	    "-m",
				     "physdev",	    "--physdev-in",
				     netif,	    "-j",
				     "DROP",	    NULL };

	return proc_fork_and_execvp(argv);
}

int
network_phys_allow_mac(const char *chain, const char *netif, uint8_t mac[6], bool add)
{
	ASSERT(netif);

	char *mac_str = network_mac_addr_to_str_new(mac);
	const char *const argv[] = { IPTABLES_PATH, add ? "-I" : "-D",
				     chain,	    "-m",
				     "physdev",	    "--physdev-in",
				     netif,	    "-m",
				     "mac",	    "--mac-source",
				     mac_str,	    "-j",
				     "ACCEPT",	    NULL };

	int ret = proc_fork_and_execvp(argv);

	mem_free0(mac_str);
	return ret;
}
