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

#define LOGF_LOG_MIN_PRIO 2
#define _GNU_SOURCE

#include "network.h"
#include "nl.h"
#include "macro.h"
#include "mem.h"
#include "file.h"
#include "proc.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <linux/netlink.h>

//#define IPTABLES_PATH "/sbin/iptables"
//#define IP_PATH "/sbin/ip"

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

#define MAX_CAP_NUM (CAP_TO_INDEX(CAP_LAST_CAP) + 1)

static int
network_call_ip(const char *addr, uint32_t subnet, const char *interface, char *action)
{
	char *net = mem_printf("%s/%i", addr, subnet);
	const char *const argv[] = { IP_PATH, "addr", action, net, "dev", interface, NULL };
	int ret = proc_fork_and_execvp(argv);
	mem_free(net);
	return ret;
}

int
network_move_link_ns(pid_t src_pid, pid_t dest_pid, const char *interface)
{
	char *src_pid_str = mem_printf("%d", src_pid);
	char *dest_pid_str = mem_printf("%d", dest_pid);
	const char *const argv[] = { NSENTER_PATH, "-t",	 src_pid_str, "-n",
				     IP_PATH,      "link",       "set",       interface,
				     "netns",      dest_pid_str, NULL };
	DEBUG("NSENTER:");
	for (int i = 0; argv[i]; i++)
		DEBUG("-- %s", argv[i]);
	int ret = proc_fork_and_execvp(argv);
	mem_free(src_pid_str);
	mem_free(dest_pid_str);
	return ret;
}

int
network_list_link_ns(pid_t pid, list_t **link_list)
{
	char *command = mem_printf("%s -t %d -n %s link", NSENTER_PATH, pid, IP_PATH);
	FILE *fp;
	int line_size = 1024;
	char *line = mem_new0(char, line_size);

	fp = popen(command, "r");
	if (fp == NULL)
		return -1;

	int n = 0;
	while (fgets(line + n, line_size - n, fp) != NULL) {
		if (n != 0) {
			line[strnlen(line, line_size) - 1] = 0;
			*link_list = list_append(*link_list, mem_strdup(line));
			n = 0;
		} else {
			n = strnlen(line, line_size);
		}
	}
	pclose(fp);
	mem_free(line);
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

	const char *const argv[] = { IP_PATH,   "route",  add ? "replace" : "del",
				     "default", "via",    gateway,
				     "table",   table_id, NULL };
	return proc_fork_and_execvp(argv);
}

int
network_setup_route_table(const char *table_id, const char *net_dst, const char *dev, bool add)
{
	ASSERT(net_dst);
	ASSERT(dev);
	DEBUG("%s route to %s via %s", add ? "Adding" : "Deleting", net_dst, dev);

	const char *const argv[] = { IP_PATH, "route",  add ? "replace" : "del",
				     net_dst, "dev",    dev,
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
network_iptables(const char *table, const char *chain, const char *net_src, const char *jmp_target,
		 bool add)
{
	ASSERT(table);
	ASSERT(chain);
	ASSERT(net_src);
	ASSERT(jmp_target);

	const char *const argv[] = { IPTABLES_PATH, "-t",    table, add ? "-I" : "-D", chain,
				     "-s",	  net_src, "-j",  jmp_target,	NULL };
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

	// forward local port to destination:port
	const char *const argv[] = { IPTABLES_PATH, "-t", "nat",       enable ? "-I" : "-D",
				     "OUTPUT",      "-s", "127.0.0.1", "-d",
				     "127.0.0.1",   "-p", "tcp",       "--dport",
				     src_port,      "-j", "DNAT",      "--to-destination",
				     dst,	   NULL };
	int error = proc_fork_and_execvp(argv);
	// change source address for forwarded packets
	const char *const argv2[] = { IPTABLES_PATH, "-t", "nat",       enable ? "-I" : "-D",
				      "POSTROUTING", "-s", "127.0.0.1", "-d",
				      dstip,	 "-p", "tcp",       "--dport",
				      dst_port,      "-j", "SNAT",      "--to-source",
				      srcip,	 NULL };
	error |= proc_fork_and_execvp(argv2);

	mem_free(src_port);
	mem_free(dst_port);
	mem_free(dst);

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
	mem_free(route_localnet_file);
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

	const char *const argv2[] = { IP_PATH,  "rule",		  "add", "from", "all",
				      "lookup", IP_ROUTING_TABLE, NULL };
	return proc_fork_and_execvp(argv2);
}

list_t *
network_get_physical_interfaces_new()
{
	struct if_nameindex *if_ni, *i;
	if_ni = if_nameindex();

	list_t *if_name_list = NULL;

	IF_NULL_RETVAL(if_ni, NULL);

	for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
		char *dev_drv_path = mem_printf("/sys/class/net/%s/device/driver", i->if_name);
		if (file_exists(dev_drv_path))
			if_name_list = list_append(if_name_list, mem_strdup(i->if_name));
		mem_free(dev_drv_path);
	}
	return if_name_list;
}
