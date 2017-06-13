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

#include "network.h"
#include "macro.h"
#include "mem.h"
#include "file.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define IPTABLES_PATH "/sbin/iptables"
#define IP_PATH "/sbin/ip"
#if PLATFORM_VERSION_MAJOR < 5
#define IP_ROUTING_TABLE "main"
#else
//#define IP_ROUTING_TABLE "legacy_system"
//TODO make table lookup by name work
#define IP_ROUTING_TABLE "99"
#endif

#define IP_FORWARD_FILE "/proc/sys/net/ipv4/ip_forward"

static int
network_fork_and_execvp(const char *path, const char * const *argv)
{
	ASSERT(path);
	//ASSERT(argv);	    // on some OSes, argv can be NULL...

	pid_t pid = fork();
	if (pid == -1) {    // error
		ERROR_ERRNO("Could not fork '%s'", path);
	} else if (pid == 0) {	    // child
		// cast away const from char (!) for compatibility with legacy (not so clever) execv API
		// see discussion at http://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html#tag_16_111_08
		execvp(path, (char * const *)argv);
		ERROR_ERRNO("Could not execv '%s'", path);
	} else {
		// parent
		int status;
		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%s'", path);
		} else if (!WIFEXITED(status)) {
			ERROR("Child '%s' terminated abnormally", path);
		} else {
			DEBUG("%s terminated normally", path);
			return WEXITSTATUS(status);
		}
	}
	return -1;
}

static int
network_call_ip(const char *addr, uint32_t subnet, const char *interface, char *action)
{
	char *net = mem_printf("%s/%i", addr, subnet);
	const char * const argv[] = {IP_PATH, "addr", action, net, "dev", interface, NULL};
	int ret = network_fork_and_execvp(IP_PATH, argv);
	mem_free(net);
	return ret;
}

int
network_set_ip_addr_of_interface(const char *addr, uint32_t subnet, const char *interface)
{
	DEBUG("About to configure network interface %s with ip %s and subnet %i", interface, addr, subnet);
	return network_call_ip(addr, subnet, interface, "add");
}

int
network_remove_ip_addr_from_interface(const char *addr, uint32_t subnet, const char *interface)
{
	DEBUG("About to remove ip %s and subnet %i from network interface %s", addr, subnet, interface);
	return network_call_ip(addr, subnet, interface, "del");
}

int
network_setup_default_route(const char *gateway, bool add)
{
	ASSERT(gateway);
	DEBUG("%s default route via %s", add?"Adding":"Deleting", gateway);

	const char * const argv[] = {"ip", "route", add?"replace":"del", "default", "via", gateway, NULL};
	return network_fork_and_execvp(IP_PATH, argv);
}

int
network_setup_route(const char *net_dst, const char *dev, bool add)
{
	ASSERT(net_dst);
	ASSERT(dev);
	DEBUG("%s route to %s via %s", add?"Adding":"Deleting", net_dst, dev);

	const char * const argv[] = {"ip", "route", add?"replace":"del", net_dst, "dev", dev, "table", IP_ROUTING_TABLE, NULL};
	return network_fork_and_execvp(IP_PATH, argv);
}

int
network_iptables(const char *table, const char *chain, const char *net_src, const char *jmp_target, bool add)
{
	ASSERT(table);
	ASSERT(chain);
	ASSERT(net_src);
	ASSERT(jmp_target);

	const char * const argv[] = {IPTABLES_PATH, "-t", table, add?"-I":"-D", chain, "-s", net_src,
		"-j", jmp_target, NULL};
	return network_fork_and_execvp(IPTABLES_PATH, argv);
}

int
network_setup_port_forwarding(const char *srcip, uint16_t srcport, const char *dstip, uint16_t dstport, bool enable)
{
	ASSERT(srcip);
	ASSERT(dstip);

	char *src_port = mem_printf("%" PRIu16, srcport);
	char *dst_port = mem_printf("%" PRIu16, dstport);
	char *dst = mem_printf("%s:%" PRIu16, dstip, dstport);

	DEBUG("%s port forwarding from %s to %s", enable?"Enabling":"Disabling", src_port, dst);

	// forward local port to destination:port
	const char * const argv[] = {IPTABLES_PATH, "-t", "nat", enable?"-I":"-D", "OUTPUT",
		"-s", "127.0.0.1", "-d", "127.0.0.1", "-p", "tcp", "--dport", src_port,
		"-j", "DNAT", "--to-destination", dst, NULL};
	int error = network_fork_and_execvp(IPTABLES_PATH, argv);
	// change source address for forwarded packets
	const char * const argv2[] = {IPTABLES_PATH, "-t", "nat", enable?"-I":"-D", "POSTROUTING",
		"-s", "127.0.0.1", "-d", dstip, "-p", "tcp", "--dport", dst_port,
		"-j", "SNAT", "--to-source", srcip, NULL};
	error |= network_fork_and_execvp(IPTABLES_PATH, argv2);

	mem_free(src_port);
	mem_free(dst_port);
	mem_free(dst);

	return error;
}

int
network_setup_masquerading(const char *subnet, bool enable)
{
	ASSERT(subnet);

	DEBUG("%s IP forwarding from %s", enable?"Enabling":"Disabling", subnet);

	// outgoing
	int error = network_iptables("nat", "POSTROUTING", subnet, "MASQUERADE", enable);
	error |= network_iptables("filter", "FORWARD", subnet, "ACCEPT", enable);
	// incoming
	const char * const argv[] = {IPTABLES_PATH, "-t", "filter", enable?"-I":"-D", "FORWARD",
		"-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED",
		"-j", "ACCEPT", NULL};
	error |= network_fork_and_execvp(IPTABLES_PATH, argv);

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

	const char * const argv[] = {"ip", "link", "delete", dev, NULL};
	return network_fork_and_execvp(IP_PATH, argv);
}

void
network_enable_ip_forwarding(void)
{
	// enable IP forwarding
	if (file_write(IP_FORWARD_FILE, "1", 1) <= 0)
		ERROR_ERRNO("Could not enable IP forwarding.");
	INFO("IP forwarding enabled!");
}

