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
 * @file c_net.c
 *
 * This module is responsible for the network setup of containers. It
 * provides interfaces to such networking tasks that have to be executed
 * at the startup of containers. It is e.g. responsible for moving interfaces to different network namespaces,
 * or to set ipv4/gateway/mac addresses. It makes heavy usage of the netlink module.
 */

#define _GNU_SOURCE

#define MOD_NAME "c_net"

#include <sched.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <inttypes.h>
#include <signal.h>

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/list.h"
#include "common/nl.h"
#include "common/ns.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/network.h"
#include "common/proc.h"
#include "common/event.h"
#include "common/ns.h"
#include "container.h"
#include "cmld.h"
#include "hotplug.h"

/* Offset for ipv4/mac address allocation, e.g. 127.1.(IPV4_SUBNET_OFFS+x).2
 * Defines the start value for address allocation */
// TODO: we can possibly run into collisions (increment in get next ip function if ip request fails
#define IPV4_SUBNET_OFFS 0

/* Max number of network structures that can be allocated depends on the available subnets */
#define MAX_NUM_DEVICES (255 - IPV4_SUBNET_OFFS)

/* Path to search for net devices */
#define SYS_NET_PATH "/sys/class/net"

/* ipv4 addresses for cmld and cont endpoints, where the subnet depends on the container */
#ifdef USE_LOCALNET_ROUTING
#define IPV4_CMLD_ADDRESS "127.1.%d.1"
#define IPV4_CONT_ADDRESS "127.1.%d.2"
#define IPV4_DHCP_RANGE_START "127.1.%d.50"
#define IPV4_DHCP_RANGE_END "127.1.%d.61"
#else
#define IPV4_CMLD_ADDRESS "172.23.%d.1"
#define IPV4_CONT_ADDRESS "172.23.%d.2"
#define IPV4_DHCP_RANGE_START "172.23.%d.2"
#define IPV4_DHCP_RANGE_END "172.23.%d.12"
#define IPV4_DHCP_MASK "255.255.255.0"
#endif

// uplink interface for cmld inside of routing container (c0)
#define CML_UPLINK_INTERFACE_NAME "cml"

/* Network prefix */
#define IPV4_PREFIX 24

/* Port numbers for SSH access to cml in debug build.
 * CML_SSH_PORT_C0 gets forwarded to CML_SSH_PORT_CML */
#define CML_SSH_PORT_CML 22
#define CML_SSH_PORT_C0 2222

/* Network interface structure with interface specific settings */
typedef struct {
	char *nw_name;		       //!< Name of the network device
	char *nw_name_cmld;	       //!< Name of the network device in rootns
	bool configure;		       //!< do ip/routing configuration
	char *veth_cmld_name;	       //!< associated veth name in root ns
	char *veth_cont_name;	       //!< veth name in the container's ns
	char *subnet;		       //!< string with subnet (x.x.x.x/y)
	struct in_addr ipv4_cmld_addr; //!< associated ipv4 address in root ns
	struct in_addr ipv4_cont_addr; //!< ipv4 address of container
	struct in_addr ipv4_bc_addr;   //!< ipv4 bcaddr of container/cmld subnet
	int cont_offset;	       //!< gives information about the adresses to be set
	uint8_t veth_mac[6];	       //!< generated or configured mac of nic in container
	int veth_cmld_idx;	       //!< Index of veth endpoint in rootns
} c_net_interface_t;

/* Network structure with specific network settings */
typedef struct c_net {
	container_t *container; //!< container which the c_net struct is associated to
	list_t *interface_list; //!< contains list of settings for different nw interfaces
	list_t *pnet_mv_list; //!< contains list of phyiscal NICs to be bridged via a veth or moved into a container. MAC adress filtering may be applied
	char *ns_path;	      //!< path for binding netns into filesystem
	int fd_netns;	      //!< fd to keep netns active during reboots
	list_t *hotplug_registered_mac_list; //!< contains list of macs which are registered at hotplug module
} c_net_t;

/**
 * bool array, which globally holds assigend offsets in order to
 * determine a new offset for a starting container.
 * address_offsets[i]==true means that a container holds this offset to get its specific ip address
 */
static bool *address_offsets = NULL;

/**
 * sets the offset at the specified position to false.
 * indicates that a container releases its addresses.
 */
static void
c_net_unset_offset(int offset)
{
	ASSERT(offset >= 0 && offset < MAX_NUM_DEVICES);
	TRACE("Offset %d released by a container", offset);

	address_offsets[offset] = false;
}

/**
 * determines first free slot and occupies it. Also responsible for allocating the offsets array.
 * @return failure, return -1, else return first free offset
 */
static int
c_net_set_next_offset(void)
{
	if (!address_offsets) {
		address_offsets = mem_new0(bool, MAX_NUM_DEVICES);
		address_offsets[0] = true;
		TRACE("Offset 0 ocupied by a container");
		return 0;
	}

	for (int i = 0; i < MAX_NUM_DEVICES; i++) {
		if (!address_offsets[i]) {
			TRACE("Offset %d occupied by a container", i);
			address_offsets[i] = true;
			return i;
		}
	}

	DEBUG("Unable to provide a valid ip address for c_net");
	return -1;
}

/**
 * This function determines and sets the next available ipv4 address, depending on the container offset.
 * The ipv4 address relates to the ipv4 in the root namespace.
 */
static int
c_net_get_next_ipv4_cmld_addr(int offset, struct in_addr *ipv4_addr)
{
	ASSERT(ipv4_addr);

	char *ipv4_next = mem_printf(IPV4_CMLD_ADDRESS, offset + IPV4_SUBNET_OFFS);

	if (!ipv4_next) {
		ERROR("failed to allocate ipv4 address string");
		return -1;
	}

	if (!inet_aton(ipv4_next, ipv4_addr)) {
		mem_free0(ipv4_next);
		ERROR("failed to determine free ip address");
		return -1;
	}

	DEBUG("next free ip cmld address is: %s", ipv4_next);
	mem_free0(ipv4_next);
	return 0;
}

/**
 * This function determines and sets the mac address, depending on its corresponding ipv4 address
 */
static int
c_net_get_next_ipv4_bcaddr(const struct in_addr *ipv4_addr, struct in_addr *ipv4_bcaddr)
{
	ASSERT(ipv4_addr && ipv4_bcaddr);

	ipv4_bcaddr->s_addr = ipv4_addr->s_addr | htonl(INADDR_BROADCAST >> IPV4_PREFIX);

	if (ipv4_bcaddr->s_addr == 0) {
		ERROR("failed to determine corresponding ipv4 broadcast address");
		return -1;
	}

	DEBUG("corresponding ipv4 broadcast address is: %s", inet_ntoa(*ipv4_bcaddr));

	return 0;
}

/**
 * This function determines and sets the next available ipv4 address, depending on the container offset.
 * The ipv4 address relates to the ipv4 in the container's namespace.
 */
static int
c_net_get_next_ipv4_cont_addr(int offset, struct in_addr *ipv4_addr)
{
	ASSERT(ipv4_addr);

	char *ipv4_next = mem_printf(IPV4_CONT_ADDRESS, offset + IPV4_SUBNET_OFFS);

	if (!ipv4_next) {
		ERROR("failed to allocate ipv4 address string");
		return -1;
	}

	if (!inet_aton(ipv4_next, ipv4_addr)) {
		mem_free0(ipv4_next);
		ERROR("failed to determine free ip address");
		return -1;
	}

	DEBUG("next free ipv4 container address is: %s", ipv4_next);
	mem_free0(ipv4_next);
	return 0;
}

/**
 * This function checks if the specified veth name is free.
 * In case it is free, 0 is returned, if it's blocked 1
 * In case of failure, the function returns -1
 */
static int
c_net_is_veth_used(const char *if_name)
{
	ASSERT(if_name);

	DIR *dirp = opendir(SYS_NET_PATH);
	struct dirent *dp;

	if (!dirp) {
		ERROR_ERRNO("failed to open net directory");
		return -1;
	}

	/* read the network directory and compare names */
	while ((dp = readdir(dirp)) != NULL) {
		char *path = mem_printf("%s/%s", SYS_NET_PATH, dp->d_name);

		TRACE("veth lookup path: %s, name: %s, parameter to match: %s", path, dp->d_name,
		      if_name);

		if (file_is_link(path)) {
			if (!strncmp(dp->d_name, if_name, IFNAMSIZ)) {
				DEBUG("veth %s is occupied", if_name);
				closedir(dirp);
				mem_free0(path);
				return 1;
			}
		}
		mem_free0(path);
	}

	DEBUG("veth %s is free", if_name);
	closedir(dirp);
	return 0;
}

/**
 * This function moves the network interface to the corresponding namespace,
 * specified by the pid (from root namespace to container namespace).
 */
static int
c_net_move_ifi(const char *ifi_name, const pid_t pid)
{
	if (network_interface_is_wifi(ifi_name))
		return network_nl80211_move_ns(ifi_name, pid);
	else
		return network_rtnet_move_ns(ifi_name, pid);
}

/**
 * This function removes the network interface from the corresponding namespace,
 * specified by the pid
 */
static int
c_net_remove_ifi(const char *ifi_name, const pid_t pid)
{
	ASSERT(ifi_name);
	int ret = network_move_link_ns(pid, 1, ifi_name);
	return ret;
}

/**
 * This function creates a veth pair veth1/veth2 (in the root namespace)
 * with a netlink message using the netlink socket
 */
static int
c_net_create_veth_pair(const char *veth1, const char *veth2, uint8_t veth1_mac[6])
{
	ASSERT(veth1 && veth2);

	nl_sock_t *nl_sock = NULL;
	nl_msg_t *req = NULL;

	/* Open netlink socket */
	if (!(nl_sock = nl_sock_routing_new())) {
		ERROR("failed to allocate netlink socket");
		return -1;
	}

	/* Create request netlink message */
	if (!(req = nl_msg_new())) {
		ERROR("failed to allocate netlink message");
		nl_sock_free(nl_sock);
		return -1;
	}

	/* Prepare request message */
	struct ifinfomsg link_req = { .ifi_family = AF_INET };

	struct nlattr *attr1, *attr2, *attr3;

	/* Fill netlink message header */
	if (nl_msg_set_type(req, RTM_NEWLINK))
		goto msg_err;

	/* Set appropriate flags for request, creating new object,
	 * exclusive access and acknowledgment response */
	if (nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK))
		goto msg_err;

	/* Fill link request header of request message */
	if (nl_msg_set_link_req(req, &link_req) != 0)
		goto msg_err;

	/* Add the corresponding attributes to the netlink header */
	if (!(attr1 = nl_msg_start_nested_attr(req, IFLA_LINKINFO)))
		goto msg_err;

	/* Set link type */
	if (nl_msg_add_string(req, IFLA_INFO_KIND, "veth"))
		goto msg_err;

	/* Add nested attributes for INFO and PEER */
	if (!(attr2 = nl_msg_start_nested_attr(req, IFLA_INFO_DATA)))
		goto msg_err;

	if (!(attr3 = nl_msg_start_nested_attr(req, VETH_INFO_PEER)))
		goto msg_err;

	/* VETH_INFO_PEER carries struct ifinfomsg plus optional IFLA
	   attributes. A minimal size of sizeof(struct ifinfomsg) must be
	   enforced or we may risk accessing that struct beyond the limits
	   of the netlink message */
	if (nl_msg_expand_len(req, sizeof(struct ifinfomsg)))
		goto msg_err;

	/* Set veth2 name */
	if (nl_msg_add_string(req, IFLA_IFNAME, veth2))
		goto msg_err;

	/* Close nested attributes */
	if (nl_msg_end_nested_attr(req, attr3))
		goto msg_err;
	if (nl_msg_end_nested_attr(req, attr2))
		goto msg_err;
	if (nl_msg_end_nested_attr(req, attr1))
		goto msg_err;

	/* Set veth1 name */
	if (nl_msg_add_string(req, IFLA_IFNAME, veth1))
		goto msg_err;

	/* Set veth1 mac address */
	if (nl_msg_add_buffer(req, IFLA_ADDRESS, (char *)veth1_mac, 6))
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

/**
 * This function sets an ipv4 address (and the broadcast addr) for a given veth
 * with a netlink message using the netlink socket.
 * We use this in the root namespace and in the container's namespace.
 */
static int
c_net_set_ipv4(const char *ifi_name, const struct in_addr *ipv4_addr,
	       const struct in_addr *ipv4_bcaddr)
{
	ASSERT(ifi_name);

	nl_sock_t *nl_sock = NULL;
	unsigned int ifi_index;
	nl_msg_t *req = NULL;

	DEBUG("Set ipv4 addr %s for %s", inet_ntoa(*ipv4_addr), ifi_name);

	/* Get the interface index of the interface name */
	if (!(ifi_index = if_nametoindex(ifi_name))) {
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

	/* Prepare the request message */
	struct ifaddrmsg ip_req = { .ifa_family = AF_INET,
				    .ifa_prefixlen = IPV4_PREFIX,
				    .ifa_index = ifi_index, /* The index of the interface */
				    .ifa_scope = RT_SCOPE_UNIVERSE };

	/* Fill netlink message header */
	if (nl_msg_set_type(req, RTM_NEWADDR))
		goto msg_err;

	/* Set appropriate flags for request, creating new object,
	 * exclusive access and acknowledgment response */
	if (nl_msg_set_flags(req, NLM_F_ACK | NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE))
		goto msg_err;

	/* Fill link request header of request message */
	if (nl_msg_set_ip_req(req, &ip_req))
		goto msg_err;

	/* Set local IPv4 address */
	if (nl_msg_add_buffer(req, IFA_LOCAL, (void *)ipv4_addr, sizeof(struct in_addr)))
		goto msg_err;

	/* Set IPv4 address */
	if (nl_msg_add_buffer(req, IFA_ADDRESS, (void *)ipv4_addr, sizeof(struct in_addr)))
		goto msg_err;

	/* Set IPv4 broadcast address */
	if (nl_msg_add_buffer(req, IFA_BROADCAST, (void *)ipv4_bcaddr, sizeof(struct in_addr)))
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

static c_net_interface_t *
c_net_interface_new(const char *if_name, const char *root_if_name, uint8_t if_mac[6],
		    bool configure)
{
	ASSERT(if_name);

	c_net_interface_t *ni = mem_new0(c_net_interface_t, 1);
	ni->nw_name = mem_strdup(if_name);
	ni->nw_name_cmld = root_if_name ? mem_strdup(root_if_name) : NULL;
	memcpy(ni->veth_mac, if_mac, 6);
	ni->configure = configure;
	ni->cont_offset = -1;

	return ni;
}

/*
 * This funtion enables or disables the mac_filter according to param apply
 */
static int
c_net_mac_filter(const char *if_name, list_t *mac_whitelist, bool apply)
{
	int ret;
	ret = network_iptables_phys_deny("INPUT", if_name, apply);
	ret |= network_iptables_phys_deny("FORWARD", if_name, apply);
	if (ret) {
		ERROR("Failed to %s deny all on %s", apply ? "apply" : "reset", if_name);
		return -1;
	}
	for (list_t *l = mac_whitelist; l; l = l->next) {
		uint8_t *mac = l->data;
		ret = network_phys_allow_mac("INPUT", if_name, mac, apply);
		ret |= network_phys_allow_mac("FORWARD", if_name, mac, apply);
		if (ret) {
			char *mac_str = network_mac_addr_to_str_new(mac);
			ERROR("Failed to allow %s on %s", mac_str, if_name);
			mem_free0(mac_str);
			return -1;
		}
	}
	return 0;
}

static int
c_net_bridge_ifi(const char *if_name, list_t *mac_whitelist, const pid_t pid)
{
	ASSERT(if_name);

	char *br_cmld_name = mem_printf("br_%s", if_name);
	char *veth_cmld_name = mem_printf("r_%s", if_name);
	char *veth_cont_name = mem_printf("c_%s", if_name);

	/* Create veth pair */
	if (c_net_is_veth_used(veth_cmld_name)) {
		ERROR("root ns veth %s already in use", veth_cmld_name);
		goto err;
	}
	if (c_net_is_veth_used(veth_cont_name)) {
		ERROR("container veth %s already in use", veth_cont_name);
		goto err;
	}

	uint8_t veth_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 };
	if (file_read("/dev/urandom", (char *)veth_mac, 6) < 0) {
		WARN_ERRNO("Failed to read from /dev/urandom");
	}
	// sanitize mac veth otherwise kernel may reject the mac
	veth_mac[0] &= 0xfe; /* clear multicast bit */
	veth_mac[0] |= 0x02; /* set local assignment bit (IEEE802) */

	if (c_net_create_veth_pair(veth_cont_name, veth_cmld_name, veth_mac))
		goto err;

	/* Bring up ports */
	if (network_set_flag(veth_cmld_name, IFF_UP)) {
		WARN_ERRNO("Could not set bridge port %s up!", veth_cmld_name);
		goto err_br;
	}
	if (network_set_flag(if_name, IFF_UP)) {
		WARN_ERRNO("Could not set bridge port %s up!", if_name);
		goto err_br;
	}

	/* Create and setup bridge */
	if (0 != network_create_bridge(br_cmld_name)) {
		ERROR("Failed to create bridge %s", br_cmld_name);
		goto err_br;
	}
	if (0 != network_bridge_set_up(br_cmld_name)) {
		ERROR("Failed to bring up bridge %s", br_cmld_name);
		goto err_port;
	}
	if (0 != network_bridge_add_port(br_cmld_name, if_name)) {
		ERROR("Failed to add port %s to bridge %s", if_name, br_cmld_name);
		goto err_port;
	}
	if (0 != network_bridge_add_port(br_cmld_name, veth_cmld_name)) {
		ERROR("Failed to add port %s to bridge %s", veth_cmld_name, br_cmld_name);
		network_delete_bridge(br_cmld_name);
		goto err_port;
	}

	/* apply MAC filtering rules */
	if (c_net_mac_filter(if_name, mac_whitelist, true)) {
		ERROR("Failed apply mac_filter to %s", if_name);
		goto err_port;
	}

	/* Move end point to Container */
	if (c_net_move_ifi(veth_cont_name, pid)) {
		ERROR("Failed to move %s to container with pid %d", veth_cont_name, pid);
		goto err_port;
	}

	mem_free0(br_cmld_name);
	mem_free0(veth_cmld_name);
	mem_free0(veth_cont_name);

	return 0;

err_port:
	network_delete_bridge(br_cmld_name);
err_br:
	network_delete_link(veth_cmld_name);
	network_delete_link(veth_cont_name);
	network_set_flag(if_name, IFF_DOWN);
err:
	mem_free0(br_cmld_name);
	mem_free0(veth_cmld_name);
	mem_free0(veth_cont_name);

	return -1;
}

static int
c_net_unbridge_ifi(const char *if_name, list_t *mac_whitelist, const pid_t pid)
{
	ASSERT(if_name);

	char *br_cmld_name = mem_printf("br_%s", if_name);
	char *veth_cmld_name = mem_printf("r_%s", if_name);
	char *veth_cont_name = mem_printf("c_%s", if_name);

	/* Bring down ports */
	if (pid > 0 && c_net_remove_ifi(veth_cont_name, pid) < 0) {
		WARN("container's network interface could not be grabbed");
	} else if (c_net_is_veth_used(veth_cont_name)) {
		if (network_set_flag(veth_cmld_name, IFF_DOWN))
			WARN("network interface could not be gracefully shut down");

		if (network_delete_link(veth_cmld_name))
			WARN("network interface %s could not be destroyed", veth_cmld_name);
	}
	if (c_net_is_veth_used(veth_cmld_name)) {
		if (network_set_flag(veth_cmld_name, IFF_DOWN))
			WARN("network interface could not be gracefully shut down");

		if (network_delete_link(veth_cmld_name))
			WARN("network interface %s could not be destroyed", veth_cmld_name);
	}

	/* delete bridge */
	if (0 != network_delete_bridge(br_cmld_name))
		WARN("Failed to delete bridge %s", br_cmld_name);

	if (0 != network_set_flag(if_name, IFF_DOWN))
		WARN("Failed to delete bridge %s", br_cmld_name);

	/* clean out MAC filtering rules */
	if (-1 == c_net_mac_filter(if_name, mac_whitelist, false))
		WARN("Failed apply mac_filter to %s", if_name);

	mem_free0(br_cmld_name);
	mem_free0(veth_cmld_name);
	mem_free0(veth_cont_name);

	return 0;
}

/**
 * This function moves/bridges the network interface to the corresponding net
 * namespace of a container.
 * This Funtion mainly implement TSF.CML.DeviceAccessControl for network devices.
 *
 * It is used internally by c_net_new, than we already have grabbed the interface.
 * also this function is used externally for new devices during runtime from control
 * or hotplug handler. Then we have to grab the interface from cmld's list of available
 * interfaces and add the pnet_cfg to the internal c_net list.
 */
static int
c_net_add_interface(void *netp, container_pnet_cfg_t *pnet_cfg)
{
	c_net_t *net = netp;
	ASSERT(net);
	IF_NULL_RETVAL(pnet_cfg, -1);

	bool c_net_internal = (NULL != list_find(net->pnet_mv_list, pnet_cfg));
	pid_t pid = container_get_pid(net->container);

	uint8_t if_mac[6];
	char *if_name = (network_str_to_mac_addr(pnet_cfg->pnet_name, if_mac) != -1) ?
				network_get_ifname_by_addr_new(if_mac) :
				mem_strdup(pnet_cfg->pnet_name);

	IF_NULL_RETVAL(if_name, -1);

	if (!c_net_internal) {
		IF_FALSE_GOTO_ERROR(cmld_netif_phys_remove_by_name(if_name), err);

		// adding to c0, thus mark this interface available as free for others
		if (cmld_containers_get_c0() == net->container) {
			// re-add iface to list of available network interfaces
			cmld_netif_phys_add_by_name(if_name);
		}
	}

	if (!pnet_cfg->mac_filter) { // directly map phys. IF into container
		DEBUG("move phys %s to the ns of this pid: %d", pnet_cfg->pnet_name, pid);
		IF_TRUE_GOTO_ERROR(-1 == c_net_move_ifi(if_name, pid), err);
	} else { // pIF should be bridged and MAC filtering applied
		DEBUG("bridge phys %s to the ns of this pid: %d", pnet_cfg->pnet_name, pid);
		IF_TRUE_GOTO_ERROR(-1 == c_net_bridge_ifi(if_name, pnet_cfg->mac_whitelist, pid),
				   err);
	}

	if (!c_net_internal) // called externally add to internal list
		net->pnet_mv_list = list_append(net->pnet_mv_list, pnet_cfg);

	INFO("Sucessfully move/bridged iface %s to %s", if_name,
	     container_get_name(net->container));

	mem_free0(if_name);
	return 0;
err:
	mem_free0(if_name);
	return -1;
}

/**
 * This function removes the network interface from the corresponding net
 * namespace of a container, according to the name or mac address.
 */
static int
c_net_remove_interface(void *netp, const char *if_name_mac)
{
	c_net_t *net = netp;
	ASSERT(net);

	IF_NULL_RETVAL(if_name_mac, -1);

	container_pnet_cfg_t *cfg = NULL;
	pid_t pid = container_get_pid(net->container);

	uint8_t if_mac[6];
	char *if_name = (network_str_to_mac_addr(if_name_mac, if_mac) != -1) ?
				network_get_ifname_by_addr_new(if_mac) :
				mem_strdup(if_name_mac);

	IF_NULL_RETVAL(if_name, -1);

	for (list_t *l = net->pnet_mv_list; l; l = l->next) {
		container_pnet_cfg_t *_cfg = l->data;
		char *_if_name = (network_str_to_mac_addr(_cfg->pnet_name, if_mac) != -1) ?
					 network_get_ifname_by_addr_new(if_mac) :
					 mem_strdup(_cfg->pnet_name);
		if (strcmp(if_name, _if_name)) {
			cfg = _cfg;
			mem_free0(_if_name);
			break;
		}
		mem_free0(_if_name);
	}

	if (NULL == cfg) {
		mem_free0(if_name);
		return 0;
	}

	if (!cfg->mac_filter) { // remove directly mapped ifi
		DEBUG("remove phys %s to the ns of this pid: %d", cfg->pnet_name, pid);
		IF_TRUE_GOTO_ERROR(-1 == c_net_remove_ifi(if_name, pid), err);
	} else { // pIF remove bridged and MAC filtering rules
		DEBUG("remove bridged phys %s to the ns of this pid: %d", cfg->pnet_name, pid);
		IF_TRUE_GOTO_ERROR(-1 == c_net_unbridge_ifi(if_name, cfg->mac_whitelist, pid), err);
	}

	net->pnet_mv_list = list_remove(net->pnet_mv_list, cfg);
	container_pnet_cfg_free(cfg);

	cmld_netif_phys_add_by_name(if_name);
	mem_free0(if_name);
	return 0;

err:
	mem_free0(if_name);
	return -1;
}

/**
 * This function allocates a new c_net_t instance, associated to a specific container object.
 * @return the c_net_t network structure which holds networking information for a container.
 */
static void *
c_net_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_net_t *net = mem_new0(c_net_t, 1);
	net->container = compartment_get_extension_data(compartment);

	/* if the container does not have a network namespace, we don't execute any of this,
	 * i.e. we always return at the start of the functions  */
	if (!container_has_netns(net->container)) {
		return net;
	}

	// add cml interface as uplink for cmld through c0
	if (container_uuid_is_c0id(container_get_uuid(net->container))) {
		INFO("Generating uplink veth %s", CML_UPLINK_INTERFACE_NAME);
		uint8_t mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00 };
		if (file_read("/dev/urandom", (char *)mac, 6) < 0) {
			WARN_ERRNO("Failed to read from /dev/urandom");
		}
		mac[0] &= 0xfe; /* clear multicast bit */
		mac[0] |= 0x02; /* set local assignment bit (IEEE802) */

		c_net_interface_t *ni_cml =
			c_net_interface_new(CML_UPLINK_INTERFACE_NAME, "uplink", mac, true);
		net->interface_list = list_append(net->interface_list, ni_cml);
	}

	for (list_t *l = container_get_vnet_cfg_list(net->container); l; l = l->next) {
		container_vnet_cfg_t *cfg = l->data;

		c_net_interface_t *ni = c_net_interface_new(cfg->vnet_name, cfg->rootns_name,
							    cfg->vnet_mac, cfg->configure);
		ASSERT(ni);
		net->interface_list = list_append(net->interface_list, ni);

		TRACE("new c_net_interface_t struct %s was allocated", ni->nw_name);
	}

	uint8_t mac[6];
	for (list_t *l = container_get_pnet_cfg_list(net->container); l; l = l->next) {
		container_pnet_cfg_t *pnet_cfg = l->data;
		// deep copy for internal list and hotplugging
		container_pnet_cfg_t *pnet_cfg_mv = container_pnet_cfg_new(
			pnet_cfg->pnet_name, pnet_cfg->mac_filter, pnet_cfg->mac_whitelist);
		char *if_name_macstr = pnet_cfg->pnet_name;
		char *if_name = NULL;
		TRACE("mv_name_list add ifname %s", if_name_macstr);
		mem_memset(&mac, 0, 6);
		// check if string is mac address
		if (0 == network_str_to_mac_addr(if_name_macstr, mac)) {
			TRACE("mv_name_list add if by mac: %s", if_name_macstr);
			// register at hotplug subsys
			if (-1 == hotplug_register_netdev(net->container, pnet_cfg_mv)) {
				WARN("Could not register Interface for moving");
				container_pnet_cfg_free(pnet_cfg_mv);
			} else {
				INFO("Registed Interface for mac '%s' at hotplug subsys",
				     if_name_macstr);

				net->hotplug_registered_mac_list =
					list_append(net->hotplug_registered_mac_list,
						    mem_memcpy((unsigned char *)&mac, sizeof(mac)));
			}

			if_name = network_get_ifname_by_addr_new(mac);
			if (NULL == if_name) {
				INFO("Interface for mac '%s' is not yet connected.",
				     if_name_macstr);
				continue;
			}
		}

		if (NULL == if_name)
			if_name = mem_strdup(if_name_macstr);

		TRACE("mv_name_list add ifname %s", if_name);

		if (cmld_netif_phys_remove_by_name(if_name))
			net->pnet_mv_list = list_append(net->pnet_mv_list, pnet_cfg_mv);

		mem_free0(if_name);
	}

	// path to bind netns, compatible to ip netns tool
	dir_mkdir_p("/var/run/netns", 00755);
	net->ns_path =
		mem_printf("/var/run/netns/%s", uuid_string(container_get_uuid(net->container)));

	TRACE("new c_net struct was allocated");

	return net;
}

static int
c_net_start_pre_clone_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	/* Get container offset based on currently started containers */
	if ((ni->cont_offset = c_net_set_next_offset()) == -1) {
		WARN_ERRNO("Maximum offset for Network interfaces reached!");
		goto err;
	}

	ni->veth_cmld_name = mem_printf("r_%d", ni->cont_offset);
	ni->veth_cont_name = mem_printf("c_%d", ni->cont_offset);

	if (ni->configure) {
		/* Get root ns ipv4 address */
		if (c_net_get_next_ipv4_cmld_addr(ni->cont_offset, &ni->ipv4_cmld_addr)) {
			ERROR("failed to retrieve a root/c0 ns ip address");
			goto err;
		}
		/* set subnet string */
		uint32_t ip = ntohl(ni->ipv4_cmld_addr.s_addr);
		uint32_t mask = ~(((uint32_t)-1) >> IPV4_PREFIX);
		struct in_addr net_prefix = { .s_addr = htonl(ip & mask) };
		ni->subnet = mem_printf("%s/%d", inet_ntoa(net_prefix), IPV4_PREFIX);

		/* Get container ns ipv4 address */
		if (c_net_get_next_ipv4_cont_addr(ni->cont_offset, &ni->ipv4_cont_addr)) {
			ERROR("failed to retrieve an ip container address");
			goto err;
		}
		/* Get corresponding bcaddress */
		if (c_net_get_next_ipv4_bcaddr(&ni->ipv4_cont_addr, &ni->ipv4_bc_addr)) {
			ERROR("failed to retrieve the ip container broadcast address");
			goto err;
		}
	}

	/* Create free veth pair from container name, check if the interfaces are free */
	if (c_net_is_veth_used(ni->veth_cmld_name)) {
		ERROR("root ns veth %s already in use", ni->veth_cmld_name);
		goto err;
	}
	if (c_net_is_veth_used(ni->veth_cont_name)) {
		ERROR("container veth %s already in use", ni->veth_cont_name);
		goto err;
	}

	/* TODO: check if physical IF has MAC that is allowed by container config */

	/* Start with second step: create veth pair, set root ns ipv4 add, bring the interface up */
	DEBUG("Create veth pair %s/%s", ni->veth_cont_name, ni->veth_cmld_name);

	/* Create veth pair */
	if (c_net_create_veth_pair(ni->veth_cont_name, ni->veth_cmld_name, ni->veth_mac))
		goto err;

	/* Get the interface index of the interface name */
	if (!(ni->veth_cmld_idx = if_nametoindex(ni->veth_cmld_name))) {
		ERROR("veth interface name could not be resolved");
		goto err;
	}

	return 0;

	/* In case of an error, release the current offset */
err:
	if (ni->cont_offset >= 0)
		c_net_unset_offset(ni->cont_offset);
	if (ni->veth_cmld_name) {
		// delete veth pair if it was created!
		if (c_net_is_veth_used(ni->veth_cmld_name)) {
			if (network_delete_link(ni->veth_cmld_name))
				TRACE("network interface %s could not be destroyed",
				      ni->veth_cmld_name);
		}
		mem_free0(ni->veth_cmld_name);
		ni->veth_cmld_name = NULL;
	}
	if (ni->veth_cont_name) {
		mem_free0(ni->veth_cont_name);
		ni->veth_cont_name = NULL;
	}
	return -1;
}

/**
 * Before clone, initialize c_net structure, create a veth pair and configure the root ns veth
 * This Function is part of TSF.CML.CompartmentIsolation.
 *
 * First part: get currently free ipv4 and veth addresses/names for the network setup.
 * Second part: Create a veth pair and configure the root namespace veth
 * Third part: Setup routing and filtering/nat.
 * by setting its ipv4 and bringing up the interface.
 *
 * @return: 0 on success, -COMPARTMENT_ERROR_NET in case of failure.
 */
static int
c_net_start_pre_clone(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);

	/* If container has no network namespace, we can just skip, as every networking
	 * operation will be skipped */
	if (!container_has_netns(net->container))
		return 0;

	/* skip on reboots of c0 */
	if ((cmld_containers_get_c0() == net->container) &&
	    (container_get_prev_state(net->container) == COMPARTMENT_STATE_REBOOTING))
		return 0;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (c_net_start_pre_clone_interface(ni) == -1)
			return -COMPARTMENT_ERROR_NET;
		if (!ni->configure)
			continue;
	}
	return 0;
}

static int
c_net_start_post_clone_interface(pid_t pid, c_net_interface_t *ni)
{
	ASSERT(ni);

	if (!(ni->veth_cont_name && pid > 0)) {
		ERROR("PID or veth name missing to move ifi");
		return -1;
	}

	DEBUG("move %s to the ns of this pid: %d", ni->veth_cont_name, pid);
	if (c_net_move_ifi(ni->veth_cont_name, pid) < 0)
		return -1;

	/* Rename veth endpoint in rootns to the given name in container config */
	if (ni->nw_name_cmld && (0 == network_rename_ifi(ni->veth_cmld_name, ni->nw_name_cmld))) {
		DEBUG("renamed rootns ifi from %s to %s", ni->veth_cmld_name, ni->nw_name_cmld);
		mem_free0(ni->veth_cmld_name);
		ni->veth_cmld_name = mem_strdup(ni->nw_name_cmld);
	}

	return 0;
}

#ifdef DEBUG_BUILD
static int
setup_c0_cml_ssh_port_forwarding(c_net_interface_t *ni)
{
	char srcaddr[INET_ADDRSTRLEN];
	char dstaddr[INET_ADDRSTRLEN];

	IF_NULL_GOTO(inet_ntop(AF_INET, &ni->ipv4_cont_addr, srcaddr, sizeof(srcaddr)), err);
	IF_NULL_GOTO(inet_ntop(AF_INET, &ni->ipv4_cmld_addr, dstaddr, sizeof(dstaddr)), err);

	IF_TRUE_GOTO(network_setup_port_forwarding(srcaddr, CML_SSH_PORT_C0, dstaddr,
						   CML_SSH_PORT_CML, true),
		     err);

	return 0;

err:
	ERROR_ERRNO("Could not setup port forwarding from %s:%d to %s:%d on interface %s!", srcaddr,
		    CML_SSH_PORT_C0, dstaddr, CML_SSH_PORT_CML, ni->veth_cmld_name);
	return -1;
}
#endif

/**
 * This function is responsible for moving the container interface to its corresponding namespace.
 * This Function is part of TSF.CML.CompartmentIsolation.
 *
 * It moves physical interfaces to its configured containers. Furher it creates a new child from
 * cmld and joins this to c0's netns for configuring the network endpoint of container virtual
 * veth's there.
 * If mac filter is applied do not move physical interfaces but rather a veth so that iptables
 * can be applied in the CML context.
 *
 * @return: 0 on success, -COMPARTMENT_ERROR_NET in case of failure.
 */
static int
c_net_start_post_clone(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);

	/* Skip, if the container doesn't have a network ns */
	if (!container_has_netns(net->container))
		return 0;

	/* skip on reboots of c0 */
	if ((cmld_containers_get_c0() == net->container) &&
	    (container_get_prev_state(net->container) == COMPARTMENT_STATE_REBOOTING))
		return 0;

	/* Get container's pid */
	pid_t pid = container_get_pid(net->container);
	pid_t pid_c0 = cmld_containers_get_c0() ? container_get_pid(cmld_containers_get_c0()) : 0;

	/* append list for c0 with available phys network interfaces */
	if (pid == pid_c0 && container_is_privileged(net->container)) {
		for (list_t *l = cmld_get_netif_phys_list(); l; l = l->next) {
			char *iff_name = l->data;
			container_pnet_cfg_t *cfg = container_pnet_cfg_new(iff_name, false, NULL);
			net->pnet_mv_list = list_append(net->pnet_mv_list, cfg);
		}
	}

	/* move or bridge phys network intrefaces to container */
	for (list_t *l = net->pnet_mv_list; l; l = l->next) {
		container_pnet_cfg_t *cfg = l->data;
		if (c_net_add_interface(net, cfg) < 0)
			return -COMPARTMENT_ERROR_NET;
	}

	// nothing to be configured
	if (NULL == net->interface_list)
		return 0;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (c_net_start_post_clone_interface(pid, ni) == -1)
			return -COMPARTMENT_ERROR_NET;
		if (pid == pid_c0) //skip moving interfaces defined for c0 (e.g. uplink iiff)
			continue;
		if (cmld_containers_get_c0()) {
			DEBUG("move %s to the ns of c0's pid: %d", ni->veth_cmld_name, pid_c0);
			if (c_net_move_ifi(ni->veth_cmld_name, pid_c0) < 0)
				return -COMPARTMENT_ERROR_NET;
		}
	}

	// configure moved rootns veth endpoint in c0's network namespace
	pid_t *c0_netns_pid = mem_new0(pid_t, 1);
	*c0_netns_pid = fork();
	if (*c0_netns_pid == -1) {
		ERROR_ERRNO("Could not fork for switching to c0's netns");
		mem_free0(c0_netns_pid);
		return -COMPARTMENT_ERROR_NET;
	} else if (*c0_netns_pid == 0) {
		const char *hostns = cmld_containers_get_c0() ? "c0" : "CML";

		DEBUG("Configuring netifs in %s", hostns);

		event_reset(); // reset event_loop of cloned from parent
		if (cmld_containers_get_c0()) {
			char *c0_netns = mem_printf("/proc/%d/ns/net",
						    container_get_pid(cmld_containers_get_c0()));
			int netns_fd = open(c0_netns, O_RDONLY);
			mem_free0(c0_netns);
			if (netns_fd == -1)
				FATAL_ERRNO("Could not open netns file of c0");
			if (setns(netns_fd, CLONE_NEWNET) == -1)
				FATAL_ERRNO("Could not join network namespace of c0");
			close(netns_fd);
		}

		// enable forwarding for container conectivity
		network_enable_ip_forwarding();

		for (list_t *l = net->interface_list; l; l = l->next) {
			c_net_interface_t *ni = l->data;
			if (!ni->configure)
				continue;

			DEBUG("set IFF_UP for veth: %s", ni->veth_cmld_name);

			/* Configure uplink of CML in c0 */
			if (!strcmp(ni->nw_name, CML_UPLINK_INTERFACE_NAME)) {
				if (network_setup_masquerading(ni->subnet, true))
					FATAL_ERRNO("Could not setup masquerading for %s!",
						    ni->veth_cmld_name);
					// configuration of interface is done in root netns below

#ifdef DEBUG_BUILD
				/* setup port forwarding for ssh in debug build */
				if (setup_c0_cml_ssh_port_forwarding(ni))
					FATAL("Could not setup ssh port forwarding!");
#endif
				continue;
			}

			/* Set IPv4 address */
			if (c_net_set_ipv4(ni->veth_cmld_name, &ni->ipv4_cmld_addr,
					   &ni->ipv4_bc_addr))
				FATAL_ERRNO("Cannot set ip for '%s' in %s!", ni->veth_cmld_name,
					    hostns);

			/* Bring veth up */
			if (network_set_flag(ni->veth_cmld_name, IFF_UP))
				FATAL_ERRNO("Could not configure %s in %s!", ni->veth_cmld_name,
					    hostns);

			/* Setup firewall for container connectivity */
			if (network_setup_masquerading(ni->subnet, true))
				FATAL_ERRNO("Could not setup masquerading for %s!",
					    ni->veth_cmld_name);

			DEBUG("Successfully configured %s in %s, wait for child to exit.",
			      ni->veth_cmld_name, hostns);
		}
		DEBUG("Setup of net ifs in netns of %s done, exiting netns child!", hostns);
		_exit(0); // don't call atexit registered cleanup of main process
	} else {
		DEBUG("Setup of nis should be done by pid=%d", *c0_netns_pid);
		// register at sigchild handler for helper clone in netns of c0
		container_wait_for_child(net->container, "c0-netns-helper", *c0_netns_pid);

		/* setup uplink of cml */
		c_net_interface_t *ni = list_nth_data(net->interface_list, 0);
		if (ni && !strcmp(ni->nw_name, CML_UPLINK_INTERFACE_NAME)) {
			/* Set IPv4 address */
			if (c_net_set_ipv4(ni->veth_cmld_name, &ni->ipv4_cmld_addr,
					   &ni->ipv4_bc_addr))
				ERROR_ERRNO("Cannot set ip for uplink iff '%s'!",
					    ni->veth_cmld_name);

			/* Bring veth up */
			if (network_set_flag(ni->veth_cmld_name, IFF_UP))
				ERROR_ERRNO("Could not configure uplink %s!", ni->veth_cmld_name);

			if (network_setup_default_route(inet_ntoa(ni->ipv4_cont_addr), true))
				ERROR("Failed to setup gateway for CML's uplink");
			// TODO firewall connections to cml
		}
	}

	// bind netns to file
	if (ns_bind("net", pid, net->ns_path) == -1) {
		WARN("Could not bind netns of %s into filesystem!",
		     container_get_name(net->container));
	}

	return 0;
}

static int
c_net_start_child_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	DEBUG("rename ifi from %s to %s", ni->veth_cont_name, ni->nw_name);

	/* Rename container veth to the given if name */
	if (network_rename_ifi(ni->veth_cont_name, ni->nw_name))
		return -1;

	/* Skip IPv4 setup if interface has no config */
	if (!ni->configure) {
		DEBUG("Leave %s interface unconfigured. (Manual configuration detected)",
		      ni->nw_name);
		return 0;
	}

	DEBUG("set ipv4 (addr: %s) for %s", inet_ntoa(ni->ipv4_cont_addr), ni->nw_name);

	/* Set IPv4 address */
	if (c_net_set_ipv4(ni->nw_name, &ni->ipv4_cont_addr, &ni->ipv4_bc_addr))
		return -1;

	/* bring net->nw_name interface up */
	DEBUG("bring %s interface up", ni->nw_name);

	if (network_set_flag(ni->nw_name, IFF_UP))
		return -1;

	return 0;
}

/**
 * In the container's namespace, the container veth is configured
 * This Function is part of TSF.CML.CompartmentIsolation.
 *
 * In the container namespace, rename the interface to net->nw_name,
 * set the ipv4 container address and bring the interfaces up.
 *
 * @return: 0 on success, -COMPARTMENT_ERROR_NET in case of failure.
 */
static int
c_net_start_child(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);

	/* Skip this, if the container doesn't have a network namespace */
	if (!container_has_netns(net->container) || !(list_length(net->interface_list) > 0))
		return 0;

	/* skip on reboots of c0 */
	if ((cmld_containers_get_c0() == net->container) &&
	    (container_get_prev_state(net->container) == COMPARTMENT_STATE_REBOOTING))
		return 0;

	// shrink subnet reserverd for loopback device
	if (network_setup_loopback())
		return -COMPARTMENT_ERROR_NET;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (c_net_start_child_interface(ni) == -1)
			return -COMPARTMENT_ERROR_NET;
	}
	/* default inet uplink through first configured iif */
	c_net_interface_t *ni = list_nth_data(net->interface_list, 0);
	if (ni->configure && !container_uuid_is_c0id(container_get_uuid(net->container))) {
		if (network_setup_default_route(inet_ntoa(ni->ipv4_cmld_addr), true))
			WARN("Failed to setup gateway for %s", ni->veth_cont_name);
	}

	return 0;
}

static void
c_net_cleanup_interface(c_net_interface_t *ni)
{
	TRACE("cleanup c_net_t structure");

	DEBUG("shut network interface %s down", ni->veth_cont_name);

	/* Release the offset, as the ip addresses are no more occupied */
	c_net_unset_offset(ni->cont_offset);

	if (ni->subnet) {
		mem_free0(ni->subnet);
		ni->subnet = NULL;
	}
	mem_memset(&ni->ipv4_cmld_addr, 0, sizeof(struct in_addr));
	mem_memset(&ni->ipv4_cont_addr, 0, sizeof(struct in_addr));
	mem_memset(&ni->ipv4_bc_addr, 0, sizeof(struct in_addr));

	if (ni->veth_cmld_name) {
		mem_free0(ni->veth_cmld_name);
		ni->veth_cmld_name = NULL;
	}
	if (ni->veth_cont_name) {
		mem_free0(ni->veth_cont_name);
		ni->veth_cont_name = NULL;
	}
}

static int
c_net_do_cleanup_host(const void *data)
{
	const c_net_t *net = data;
	ASSERT(net);

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (ni->configure && network_setup_masquerading(ni->subnet, false))
			WARN("Failed to remove masquerading from %s", ni->subnet);
	}
	return 0;
}

/**
 * Cleans up the c_net_t struct and shuts down the network interface
 * (if necessary in c0's netns).
 */
static int
c_net_cleanup_c0(const c_net_t *net)
{
	ASSERT(net);
	int ret = 0;
	container_t *c0 = cmld_containers_get_c0();
	const char *hostns = c0 ? "c0" : "CML";

	DEBUG("Cleaning up netifs in %s", hostns);

	// cleanup moved rootns veth endpoint in c0's network namespace
	pid_t pid = c0 ? container_get_pid(c0) : getpid();
	ret = namespace_exec(pid, CLONE_NEWNET | CLONE_NEWUSER, 0, 0, c_net_do_cleanup_host, net);

	DEBUG("Cleanup of net ifs in netns of %s done!", hostns);
	return ret;
}

static void
c_net_interface_down(const char *iface)
{
	if (network_set_flag(iface, IFF_DOWN))
		WARN("Network interface %s could not be stopped gracefully", iface);

	if (network_delete_link(iface))
		WARN("Network interface %s could not be destroyed", iface);
}

/**
 * Rename physical network interfaces of container before netns destruction
 */
static int
c_net_cleanup_phys(const c_net_t *net)
{
	ASSERT(net);

	// no need to cleanup/rename if no phys interfaces where added
	IF_FALSE_RETVAL(net->pnet_mv_list, 0);

	IF_FALSE_RETVAL(file_exists(net->ns_path), -1);

	// rename moved physical interfaces in network namespace of container
	pid_t c_netns_pid = fork();
	if (c_netns_pid == -1) {
		ERROR_ERRNO("Could not fork for switching to netns");
		return -1;
	} else if (c_netns_pid == 0) {
		DEBUG("Renaming netifs in %s", container_get_name(net->container));

		event_reset(); // reset event_loop of cloned from parent
		if (ns_join_by_pid(container_get_pid(net->container), CLONE_NEWNET) < 0)
			FATAL_ERRNO("Could not join netns of compartment");

		list_t *phys_ifaces = network_get_physical_interfaces_new();
		// Rename all physical interfaces.
		int index = 0;
		for (list_t *l = phys_ifaces; l; l = l->next) {
			const char *ifname = l->data;
			const char *prefix = (network_interface_is_wifi(ifname)) ? "wlan" : "eth";

			// create collision free name with cmld's main process naming scheme
			char *newname = mem_printf("%s%08x_%03d", prefix,
						   container_get_uid(net->container), index++);
			if (strlen(newname) > IFNAMSIZ) {
				ERROR("newname '*s' exceeds IFNAMSIZ %d.", IFNAMSIZ);
				mem_free(newname);
				mem_free0(l->data);
				continue;
			}

			DEBUG("Renaming interface %s to %s in netns of %s ", ifname, newname,
			      container_get_name(net->container));

			if (network_rename_ifi(ifname, newname))
				WARN("Failed to rename interface %s", ifname);

			mem_free(newname);
			mem_free0(l->data);
		}
		list_delete(phys_ifaces);

		DEBUG("Renaming ifs in netns of %s done, exiting netns child!",
		      container_get_name(net->container));
		_exit(0); // don't call atexit registered cleanup of main process
	} else {
		DEBUG("Renaming of ifs should be done by pid=%d", c_netns_pid);
		// register at sigchild handler for helper clone in netns of container
		container_wait_for_child(net->container, "c-netns-rename-helper", c_netns_pid);
	}

	return 0;
}

/**
 * Cleans up the c_net_t struct and shuts down the network interface.
 */
static void
c_net_cleanup(void *netp, bool is_rebooting)
{
	c_net_t *net = netp;
	ASSERT(net);

	/* We can skip this in case the container has no network ns */
	if (!container_has_netns(net->container) || !(list_length(net->interface_list)))
		return;

	/* skip cleanup and keep netns open on reboots of c0 */
	if (is_rebooting && (cmld_containers_get_c0() == net->container)) {
		net->fd_netns = open(net->ns_path, O_RDONLY);
		if (net->fd_netns < 0)
			WARN("Could not keep netns active for reboot!");
		return;
	}

	// rename phys interface to avoid name clashes during fallback to rootns
	if (c_net_cleanup_phys(net) == -1)
		WARN("Failed to create helper child for cleanup of phys in container's netns");

	// remove bound to filesystem
	if (net->fd_netns > 0) {
		close(net->fd_netns);
		net->fd_netns = -1;
	}
	ns_unbind(net->ns_path);

	/* remove phys network intrefaces from container */
	uint8_t if_mac[6];
	for (list_t *l = net->pnet_mv_list; l; l = l->next) {
		container_pnet_cfg_t *cfg = l->data;
		if (!cfg->mac_filter) { // skip directly moved if will fallback to rootns
			continue;
		} else { // pIF remove bridged and MAC filtering rules
			char *if_name = (network_str_to_mac_addr(cfg->pnet_name, if_mac) != -1) ?
						network_get_ifname_by_addr_new(if_mac) :
						mem_strdup(cfg->pnet_name);
			DEBUG("remove bridged phys %s of %s", cfg->pnet_name,
			      container_get_name(net->container));
			if (-1 == c_net_unbridge_ifi(if_name, cfg->mac_whitelist, -1))
				WARN("Failed to remove phys if %s", if_name);
			mem_free0(if_name);
		}
	}

	if (c_net_cleanup_c0(net) == -1)
		WARN("Failed to create helper child for cleanup in c0's netns");

	/* release ip offsets and names of veths */
	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;
		c_net_cleanup_interface(ni);
	}
}

/**
 * Frees the c_net_interface_t structure
 */
static void
c_net_free_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	if (ni->subnet)
		mem_free0(ni->subnet);
	mem_free0(ni->veth_cmld_name);
	mem_free0(ni->veth_cont_name);
	mem_free0(ni->nw_name);
	if (ni->nw_name_cmld)
		mem_free0(ni->nw_name_cmld);
	mem_free0(ni);
}

/**
 * Frees the c_net_t structure
 */
static void
c_net_free(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);

	/* unregister netdevs by mac from hotplug subsystem */
	for (list_t *l = net->hotplug_registered_mac_list; l; l = l->next) {
		uint8_t *mac = l->data;
		hotplug_unregister_netdev(net->container, mac);
		mem_free0(mac);
	}
	list_delete(net->hotplug_registered_mac_list);

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;
		c_net_free_interface(ni);
	}
	list_delete(net->interface_list);
	for (list_t *l = net->pnet_mv_list; l; l = l->next) {
		container_pnet_cfg_t *pnet = l->data;
		container_pnet_cfg_free(pnet);
	}
	list_delete(net->pnet_mv_list);
	mem_free0(net->ns_path);
	mem_free0(net);
}

/**
 * This function provides a list of container_net_cfg_t* objects
 * which contain the name of an interface inside the container and the
 * corresponding interface name of the endpoint in the root network namespace.
 */
static list_t *
c_net_get_interface_mapping_new(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);

	list_t *mapping = NULL;
	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;
		container_vnet_cfg_t *vnet_cfg = container_vnet_cfg_new(
			ni->nw_name, ni->veth_cmld_name, ni->veth_mac, ni->configure);
		mapping = list_append(mapping, vnet_cfg);
	}
	return mapping;
}

/**
 * Rejoin existing netns on reboots where netns is kept active
 * This Function is part of TSF.CML.CompartmentIsolation.
 */
static int
c_net_join_netns(void *netp)
{
	c_net_t *net = netp;
	ASSERT(net);
	IF_FALSE_RETVAL(file_exists(net->ns_path), -1);

	if (ns_join_by_path(net->ns_path) < 0)
		return -COMPARTMENT_ERROR_NET;

	return 0;
}

static compartment_module_t c_net_module = {
	.name = MOD_NAME,
	.compartment_new = c_net_new,
	.compartment_free = c_net_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = c_net_start_pre_clone,
	.start_post_clone = c_net_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_pre_exec_child_early = NULL,
	.start_child = c_net_start_child,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_net_cleanup,
	.join_ns = c_net_join_netns,
};

static void INIT
c_net_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_net_module);

	// register relevant handlers implemented by this module
	container_register_add_net_interface_handler(MOD_NAME, c_net_add_interface);
	container_register_remove_net_interface_handler(MOD_NAME, c_net_remove_interface);
	container_register_get_vnet_runtime_cfg_new_handler(MOD_NAME,
							    c_net_get_interface_mapping_new);
}
