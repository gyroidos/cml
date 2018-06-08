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

#include "c_net.h"

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

#ifdef ANDROID
#include <linux/if_arp.h>
#include <linux/if.h>
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/list.h"
#include "common/nl.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/network.h"
#include "common/proc.h"
#include "common/event.h"
#include "container.h"
#include "hardware.h"

/* Offset for ipv4/mac address allocation, e.g. 127.1.(IPV4_SUBNET_OFFS+x).2
 * Defines the start value for address allocation */
// TODO: we can possibly run into collisions (increment in get next ip function if ip request fails
#define IPV4_SUBNET_OFFS 0

/* Max number of network structures that can be allocated depends on the available subnets */
#define MAX_NUM_DEVICES (255-IPV4_SUBNET_OFFS)

/* Path to search for net devices */
#define SYS_NET_PATH "/sys/class/net"

/* ipv4 addresses for cmld and cont endpoints, where the subnet depends on the container */
#define IPV4_CMLD_ADDRESS "127.1.%d.1"
#define IPV4_CONT_ADDRESS "127.1.%d.2"
#define IPV4_DHCP_RANGE_START "127.1.%d.50"
#define IPV4_DHCP_RANGE_END "127.1.%d.61"

// connection to adb in container
#define ADB_INTERFACE_NAME "adb"
#define ADB_DAEMON_PORT 5555

/* Network prefix */
#define IPV4_PREFIX 24

/* Network interface structure with interface specific settings */
typedef struct {
	char *nw_name; //!< Name of the network device
	char *veth_cmld_name; //!< associated veth name in root ns
	char *veth_cont_name; //!< veth name in the container's ns
	char *subnet;	      //!< string with subnet (x.x.x.x/y)
	struct in_addr ipv4_cmld_addr; //!< associated ipv4 address in root ns
	struct in_addr ipv4_cont_addr; //!< ipv4 address of container
	struct in_addr ipv4_bc_addr; //!< ipv4 bcaddr of container/cmld subnet
	int cont_offset; //!< gives information about the adresses to be set
} c_net_interface_t;

/* Network structure with specific network settings */
struct c_net {
	container_t *container; //!< container which the c_net struct is associated to
	uint16_t adb_port;	//!< forwarded port for adb in container
	bool ns_net; //!< indicates if the c_net structure has a network namespace
	list_t *interface_list; //!< contains list of settings for different nw interfaces
	list_t *interface_mv_name_list; //!< contains list of iff names to be moved into the container
};

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
c_net_unset_offset(int offset) {
	ASSERT(offset >= 0 && offset < MAX_NUM_DEVICES);
	TRACE("Offset %d released by a container", offset);

	address_offsets[offset] = false;
}

/**
 * determines first free slot and occupies it. Also responsible for allocating the offsets array.
 * @return failure, return -1, else return first free offset
 */
static int
c_net_set_next_offset(void) {
	if (!address_offsets) {
		address_offsets = mem_new0(bool, MAX_NUM_DEVICES);
		address_offsets[0] = true;
		TRACE("Offset 0 ocupied by a container");
		return 0;
	}


	for (int i=0; i < MAX_NUM_DEVICES; i++) {
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

	char * ipv4_next = mem_printf(IPV4_CMLD_ADDRESS, offset+IPV4_SUBNET_OFFS);

	if (!ipv4_next) {
		ERROR("failed to allocate ipv4 address string");
		return -1;
	}

	if (!inet_aton(ipv4_next, ipv4_addr)) {
		mem_free(ipv4_next);
		ERROR("failed to determine free ip address");
		return -1;
	}

	DEBUG("next free ip cmld address is: %s", ipv4_next);
	mem_free(ipv4_next);
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

	char * ipv4_next = mem_printf(IPV4_CONT_ADDRESS, offset+IPV4_SUBNET_OFFS);

	if (!ipv4_next) {
		ERROR("failed to allocate ipv4 address string");
		return -1;
	}

	if (!inet_aton(ipv4_next, ipv4_addr)) {
		mem_free(ipv4_next);
		ERROR("failed to determine free ip address");
		return -1;
	}

	DEBUG("next free ipv4 container address is: %s", ipv4_next);
	mem_free(ipv4_next);
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

		TRACE("veth lookup path: %s, name: %s, parameter to match: %s", path, dp->d_name, if_name);

		if (file_is_link(path)) {
			if (!strncmp(dp->d_name, if_name, IFNAMSIZ)) {
				DEBUG("veth %s is occupied", if_name);
				closedir(dirp);
				mem_free(path);
				return 1;
			}
		}
		mem_free(path);
	}

	DEBUG("veth %s is free", if_name);
	closedir(dirp);
	return 0;
}

/**
 * This function renames a (container namespace) veth name from old_ifi_name to new_ifi_name
 * with a netlink message using the netlink socket.
 */
static int
c_net_rename_ifi(const char *old_ifi_name, const char *new_ifi_name)
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

	struct ifinfomsg link_req = {
		.ifi_family = AF_INET,
		.ifi_index = ifi_index_old
	};

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

/**
 * This function moves the network interface to the corresponding namespace,
 * specified by the pid (from root namespace to container namespace).
 * It transmits a netlink message using the netlink socket
 */
int
c_net_move_ifi(const char *ifi_name, const pid_t pid)
{
	ASSERT(ifi_name);

	nl_sock_t *nl_sock = NULL;
	unsigned int ifi_index;
	nl_msg_t *req = NULL;

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
	struct ifinfomsg link_req = {
		.ifi_family = AF_INET,
		.ifi_index = ifi_index	/* The index of the interface */
	};

	/* Fill netlink message header */
	if (nl_msg_set_type(req, RTM_NEWLINK))
		goto msg_err;

	/* Set appropriate flags for request, creating new object,
	 * exclusive access and acknowledgment response */
	if (nl_msg_set_flags(req, NLM_F_REQUEST | NLM_F_ACK))
		goto msg_err;

	/* Fill link request header of request message */
	if (nl_msg_set_link_req(req, &link_req))
		goto msg_err;

	/* Set the PID in the netlink header */
	if (nl_msg_add_u32(req, IFLA_NET_NS_PID, pid))
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
 * This function removes the network interface from the corresponding namespace,
 * specified by the pid
 */
int
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
c_net_create_veth_pair(const char *veth1, const char *veth2)
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
	struct ifinfomsg link_req = {
		.ifi_family = AF_INET
	};

	struct rtattr *attr1, *attr2, *attr3;

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
	struct ifaddrmsg ip_req = {
		.ifa_family = AF_INET,
		.ifa_prefixlen = IPV4_PREFIX,
		.ifa_index = ifi_index,	/* The index of the interface */
		.ifa_scope = RT_SCOPE_UNIVERSE
	};

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
c_net_interface_new(const char *if_name)
{
	ASSERT(if_name);

	c_net_interface_t *ni = mem_new0(c_net_interface_t, 1);
	ni->nw_name = mem_printf("%s", if_name);

	/* Get container offset based on currently started containers */
	if ((ni->cont_offset = c_net_set_next_offset()) == -1) {
		WARN_ERRNO("Maximum offset for Network interfaces reached!");
		return NULL;
	}

	ni->veth_cmld_name = mem_printf("r_%d", ni->cont_offset);
	ni->veth_cont_name = mem_printf("c_%d", ni->cont_offset);
	return ni;
}

/**
 * This function allocates a new c_net_t instance, associated to a specific container object.
 * @return the c_net_t network structure which holds networking information for a container.
 */
c_net_t *
c_net_new(container_t *container, bool net_ns, list_t *nw_name_list, list_t *nw_mv_name_list, uint16_t adb_port)
{
	ASSERT(container);

	c_net_t *net = mem_new0(c_net_t, 1);
	net->container = container;
	net->ns_net = net_ns;
	net->adb_port = adb_port;

	/* if the container does not have a network namespace, we don't execute any of this,
	 * i.e. we always return at the start of the functions  */
	if (!net_ns) {
		return net;
	}

	for (list_t *l = nw_name_list; l; l = l->next) {
		char *if_name = l->data;

		c_net_interface_t *ni = c_net_interface_new(if_name);
		ASSERT(ni);
		net->interface_list = list_append(net->interface_list, ni);

		TRACE("new c_net_interface_t struct %s was allocated", ni->nw_name);
	}

	for (list_t *l = nw_mv_name_list; l; l = l->next) {
		char *if_name = l->data;

		net->interface_mv_name_list = list_append(net->interface_mv_name_list, strdup(if_name));
	}

	if (adb_port > 0) {
		c_net_interface_t *ni_adb = c_net_interface_new(ADB_INTERFACE_NAME);
		net->interface_list = list_append(net->interface_list, ni_adb);
	}

	TRACE("new c_net struct was allocated");

	return net;
}

static int
c_net_setup_port_forwarding(c_net_interface_t *ni, uint16_t srcport, uint16_t dstport, bool enable)
{
	ASSERT(ni);

	int ret;

	char *src_ip = mem_strdup(inet_ntoa(ni->ipv4_cmld_addr));
	char *dst_ip = mem_strdup(inet_ntoa(ni->ipv4_cont_addr));

	ret = network_setup_port_forwarding(src_ip, srcport, dst_ip, dstport, enable);

	mem_free(dst_ip);
	mem_free(src_ip);

	return ret;
}

static int
c_net_bring_up_link_and_route(const char *if_name, const char *subnet, bool up)
{
	if (network_set_flag(if_name, up?IFF_UP:IFF_DOWN))
		return -1;
	// setup proper route to subnet via interface
	int error = network_setup_route(subnet, if_name, up);
	if (error) {
		if (error!=2) {
			ERROR("Failed to setup route %s (%i)", subnet, error);
			return -1;
		}
		WARN("Failed to setup route %s (already %s)", subnet, up?"exists":"removed");
	}
	return 0;
}


static int
c_net_write_dhcp_config(c_net_interface_t *ni)
{
	ASSERT(ni);

	int bytes_written = 0;

	char *conf_dir = mem_printf("/data/misc/dhcp/dnsmasq.d");
	char *conf_file = mem_printf("%s/%s.conf", conf_dir, ni->veth_cmld_name);
	char *ipv4_start = mem_printf(IPV4_DHCP_RANGE_START, ni->cont_offset);
	char *ipv4_end  = mem_printf(IPV4_DHCP_RANGE_END, ni->cont_offset);

	// create config dir if not created yet
	if (dir_mkdir_p(conf_dir, 0755) < 0) {
		DEBUG_ERRNO("Could not mkdir %s", conf_dir);
		return -1;
	}

	bytes_written = file_printf(conf_file, "interface=%s\n dhcp-range=%s,%s,1h", ni->veth_cmld_name,
			ipv4_start, ipv4_end);

	if (chmod(conf_file, 00644) < 0)
		ERROR_ERRNO("changing of file access rights failed");

	// restart dnsmasq a0's init while restart it
	proc_killall(-1, "dnsmasq", SIGTERM);

	mem_free(conf_dir);
	mem_free(conf_file);
	mem_free(ipv4_start);
	mem_free(ipv4_end);

	if (bytes_written > 0)
		return 0;

	return -1;
}

static int
c_net_start_pre_clone_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	/* Get root ns ipv4 address */
	if (c_net_get_next_ipv4_cmld_addr(ni->cont_offset, &ni->ipv4_cmld_addr)) {
		ERROR("failed to retrieve a root ns ip address");
		goto err;
	}

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

	/* Create free veth pair from container name, check if the interfaces are free */
	if (c_net_is_veth_used(ni->veth_cmld_name)) {
		ERROR("root ns veth %s already in use", ni->veth_cmld_name);
		goto err;
	}
	if (c_net_is_veth_used(ni->veth_cont_name)) {
		ERROR("container veth %s already in use", ni->veth_cont_name);
		goto err;
	}

	/* Start with second step: create veth pair, set root ns ipv4 add, bring the interface up */
	DEBUG("Create veth pair %s/%s", ni->veth_cont_name, ni->veth_cmld_name);

	/* Create veth pair */
	if (c_net_create_veth_pair(ni->veth_cont_name, ni->veth_cmld_name))
		goto err;

	DEBUG("Set root ns ipv4 address");

	/* Set IPv4 address */
	if (c_net_set_ipv4(ni->veth_cmld_name, &ni->ipv4_cmld_addr, &ni->ipv4_bc_addr))
		goto err;

	// set subnet string
	uint32_t ip = ntohl(ni->ipv4_cmld_addr.s_addr);
	uint32_t mask = ~(((uint32_t)-1) >> IPV4_PREFIX);
	struct in_addr net = { .s_addr = htonl(ip & mask) };
	ni->subnet = mem_printf("%s/%d", inet_ntoa(net), IPV4_PREFIX);
	IF_NULL_GOTO_ERROR(ni->subnet, err);

	/* Write dhcp config for dnsmasq skip first veth (which is used in a0) */
	if (ni->cont_offset > 0) {
		if (c_net_write_dhcp_config(ni))
			goto err;
	}

	return 0;

	/* In case of an error, release the current offset */
	err:
		c_net_unset_offset(ni->cont_offset);
		// FIXME also delete veth pair if it was created?!
		return -1;
}

/**
  * First part: get currently free ipv4 and veth addresses/names for the network setup.
  * Second part: Create a veth pair and configure the root namespace veth
  * Third part: Setup routing and filtering/nat.
  * by setting its ipv4 and bringing up the interface.
  * @return: 0 on success, -1 in case of failure.
  */
int
c_net_start_pre_clone(c_net_t *net)
{
	ASSERT(net);

	/* If container has no network namespace, we can just skip, as every networking
	 * operation will be skipped */
	if (!net->ns_net) return 0;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (c_net_start_pre_clone_interface(ni) == -1)
			return -1;

		if (!strcmp(ni->nw_name, ADB_INTERFACE_NAME)) {
			if (c_net_setup_port_forwarding(ni, net->adb_port, ADB_DAEMON_PORT, true))
				return -1;
		} else {
			if (network_setup_masquerading(ni->subnet, true))
				return -1;
		}
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

	if (ni->cont_offset == 0 && hardware_get_radio_ifname()) {
		/* Rename the rootns first veth to the RADIO_IFACE_NAME name */
		if (c_net_rename_ifi(ni->veth_cmld_name, hardware_get_radio_ifname()))
			return -1;

		mem_free(ni->veth_cmld_name);
		ni->veth_cmld_name = mem_strdup(hardware_get_radio_ifname());
	}

	DEBUG("set IFF_UP for veth: %s", ni->veth_cmld_name);
	/* Bring veth up */
	if (c_net_bring_up_link_and_route(ni->veth_cmld_name, ni->subnet, true))
		return -1;

	return 0;
}

/**
 * This function is responisble for moving the container interface to its corresponding namespace.
 */
int
c_net_start_post_clone(c_net_t *net)
{
	ASSERT(net);

	/* Skip, if the container doesn't have a network ns */
	if (!net->ns_net)
		return 0;

	/* Get container's pid */
	pid_t pid = container_get_pid(net->container);

	for (list_t *l = net->interface_mv_name_list; l; l = l->next) {
		char *iff_name = l->data;

		DEBUG("move phys %s to the ns of this pid: %d", iff_name, pid);
		if (c_net_move_ifi(iff_name, pid) < 0)
			return -1;
	}

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (c_net_start_post_clone_interface(pid, ni) == -1)
			return -1;
	}

	return 0;
}

static int
c_net_start_child_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	DEBUG("rename ifi from %s to %s", ni->veth_cont_name, ni->nw_name);

	/* Rename container veth to the given if name */
	if (c_net_rename_ifi(ni->veth_cont_name, ni->nw_name))
		return -1;

	DEBUG("set ipv4 (addr: %s) for %s", inet_ntoa(ni->ipv4_cont_addr), ni->nw_name);

	/* Set IPv4 address */
	if (c_net_set_ipv4(ni->nw_name, &ni->ipv4_cont_addr, &ni->ipv4_bc_addr))
		return -1;

	/* bring net->nw_name interface up */
	DEBUG("bring %s interface up", ni->nw_name);

	if (c_net_bring_up_link_and_route(ni->nw_name, ni->subnet, true))
		return -1;

	return 0;
}

/**
 * In the container namespace, rename the interface to net->nw_name,
 * set the ipv4 container address and bring the interfaces up.
 */
int
c_net_start_child(c_net_t *net)
{
	ASSERT(net);

	/* Skip this, if the container doesn't have a network namespace */
	if (!net->ns_net || !(list_length(net->interface_list) > 0))
		return 0;

	// shrink subnet reserverd for loopback device
	if (network_setup_loopback())
		return -1;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		/* mask ifname to avoid renaming interfaces in privileged container */
		if (container_is_privileged(net->container)) {
			mem_free(ni->nw_name);
			ni->nw_name = mem_strdup(ni->veth_cont_name);
		}
		if (c_net_start_child_interface(ni) == -1)
			return -1;
	}

	// setup default route for first ni
	c_net_interface_t* first_ni = list_nth_data(net->interface_list, 0);
	network_setup_default_route(inet_ntoa(first_ni->ipv4_cmld_addr), true);

	return 0;
}

static void
c_net_cleanup_interface(c_net_interface_t *ni)
{
	ASSERT(ni);

	DEBUG("shut network interface %s down", ni->veth_cont_name);

	/* shut the network interface down */
	if (c_net_bring_up_link_and_route(ni->veth_cmld_name, ni->subnet, false))
		WARN("network interface could not be gracefully shut down");

	if (network_delete_link(ni->veth_cmld_name))
		WARN("network interface %s could not be destroyed", ni->veth_cmld_name);

	TRACE("cleanup c_net_t structure");

	/* Release the offset, as the ip addresses are no more occupied */
	c_net_unset_offset(ni->cont_offset);

	if (ni->subnet) {
		mem_free(ni->subnet);
		ni->subnet = NULL;
	}
	memset(&ni->ipv4_cmld_addr, 0, sizeof(struct in_addr));
	memset(&ni->ipv4_cont_addr, 0, sizeof(struct in_addr));
	memset(&ni->ipv4_bc_addr, 0, sizeof(struct in_addr));
}

/**
 * Cleans up the c_net_t struct and shuts down the network interface.
 */
void
c_net_cleanup(c_net_t *net)
{
	ASSERT(net);

	/* We can skip this in case the container has no network ns */
	if (!net->ns_net || !(list_length(net->interface_list)))
		return;

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;

		if (!strcmp(ni->nw_name, ADB_INTERFACE_NAME)) {
			if (c_net_setup_port_forwarding(ni, net->adb_port, ADB_DAEMON_PORT, false))
				WARN("Failed to remove port forwarding from %" PRIu16 " to %s:%" PRIu16,
						net->adb_port, inet_ntoa(ni->ipv4_cont_addr), ADB_DAEMON_PORT);
		} else {
			if (network_setup_masquerading(ni->subnet, false))
				WARN("Failed to remove masquerading from %s", ni->subnet);
		}

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
		mem_free(ni->subnet);
	mem_free(ni->veth_cmld_name);
	mem_free(ni->veth_cont_name);
	mem_free(ni->nw_name);
	mem_free(ni);
}

/**
 * Frees the c_net_t structure
 */
void
c_net_free(c_net_t *net)
{
	ASSERT(net);

	for (list_t *l = net->interface_list; l; l = l->next) {
		c_net_interface_t *ni = l->data;
		c_net_free_interface(ni);
	}
	list_delete(net->interface_list);
	for (list_t *l = net->interface_mv_name_list; l; l = l->next) {
		mem_free(l->data);
	}
	list_delete(net->interface_mv_name_list);
	mem_free(net);
}

char *
c_net_get_ip_new(c_net_t* net)
{
	if (!net->ns_net)
		return NULL;

	c_net_interface_t *ni0 = list_nth_data(net->interface_list, 0);
	return mem_strdup(inet_ntoa(ni0->ipv4_cont_addr));
}

char *
c_net_get_subnet_new(c_net_t* net)
{
	if (!net->ns_net)
		return NULL;

	c_net_interface_t *ni0 = list_nth_data(net->interface_list, 0);
	return mem_strdup(ni0->subnet);
}
