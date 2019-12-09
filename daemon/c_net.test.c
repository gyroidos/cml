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
 * @file c_net.test.c
 *
 * Unit Test for c_net.c. Tests the offset and address retrievel functionality, which
 * must be given to ensure that containers obtain and free correct adresses and devices.
 */
#include "common/list.h"
#include "container.stub.h"
#include "c_net.c"

int
main(void)
{
	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: c_net.test.c");

	DEBUG("Create a first container without namespace and do the common network setup");

	list_t *nw_name_list = NULL;

	// this functions must work for a0, as it has no network namespace, i.e.
	// the functions should return immediately.
	container_t *cont0 = container_stub_new("a0");
	c_net_t *net0 = c_net_new(cont0, false, nw_name_list, 0);
	ASSERT(net0);

	ASSERT(c_net_start_pre_clone(net0) == 0);
	ASSERT(c_net_start_post_clone(net0) == 0);
	//ASSERT(c_net_start_child(net0) == 0); (should not be run on host)
	c_net_cleanup(net0);

	DEBUG("Create a second container with network namespace and check offset and ip");
	container_t *cont1 = container_stub_new("a1");

	nw_name_list = list_append(nw_name_list, "wlan0");
	c_net_t *net1 = c_net_new(cont1, true, nw_name_list, 0);
	ASSERT(net1);

	// set and verify offset
	list_t *nil1 = list_tail(net1->interface_list);
	c_net_interface_t *ni1 = nil1->data;
	ni1->cont_offset = c_net_set_next_offset();
	ASSERT(ni1->cont_offset == 0);

	// get ip information for cont1
	ASSERT(c_net_get_next_ipv4_cmld_addr(ni1->cont_offset, &ni1->ipv4_cmld_addr) == 0);
	ASSERT(c_net_get_next_ipv4_cont_addr(ni1->cont_offset, &ni1->ipv4_cont_addr) == 0);
	ASSERT(c_net_get_next_ipv4_bcaddr(&ni1->ipv4_cont_addr, &ni1->ipv4_bc_addr) == 0);

	// check ip information of cont1
	char *cmld_ip_string = mem_printf(IPV4_CMLD_ADDRESS, IPV4_SUBNET_OFFS);
	char *cont_ip_string = mem_printf(IPV4_CONT_ADDRESS, IPV4_SUBNET_OFFS);

	// assumption that 127.1. is defined. If define changes in c_net.c, this must be adapted
	char *bc_ip_string = mem_printf("127.1.%d.255", IPV4_SUBNET_OFFS);

	char *real_cmld_ip_string = mem_strdup(inet_ntoa(ni1->ipv4_cmld_addr));
	char *real_cont_ip_string = mem_strdup(inet_ntoa(ni1->ipv4_cont_addr));
	char *real_bc_ip_string = mem_strdup(inet_ntoa(ni1->ipv4_bc_addr));
	DEBUG("cmld ip: expected %s vs %s; cont ip: expected %s vs %s; bc ip: expected %s vs %s", cmld_ip_string,
	      real_cmld_ip_string, cont_ip_string, real_cont_ip_string, bc_ip_string, real_bc_ip_string);

	ASSERT(!strncmp(cmld_ip_string, real_cmld_ip_string, strlen(cmld_ip_string)));
	ASSERT(!strncmp(cont_ip_string, real_cont_ip_string, strlen(cont_ip_string)));
	ASSERT(!strncmp(bc_ip_string, real_bc_ip_string, strlen(bc_ip_string)));

	DEBUG("Create a third container with namespace and check ip and offsets");

	container_t *cont3 = container_stub_new("a2");
	c_net_t *net3 = c_net_new(cont3, true, nw_name_list, 0);
	ASSERT(net3);

	// third container, but second one with nw namespace, i.e. offset is 1
	list_t *nil3 = list_tail(net3->interface_list);
	c_net_interface_t *ni3 = nil3->data;
	ASSERT(ni3);

	ni3->cont_offset = c_net_set_next_offset();
	ASSERT(ni3->cont_offset == 1);

	ASSERT(c_net_get_next_ipv4_cmld_addr(ni3->cont_offset, &ni3->ipv4_cmld_addr) == 0);
	ASSERT(c_net_get_next_ipv4_cont_addr(ni3->cont_offset, &ni3->ipv4_cont_addr) == 0);
	ASSERT(c_net_get_next_ipv4_bcaddr(&ni3->ipv4_cont_addr, &ni3->ipv4_bc_addr) == 0);

	cmld_ip_string = mem_printf(IPV4_CMLD_ADDRESS, IPV4_SUBNET_OFFS + 1);
	cont_ip_string = mem_printf(IPV4_CONT_ADDRESS, IPV4_SUBNET_OFFS + 1);
	// assumption that 127.1. is defined. If define changes in c_net.c, this must be adapted
	bc_ip_string = mem_printf("127.1.%d.255", IPV4_SUBNET_OFFS + 1);

	real_cmld_ip_string = mem_strdup(inet_ntoa(ni3->ipv4_cmld_addr));
	real_cont_ip_string = mem_strdup(inet_ntoa(ni3->ipv4_cont_addr));
	real_bc_ip_string = mem_strdup(inet_ntoa(ni3->ipv4_bc_addr));
	DEBUG("cmld ip: expected %s vs %s; cont ip: expected %s vs %s; bc ip: expected %s vs %s", cmld_ip_string,
	      real_cmld_ip_string, cont_ip_string, real_cont_ip_string, bc_ip_string, real_bc_ip_string);

	ASSERT(!strncmp(cmld_ip_string, real_cmld_ip_string, strlen(cmld_ip_string)));
	ASSERT(!strncmp(cont_ip_string, real_cont_ip_string, strlen(cont_ip_string)));
	ASSERT(!strncmp(bc_ip_string, real_bc_ip_string, strlen(bc_ip_string)));

	DEBUG("Check offset functionality");

	// shut down a container. in reality, a0 shouldn't be shut down
	// however, this is only to test offsets
	c_net_unset_offset(ni1->cont_offset);

	// offset 0 should be free now
	ASSERT(c_net_set_next_offset() == 0);

	ASSERT(c_net_set_next_offset() == 2);
	ASSERT(c_net_set_next_offset() == 3);
	c_net_unset_offset(2);
	ASSERT(c_net_set_next_offset() == 2);
	ASSERT(c_net_set_next_offset() == 4);

	DEBUG("offset checking done");

	list_delete(nw_name_list);
	mem_free(real_cmld_ip_string);
	mem_free(real_cont_ip_string);
	mem_free(real_bc_ip_string);
	mem_free(cmld_ip_string);
	mem_free(cont_ip_string);
	mem_free(bc_ip_string);
	container_free(cont0);
	c_net_free(net0);
	container_free(cont1);
	c_net_free(net1);
	container_free(cont3);
	c_net_free(net3);

	return 0;
}
