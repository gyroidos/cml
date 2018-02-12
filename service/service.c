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

#ifdef ANDROID
#include "device/fraunhofer/common/cml/service/c_service.pb-c.h"
#else
#include "c_service.pb-c.h"
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/logf.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/event.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#include "dumb_init.h"

#define SERVICE_SOCKET SOCK_PATH(service)
#define LOGFILE_PATH "/var/log/container.log"

static logf_handler_t *service_logfile_handler = NULL;

static int
service_set_hostname(int fd)
{
	int rc = 0;
	char *name = NULL;
	char *line = NULL;

	CmldToServiceMessage *resp = NULL;
	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_NAME_REQ;

	ssize_t msg_size = protobuf_send_message(fd, (ProtobufCMessage *) &msg);
	if (msg_size < 0)
		WARN("Could not send ireqest for hostname!, error: %zd\n", msg_size);

	resp = (CmldToServiceMessage *) protobuf_recv_message(fd, &cmld_to_service_message__descriptor);

	//protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) resp);
	if (!resp || (resp->code != CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_NAME)) {
		name = "localhost";
		WARN("Wrong Response Message received! faling back to default hostname: %s", name);
	} else
		name = resp->container_cfg_name;

	// write hostname to /etc/hosts
	line = mem_printf("127.0.1.1\t %s\n", name);
	if (file_exists("/etc/hosts")) { // save and restore stock file
		if (!file_exists("/etc/hosts.stock"))
			rc = file_copy("/etc/hosts", "/etc/hosts.stock", file_size("/etc/hosts"), 512, 0);
		else
			rc = file_copy("/etc/hosts.stock", "/etc/hosts", file_size("/etc/hosts.stock"), 512, 0);
	}
	rc += file_write_append("/etc/hosts", line, strlen(line));

	// write hostname to kernel
	rc += file_write("/proc/sys/kernel/hostname", name, strlen(name));

	mem_free(line);
	if (resp)
		protobuf_free_message((ProtobufCMessage *) resp);

	return rc;
}

static int
service_set_dnsserver(int fd)
{
	int rc;
	char *dns_addr = NULL;
	char *line = NULL;

	CmldToServiceMessage *resp = NULL;
	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__CONTAINER_CFG_DNS_REQ;

	ssize_t msg_size = protobuf_send_message(fd, (ProtobufCMessage *) &msg);
	if (msg_size < 0)
		WARN("Could not send reqest for dns_server!, error: %zd\n", msg_size);

	resp = (CmldToServiceMessage *) protobuf_recv_message(fd, &cmld_to_service_message__descriptor);

	if (!resp || (resp->code != CMLD_TO_SERVICE_MESSAGE__CODE__CONTAINER_CFG_DNS)) {
		dns_addr = "8.8.8.8";
		WARN("Wrong response message received! falling back to default dns: %s", dns_addr);
	} else
		dns_addr = resp->container_cfg_dns;

	line = mem_printf("nameserver %s\n", dns_addr);
	rc = file_write("/etc/resolv.conf", line, strlen(line));

	mem_free(line);
	if (resp)
		protobuf_free_message((ProtobufCMessage *) resp);

	return rc;
}

static int
service_fork_execvp(char *prog, char **argv)
{
	pid_t child_pid = fork();
	if (child_pid < 0) {
		ERROR_ERRNO("fork failed!");
		return -1;
	}
	if (0 == child_pid) { //child
		if (-1 == setsid()) {
			ERROR_ERRNO("child process setsid failed!");
			return -1;
		}
		if (-1 == execvp(prog, (char **)argv)) {
			ERROR_ERRNO("child process execve failed!");
			return -1;
		}
	}
	// parent
	dumb_init_set_child_pid(child_pid);
	INFO("Started child '%s' in background.", prog);
	return 0;
}

int
main(int argc, char **argv)
{
	bool do_init = true;

	//logf = fopen (LOGFILE_PATH, "w+");
	service_logfile_handler = logf_register(&logf_file_write, logf_file_new(LOGFILE_PATH));
	logf_handler_set_prio(service_logfile_handler, LOGF_PRIO_TRACE);

	if (argc < 2) {
		INFO("No child program specified, so we do not run as init!");
		do_init = false;
	}

	const char *socket_file = SERVICE_SOCKET;
	if (!file_exists(socket_file))
		FATAL("Could not find socket file %s. Aborting.", socket_file);

	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0) {
		FATAL("Could not connect to service on socket file %s. Aborting.", socket_file);
	}

	// set hostname received from cmld
	if (service_set_hostname(sock) < 0)
		WARN("Failed to set hostname");
	else
		DEBUG("Sucessfully setup hostname");

	// set dns server received from cmld
	if (service_set_dnsserver(sock) < 0)
		WARN("Failed to set DNS server");
	else
		DEBUG("Sucessfully setup DNS server");

	INFO("Minimal init done, going to start child, %s ...", argv[1]);

	if (do_init) {
		if (service_fork_execvp(argv[1], &argv[1]))
			WARN("Error starting child!");
	}

	ServiceToCmldMessage msg = SERVICE_TO_CMLD_MESSAGE__INIT;
	msg.code = SERVICE_TO_CMLD_MESSAGE__CODE__BOOT_COMPLETED;

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *) &msg);
	if (msg_size < 0)
		WARN("Could not send boot complete msg!, error: %zd\n", msg_size);

	fsync(sock);

	// give cmld some time to handle message before closing socket
	usleep(200 * 1000);
	shutdown(sock, SHUT_WR);
	close(sock);

	if (!do_init)
		return 0;

	INFO("Going to handle signals ...");
	dumb_init_signal_handler();

	return 0;

}
