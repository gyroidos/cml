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
#include "device/fraunhofer/common/cml/control/control.pb-c.h"
#else
#include "control.pb-c.h"
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"

#include <getopt.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>

#define CONTROL_SOCKET SOCK_PATH(control)

#define DEFAULT_KEY "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static void print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s <socket file>] <command> [<command args>]\n", cmd);
	printf("\n");
	printf("commands:\n");
	printf("   list\n        Lists all containers.\n");
	printf("   wipe_device\n        Wipes all containers on the device.\n");
	printf("   start <container-uuid> [--key=<key>]\n        Starts the container with the given key (default: all '0') .\n");
	printf("   stop <container-uuid>\n        Stops the specified container.\n");
	printf("   config <container-uuid>\n        Prints the config of the specified container.\n");
	printf("   state <container-uuid>\n        Prints the state of the specified container.\n");
	printf("   freeze <container-uuid>\n        Freeze the specified container.\n");
	printf("   unfreeze <container-uuid>\n        Unfreeze the specified container.\n");
	printf("   allow_audio <container-uuid>\n        Grant audio access to the specified container (cgroups).\n");
	printf("   deny_audio <container-uuid>\n        Deny audio access to the specified container (cgroups).\n");
	printf("   wipe <container-uuid>\n        Wipes the specified container.\n");
	printf("   push_guestos_config <guestos.conf> <guestos.sig> <guestos.pem>\n        (testing) Pushes the specified GuestOS config, signature, and certificate files.\n");
	printf("   assign_iface --iface <iface_name> <container-uuid> [--persistent]\n        Assign the specified network interface to the specified container. If the 'persistent' option is set, the container config file will be modified accordingly.\n");
	printf("   unassign_iface --iface <iface_name> <container-uuid> [--persistent]\n        Unassign the specified network interface from the specified container. If the 'persistent' option is set, the container config file will be modified accordingly.\n");
	printf("   ifaces <container-uuid>\n        Prints the list of network interfaces assigned to the specified container.\n");
	printf("\n");
	exit(-1);
}

static void send_message(const char *socket_file, ControllerToDaemon *msg, bool has_response)
{
	// send message
	//protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) msg);
	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0) {
		exit(-3);
	}
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *) msg);
	if (msg_size < 0) {
		exit(-4);
	}
	// recv response if applicable
	// TODO for now just dump the response in text format
	if (has_response) {
		DaemonToController *resp = (DaemonToController *) protobuf_recv_message(sock, &daemon_to_controller__descriptor);
		if (!resp) {
			exit(-5);
		}

		protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) resp);
		protobuf_free_message((ProtobufCMessage *) resp);
	}

	fsync(sock);

	// give cmld some time to handle message before closing socket
	if (!has_response)
		usleep(200 * 1000);

	shutdown(sock, SHUT_RDWR);
	close(sock);
}

static const struct option global_options[] = {
	{"socket",   required_argument, 0, 's'},
	{"help",     no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static const struct option start_options[] = {
	{"key",         optional_argument, 0, 'k'},
	{"no-switch",   no_argument, 0, 'n'},
	{0, 0, 0, 0}
};

static const struct option assign_iface_options[] = {
	{"iface",	required_argument, 0, 'i'},
	{"persistent",	no_argument, 0, 'p'},
	{0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	logf_register(&logf_test_write, stderr);

	bool has_response = false;
	const char *socket_file = CONTROL_SOCKET;
	for (int c, option_index = 0; -1 != (c = getopt_long(argc, argv, "+s:h",
					global_options, &option_index)); ) {
		switch (c) {
		case 's':
			socket_file = optarg;
			break;
		default: // includes cases 'h' and '?'
			print_usage(argv[0]);
		}
	}

	if (!file_exists(socket_file)) {
		WARN("Could not find socket file %s. Aborting.\n", socket_file);
		exit(-2);
	}

	// need at least one more argument (i.e. command string)
	if (optind >= argc)
		print_usage(argv[0]);

	// build ControllerToDaemon message
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;

	const char *command = argv[optind++];
	if (!strcasecmp(command, "list")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
		has_response = true;
		goto send_message;
	}
	if (!strcasecmp(command, "wipe_device")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__WIPE_DEVICE;
		goto send_message;
	}
	if (!strcasecmp(command, "push_guestos_config")) {
		if (optind+2 >= argc)
			print_usage(argv[0]);

		const char* cfgfile = argv[optind++];
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0) {
			ERROR("Error accessing config file %s.", cfgfile);
			exit(-2);
		}

		const char* sigfile = argv[optind++];
		off_t siglen = file_size(sigfile);
		if (siglen < 0) {
			ERROR("Error accessing signature file %s.", sigfile);
			exit(-2);
		}

		const char* certfile = argv[optind++];
		off_t certlen = file_size(certfile);
		if (certlen < 0) {
			ERROR("Error accessing certificate file %s.", certfile);
			exit(-2);
		}

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char*)cfg, cfglen) < 0) {
			ERROR("Error reading %s. Aborting.", cfgfile);
			exit(-2);
		}
		unsigned char *sig = mem_alloc(siglen);
		if (file_read(sigfile, (char*)sig, siglen) < 0) {
			ERROR("Error reading %s. Aborting.", sigfile);
			exit(-2);
		}
		unsigned char *cert = mem_alloc(certlen);
		if (file_read(certfile, (char*)cert, certlen) < 0) {
			ERROR("Error reading %s. Aborting.", certfile);
			exit(-2);
		}
		INFO("Pushing cfg %s (len %zu), sig %s (len %zu), and cert %s (len %zu).",
				cfgfile, (size_t)cfglen, sigfile, (size_t)siglen, certfile, (size_t)certlen);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG;
		msg.has_guestos_config_file = true;
		msg.guestos_config_file.len = cfglen;
		msg.guestos_config_file.data = cfg;
		msg.has_guestos_config_signature = true;
		msg.guestos_config_signature.len = siglen;
		msg.guestos_config_signature.data = sig;
		msg.has_guestos_config_certificate = true;
		msg.guestos_config_certificate.len = certlen;
		msg.guestos_config_certificate.data = cert;
		goto send_message;
	}

	ContainerStartParams container_start_params = CONTAINER_START_PARAMS__INIT;
	if (!strcasecmp(command, "start")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START;
		msg.container_start_params = &container_start_params;
		// parse specific options for start command
		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0; -1 != (c = getopt_long(start_argc, start_argv,
						"k::n", start_options, &option_index)); ) {
			switch (c) {
			case 'k':
				container_start_params.key = optarg ? optarg : DEFAULT_KEY;
				break;
			default:
				print_usage(argv[0]);
				ASSERT(false); // never reached
			}
		}
		optind += argc - start_argc;	// adjust optind to be used with argv
	} else if (!strcasecmp(command, "stop")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP;
	} else if (!strcasecmp(command, "freeze")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_FREEZE;
	} else if (!strcasecmp(command, "unfreeze")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNFREEZE;
	} else if (!strcasecmp(command, "wipe")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_WIPE;
	} else if (!strcasecmp(command, "snapshot")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SNAPSHOT;
	} else if (!strcasecmp(command, "allow_audio")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ALLOWAUDIO;
	} else if (!strcasecmp(command, "deny_audio")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_DENYAUDIO;
	} else if (!strcasecmp(command, "state")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
		has_response = true;
	} else if (!strcasecmp(command, "config")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG;
		has_response = true;
	} else if (!strcasecmp(command, "ifaces")) {
                msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_LIST_IFACES;
                has_response = true;
	} else if (!strcasecmp(command, "assign_iface") || !strcasecmp(command, "unassign_iface") ) {
		AssignInterfaceParams assign_iface_params = ASSIGN_INTERFACE_PARAMS__INIT;
		msg.assign_iface_params = &assign_iface_params;

                optind--;
                char **start_argv = &argv[optind];
                int start_argc = argc - optind;
                optind = 0; // reset optind to scan command-specific options
                for (int c, option_index = 0; -1 != (c = getopt_long(start_argc, start_argv,
                                                "i::p", assign_iface_options, &option_index)); ) {
                        switch (c) {
                        case 'i':
                                assign_iface_params.iface_name = optarg;
                                break;
                        case 'p':
                                assign_iface_params.has_persistent = true;
                                assign_iface_params.persistent = true;
                                break;
                        default:
                                print_usage(argv[0]);
                                ASSERT(false); // never reached
                        }
                }
                optind += argc - start_argc;    // adjust optind to be used with argv

		if ( !strcasecmp(command, "assign_iface") ){
	                msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ASSIGNIFACE;
		} else if ( !strcasecmp(command, "unassign_iface") ){
                        msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNASSIGNIFACE;
		} else
			ASSERT(false); // should never be reached
	} else
		print_usage(argv[0]);

	// need exactly one more argument (i.e. container string)
	if (optind != argc-1)
		print_usage(argv[0]);

	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = argv[optind];

send_message:
	send_message(socket_file, &msg, has_response);

	return 0;
}

