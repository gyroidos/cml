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
#define RUN_PATH "run"
#define DEFAULT_KEY "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static void print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s <socket file>] <command> [<command args>]\n", cmd);
	printf("\n");
	printf("commands:\n");
	printf("   list\n        Lists all containers.\n");
	printf("   reload\n        Reloads containers from config files.\n");
	printf("   wipe_device\n        Wipes all containers on the device.\n");
	printf("   create <container.conf>\n        Creates a container from the given config file.\n");
	printf("   remove <container-uuid>\n        Removes the specified container (completely).\n");
	printf("   start <container-uuid> [--key=<key>] [--setup] \n        Starts the container with the given key (default: all '0') .\n");
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
	printf("   run <command> [<arg_1> ... <arg_n>] <container-uuid>\n        Runs the specified command with the given arguments inside the specified container.\n");
	printf("\n");
	exit(-1);
}

static int sock_connect(const char *socket_file)
{
	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0) {
		exit(-3);
	}
	return sock;
}

static void send_message(int sock, ControllerToDaemon *msg)
{
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *) msg);
	if (msg_size < 0) {
		printf("error sending message\n");
		exit(-4);
	}
}

static DaemonToController* recv_message(int sock)
{
	DaemonToController *resp = (DaemonToController *) protobuf_recv_message(sock, &daemon_to_controller__descriptor);
	if (!resp) {
		printf("error receiving message\n");
		exit(-5);
	}
	return resp;
}

static void sock_disconnect(int sock)
{
	// give cmld some time to handle message before closing socket
	fsync(sock);
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
	{"setup",       no_argument, 0, 's'},
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
	int sock = 0;

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
	if (!strcasecmp(command, "reload")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__RELOAD_CONTAINERS;
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

	if (!strcasecmp(command, "create")) {
		has_response = true;
		// need exactly one more argument (container config file)
		if (optind != argc-1)
			print_usage(argv[0]);

		const char* cfgfile = argv[optind++];
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0) {
			ERROR("Error accessing container config file %s.", cfgfile);
			exit(-2);
		}

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char*)cfg, cfglen) < 0) {
			ERROR("Error reading %s. Aborting.", cfgfile);
			exit(-2);
		}
		INFO("Creating container with cfg %s (len %zu).", cfgfile, (size_t)cfglen);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CREATE_CONTAINER;
		msg.has_container_config_file = true;
		msg.container_config_file.len = cfglen;
		msg.container_config_file.data = cfg;
		goto send_message;
	}

	ContainerStartParams container_start_params = CONTAINER_START_PARAMS__INIT;
	if (!strcasecmp(command, "remove")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__REMOVE_CONTAINER;
	} else if (!strcasecmp(command, "start")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START;
		msg.container_start_params = &container_start_params;
		// parse specific options for start command
		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0; -1 != (c = getopt_long(start_argc, start_argv,
						"k::s", start_options, &option_index)); ) {
			switch (c) {
			case 'k':
				container_start_params.key = optarg ? optarg : DEFAULT_KEY;
				break;
			case 's':
                                container_start_params.has_setup = true;
                                container_start_params.setup = true;
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
	} else if (!strcasecmp(command, "run") ) {
		if ( optind > argc-2 )
			print_usage(argv[0]);
		has_response = true;
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_PID;
		optind = argc-1;
	} else
		print_usage(argv[0]);

	// need exactly one more argument (i.e. container string)
	if (optind != argc-1)
		print_usage(argv[0]);

	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = argv[optind];

send_message:
	sock = sock_connect(socket_file);
	send_message(sock, &msg);

	// recv response if applicable
	if (has_response){
		DaemonToController *resp = recv_message(sock);

		// do command-specific response processing
		if (!strcasecmp(command, "run") ){
			pid_t pid = resp->container_pid;
		        int run_argc = argc - 1;
			char **run_argv = mem_new(char *, run_argc + 1);
			run_argv[0] = mem_strdup(RUN_PATH);
			run_argv[1] = mem_printf("%u", pid);
			for ( int i = 2; i < run_argc; i++ ){
				run_argv[i] = mem_strdup(argv[i]);
			}
			run_argv[run_argc] = NULL;

			// execute command
			execvp(run_argv[0], run_argv);
			ERROR_ERRNO("run failed");
		} else {
			// TODO for now just dump the response in text format
			protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) resp);
			protobuf_free_message((ProtobufCMessage *) resp);
		}
	}
	sock_disconnect(sock);

	return 0;
}

