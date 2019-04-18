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
#include "device/fraunhofer/common/cml/control/container.pb-c.h"
#else
#include "control.pb-c.h"
#include "container.pb-c.h"
#endif

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/uuid.h"

#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

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
	printf("   update_config <container-uuid> --file=<container.conf>\n        Updates a container's config with the given config file.\n");
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

static uuid_t *
get_container_uuid_new(const char *identifier, int sock)
{
	uuid_t *uuid = uuid_new(identifier);
	if (uuid)
		return uuid;

	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;
	msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
	send_message(sock, &msg);

	DaemonToController *resp = recv_message(sock);
	for (size_t i=0; i < resp->n_container_status; ++i) {
		TRACE("name %s", resp->container_status[i]->name);
		if (0 == strcmp(resp->container_status[i]->name, identifier)) {
			uuid = uuid_new(resp->container_status[i]->uuid);
			break;
		}
	}
	if (!uuid)
		FATAL("Container with provided name does not exist!");

	protobuf_free_message((ProtobufCMessage *) resp);
	return uuid;
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

static const struct option update_cfg_options[] = {
	{"file",   required_argument, 0, 'f'},
	{0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	logf_register(&logf_test_write, stderr);

	bool has_response = false;
	const char *socket_file = CONTROL_SOCKET;
	int sock = 0;

	struct termios termios_before;
	tcgetattr(STDIN_FILENO, &termios_before);

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
	} else if (!strcasecmp(command, "update_config")) {
		const char* cfgfile = NULL;
		has_response = true;
                optind--;
                char **update_argv = &argv[optind];
                int update_argc = argc - optind;
                optind = 0; // reset optind to scan command-specific options
                for (int c, option_index = 0; -1 != (c = getopt_long(update_argc, update_argv,
                                                "f:", update_cfg_options, &option_index)); ) {
                        switch (c) {
                        case 'f':
				cfgfile = optarg ? optarg : NULL;
                                break;
                        default:
                                print_usage(argv[0]);
                                ASSERT(false); // never reached
                        }
                }
                optind += argc - update_argc;    // adjust optind to be used with argv

		//const char* cfgfile = argv[optind++];
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

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UPDATE_CONFIG;
		msg.has_container_config_file = true;
		msg.container_config_file.len = cfglen;
		msg.container_config_file.data = cfg;
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
	} else if (!strcasecmp(command, "run")) {
		if (optind > argc-2)
			print_usage(argv[0]);

		has_response = true;
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_CMD;

		int nopty = 0, argcount = 0;


		msg.has_exec_pty = true;

		if (! strcmp(argv[optind], "nopty")) {
			TRACE("Got nopty option");
			msg.exec_pty = 0;
			nopty = 1;
			optind++;
		} else {
			msg.exec_pty = 1;
		}

		if (optind > argc-2)
			print_usage(argv[0]);

		msg.exec_command = argv[optind];

		if (optind < argc - 1) {
			TRACE("[CLIENT] Allocating %d bytes for arguments", sizeof(char *) * argc);
			msg.exec_args = mem_alloc(sizeof(char *) * argc);

			while (optind < argc - 1) {
				TRACE("[CLIENT] Parsing command arguments at index %d, optind: %d: %s",
					argcount,optind, argv[optind]);
				msg.exec_args[argcount] = mem_strdup(argv[optind]);

				optind++;
				argcount++;
			}
		}

		TRACE("[CLIENT] Done parsing arguments, got %d argsuments", argcount);
		msg.n_exec_args = argcount;
		TRACE("after set n_exec_args");
	} else
		print_usage(argv[0]);

	// need exactly one more argument (i.e. container string)
	if (optind != argc - 1)
		print_usage(argv[0]);

	sock = sock_connect(socket_file);
	uuid_t *uuid = get_container_uuid_new(argv[optind], sock);
	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = mem_strdup(uuid_string(uuid));
	uuid_free(uuid);

send_message:
	if (!sock)
		sock = sock_connect(socket_file);
	send_message(sock, &msg);

	if (!strcasecmp(command, "run")) {
		TRACE("[CLIENT] Processing response for run command");

		if(msg.exec_pty) {
			TRACE("[CLIENT] Setting termios for PTY");
			struct termios termios_run = termios_before;
			termios_run.c_cflag &= ~(ICRNL | IXON | IXOFF );
			termios_run.c_oflag &= ~(OPOST);
			termios_run.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOCTL);
			tcsetattr(STDIN_FILENO, TCSANOW, &termios_run);
		}

		//free exec arguments
		TRACE("[CLIENT] Freeing %d args at %p", msg.n_exec_args, msg.exec_args);
		mem_free_array((void *) msg.exec_args, msg.n_exec_args);
		TRACE("[CLIENT] after free ");

		int pid = fork();

		if (pid == -1) {
			ERROR("[CLIENT] Failed to fork(), exiting...\n");
			goto exit;
		} else if (pid == 0) {
			TRACE("[CLIENT] User input reading child forked, PID: %i", getpid());

			char buf[128];
			unsigned int count;

			while (1) {
				TRACE("[CLIENT] Trying to read input for exec'ed process");

				if ((count = read(STDIN_FILENO, buf, 127)) > 0) {

					buf[count] = 0;

					TRACE("[CLIENT] Got input for exec'ed process: %s", buf);

					ControllerToDaemon inputmsg = CONTROLLER_TO_DAEMON__INIT;
					inputmsg.container_uuids = mem_new(char*, 1);
					inputmsg.container_uuids[0] = argv[optind];
					inputmsg.n_container_uuids = 1;
					inputmsg.command =
					CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_INPUT;
					inputmsg.exec_input = buf;

					TRACE("[CLIENT] Sending input for exec'ed process in container %s", argv[optind]);

					send_message(sock, &inputmsg);
					mem_free(inputmsg.container_uuids);
					TRACE("[CLIENT] Sent input to cmld");
				}
			}
		} else {
			TRACE("[CLIENT] Exec'ed process outputreceiving  child forked, PID: %i", getpid());

			while (1) {
				TRACE("[CLIENT] Waiting for command output message from cmld");
				DaemonToController *resp = recv_message(sock);

				TRACE("[CLIENT] Got message from exec'ed process\n");

				unsigned int count = 0;
				size_t written = 0, current = 0;

				if (resp->code == DAEMON_TO_CONTROLLER__CODE__EXEC_OUTPUT) {
					TRACE("[CLIENT] Message length; %d\n", resp->exec_output.len);
					while (written < resp->exec_output.len) {
						TRACE("[CLIENT] Writing exec output to stdout");
						if(current = write(STDOUT_FILENO, resp->exec_output.data + written,
									resp->exec_output.len - written)) {
							written += current;
						}

						fflush(stdout);
					}

				} else if (resp->code == DAEMON_TO_CONTROLLER__CODE__EXEC_END) {
					TRACE("[CLIENT] Got notification of command termination. Exiting...");

					kill(pid, SIGTERM);
					waitpid(pid, NULL, 0);
					goto exit;
				} else {
					ERROR("Detected unexpected message from cmld. Exiting");
					goto exit;
				}
			}
		}
		ERROR_ERRNO("[CLIENT] command \"run\" failed");
	}

	// recv response if applicable
	if (has_response) {
		TRACE("[CLIENT] Awaiting response");

		DaemonToController *resp = recv_message(sock);

		TRACE("[CLIENT] Got response. Processing");

		// do command-specific response processing
		// TODO for now just dump the response in text format
		protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *) resp);
		protobuf_free_message((ProtobufCMessage *) resp);
	}

exit:
	close(sock);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_before);
	for (size_t i=0; i < msg.n_container_uuids; ++i)
		mem_free(msg.container_uuids[i]);
	mem_free(msg.container_uuids);

	return 0;
}
