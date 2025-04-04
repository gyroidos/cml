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
#include "common/protobuf-text.h"
#include "common/sock.h"
#include "common/file.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/str.h"

#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

// clang-format off
#define CONTROL_SOCKET SOCK_PATH(control)
// clang-format on
#define RUN_PATH "run"
#define DEFAULT_KEY                                                                                \
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static void
print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s <socket file>] <command> [<command args>]\n", cmd);
	printf("\n");
	printf("commands:\n");
	printf("   list\n"
	       "        Lists all containers.\n\n");
	printf("   list_guestos\n"
	       "        Lists all installed guestos configs.\n\n");
	printf("   reload\n"
	       "        Reloads containers from config files.\n\n");
	printf("   wipe_device\n"
	       "        Wipes all containers on the device.\n\n");
	printf("   reboot\n"
	       "        Reboots the whole device, shutting down any containers which are running.\n\n");
	printf("   set_provisioned\n"
	       "        Sets the device to provisioned state which limits certain commands\n\n");
	printf("   get_provisioned\n"
	       "        Gets the device provisioned state.\n\n");
	printf("   device_stats\n"
	       "        Gets the device statistics about memory and disk usage.\n\n");
	printf("   create <container.conf> [<container.sig> <container.cert>]\n"
	       "        Creates a container from the given config file,\n"
	       "        and optionally signature and certificate files\n\n");
	printf("   remove <container-uuid>\n"
	       "        Removes the specified container (completely).\n\n");
	printf("   change_pin <container-uuid>\n"
	       "        Change token pin which is used for container key wrapping.\n"
	       "        Prompts for password entry.\n\n");
	printf("   start <container-uuid> [--key=<key>] [--setup]\n"
	       "        Starts the container with the given key (default: all '0') .\n\n");
	printf("   stop <container-uuid> [--key=<key>]\n"
	       "        Stops the specified container.\n\n");
	printf("   config <container-uuid>\n"
	       "        Prints the config of the specified container.\n\n");
	printf("   update_config <container-uuid> <container.conf> [<container.sig> <container.cert>]\n"
	       "        Updates a container's config with the given config file,\n"
	       "        and optionally signature and certificate files\n\n");
	printf("   state <container-uuid>\n"
	       "        Prints the state of the specified container.\n\n");
	printf("   freeze <container-uuid>\n"
	       "        Freeze the specified container.\n\n");
	printf("   unfreeze <container-uuid>\n"
	       "        Unfreeze the specified container.\n\n");
	printf("   allow_audio <container-uuid>\n"
	       "        Grant audio access to the specified container (cgroups).\n\n");
	printf("   deny_audio <container-uuid>\n"
	       "        Deny audio access to the specified container (cgroups).\n\n");
	printf("   dev_access <container-uuid>\n"
	       "        Set Access rule of a device for the specified container (cgroups).\n\n");
	printf("   wipe <container-uuid>\n"
	       "        Wipes the specified container.\n\n");
	printf("   push_guestos_config <guestos.conf> <guestos.sig> <guestos.pem>\n"
	       "        Pushes the specified GuestOS config, signature, and certificate files.\n\n");
	printf("   remove_guestos <guestos name>\n"
	       "        Remove a GuestOS by the specified name.\n"
	       "        It will only remove the OS if no container is using it anymore.\n\n");
	printf("   ca_register <ca.cert>\n"
	       "        Registers a new certificate in trusted CA store for allowed GuestOS signatures.\n\n");
	printf("   pull_csr <device.csr>\n"
	       "        Pulls the device csr and stores it in <device.csr>.\n\n");
	printf("   push_cert <device.cert>\n"
	       "        Pushes back the device certificate provided by <device.cert>.\n\n");
	printf("   assign_iface <container-uuid> --iface <iface_name> [--persistent]\n"
	       "        Assign the specified network interface to the specified container.\n"
	       "        If the 'persistent' option is set, the container config file will\n"
	       "        be modified accordingly.\n\n");
	printf("   unassign_iface <container-uuid> --iface <iface_name> [--persistent]\n"
	       "        Unassign the specified network interface from the specified container.\n"
	       "        If the 'persistent' option is set, the container config file will\n"
	       "        be modified accordingly.\n\n");
	printf("   ifaces <container-uuid>\n"
	       "        Prints the list of network interfaces assigned to the specified container.\n\n");
	printf("   run <container-uuid> <command> [<arg_1> ... <arg_n>]\n"
	       "        Runs the specified command with the given arguments inside the specified container.\n\n");
	printf("   retrieve_logs [<path_to_logstore_dir>] [--remove]\n"
	       "        Retrieves logs from the directory defined in LOGFILE_DIR and stores them in the given directory.\n"
	       "If the 'remove' option was given, all log files are removed upon successful retrieval. The currrently used log file is not removed.\n\n");
	printf("\n");
	exit(-1);
}

static int
sock_connect(const char *socket_file)
{
	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0)
		FATAL("Failed to create and connect to socket %s!", socket_file);
	return sock;
}

static void
send_message(int sock, ControllerToDaemon *msg)
{
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)msg);
	if (msg_size < 0)
		FATAL("error sending protobuf message\n");
}

static DaemonToController *
recv_message(int sock)
{
	DaemonToController *resp = (DaemonToController *)protobuf_recv_message(
		sock, &daemon_to_controller__descriptor);
	if (!resp)
		FATAL("error receiving message\n");
	return resp;
}

static bool
get_container_usb_pin_entry(uuid_t *uuid, int sock)
{
	bool pin_entry = false;
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;
	msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CMLD_HANDLES_PIN;
	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = mem_strdup(uuid_string(uuid));
	send_message(sock, &msg);

	DaemonToController *resp = recv_message(sock);

	if ((resp->code != DAEMON_TO_CONTROLLER__CODE__CONTAINER_CMLD_HANDLES_PIN) ||
	    (resp->response == DAEMON_TO_CONTROLLER__RESPONSE__CMD_UNSUPPORTED) ||
	    (!resp->has_container_cmld_handles_pin)) {
		printf("ERROR: Failed to retrieve pin handle info. Assuming control handles pin entry\n");
		return false;
	}

	pin_entry = resp->container_cmld_handles_pin;

	mem_free0(msg.container_uuids[0]);
	mem_free0(msg.container_uuids);
	protobuf_free_message((ProtobufCMessage *)resp);

	return pin_entry;
}

static uuid_t *
get_container_uuid_new(const char *identifier, int sock)
{
	uuid_t *valid_uuid = NULL;
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;
	msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
	send_message(sock, &msg);

	DaemonToController *resp = recv_message(sock);

	uuid_t *uuid = uuid_new(identifier);
	if (uuid) {
		for (size_t i = 0; i < resp->n_container_status; ++i) {
			TRACE("uuid %s", resp->container_status[i]->uuid);
			if (0 == strcmp(resp->container_status[i]->uuid, uuid_string(uuid))) {
				valid_uuid = uuid;
				break;
			}
		}
		if (valid_uuid == NULL)
			uuid_free(uuid);
	} else {
		INFO("Retrying with name");
		for (size_t i = 0; i < resp->n_container_status; ++i) {
			TRACE("name %s", resp->container_status[i]->name);
			if (0 == strcmp(resp->container_status[i]->name, identifier)) {
				valid_uuid = uuid_new(resp->container_status[i]->uuid);
				break;
			}
		}
	}
	if (!valid_uuid)
		FATAL("Container with provided uuid/name does not exist!");

	protobuf_free_message((ProtobufCMessage *)resp);
	return valid_uuid;
}

static const struct option global_options[] = { { "socket", required_argument, 0, 's' },
						{ "help", no_argument, 0, 'h' },
						{ 0, 0, 0, 0 } };

static const struct option start_options[] = { { "key", optional_argument, 0, 'k' },
					       { "no-switch", no_argument, 0, 'n' },
					       { "setup", no_argument, 0, 's' },
					       { 0, 0, 0, 0 } };

static const struct option assign_iface_options[] = { { "iface", required_argument, 0, 'i' },
						      { "persistent", no_argument, 0, 'p' },
						      { 0, 0, 0, 0 } };

static const struct option log_options[] = { { "remove", no_argument, 0, 'r' }, { 0, 0, 0, 0 } };

static char *
get_password_new(const char *prompt)
{
	struct termios termios_before;
	struct termios termios_passwd;
	char buf[128];

	printf("%s", prompt);
	fflush(stdout);

	// disable echo of input
	tcgetattr(STDIN_FILENO, &termios_before);
	termios_passwd = termios_before;
	termios_passwd.c_lflag &= ~(ECHO);
	termios_passwd.c_lflag |= ECHONL;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_passwd);

	if (fgets(buf, 128, stdin) == NULL)
		buf[0] = '\0';
	else
		buf[strlen(buf) - 1] = '\0';

	// restore terminal config
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_before);
	return mem_strdup(buf);
}

int
main(int argc, char *argv[])
{
	logf_register(&logf_test_write, stderr);

	const char *socket_file = CONTROL_SOCKET;
	uuid_t *uuid = NULL;
	int sock = 0;
	bool has_container_start_params_key = false;
	str_t *log_dir = NULL;
	struct termios termios_before;
	tcgetattr(STDIN_FILENO, &termios_before);

	for (int c, option_index = 0;
	     - 1 != (c = getopt_long(argc, argv, "+s:h", global_options, &option_index));) {
		switch (c) {
		case 's':
			socket_file = optarg;
			break;
		default: // includes cases 'h' and '?'
			print_usage(argv[0]);
		}
	}

	if (!file_exists(socket_file))
		FATAL("Could not find socket file %s. Aborting.\n", socket_file);

	// need at least one more argument (i.e. command string)
	if (optind >= argc)
		print_usage(argv[0]);

	// build ControllerToDaemon message
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;

	const char *command = argv[optind++];
	/*
	 * device global commands
	 */
	if (!strcasecmp(command, "list")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
		goto send_message;
	}
	if (!strcasecmp(command, "list_guestos")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS;
		goto send_message;
	}
	if (!strcasecmp(command, "retrieve_logs")) {
		// need at least one more argument (container config)
		if (optind >= argc)
			print_usage(argv[0]);

		log_dir = str_new(argv[optind++]);
		if (str_buffer(log_dir)[str_length(log_dir)] != '/') {
			str_append(log_dir, "/");
		}
		INFO("Copy logs to %s", str_buffer(log_dir));

		// parse specific options for retrieve_logs command
		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0;
		     - 1 !=
		     (c = getopt_long(start_argc, start_argv, "r", log_options, &option_index));) {
			switch (c) {
			case 'r':
				msg.has_remove_logs = true;
				msg.remove_logs = true;
				break;
			default:
				print_usage(argv[0]);
				ASSERT(false); // never reached
			}
		}
		optind += argc - start_argc; // adjust optind to be used with argv

		if (file_exists(str_buffer(log_dir)) && file_is_dir(str_buffer(log_dir))) {
			msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_LAST_LOG;
			goto send_message;
		} else {
			INFO("Directory does not exist. Please specify existing directory or no directory to copy into ./");
			print_usage(argv[0]);
		}
	}
	if (!strcasecmp(command, "reload")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__RELOAD_CONTAINERS;
		goto send_message;
	}
	if (!strcasecmp(command, "wipe_device")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__WIPE_DEVICE;
		goto send_message;
	}
	if (!strcasecmp(command, "reboot")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__REBOOT_DEVICE;
		goto send_message;
	}
	if (!strcasecmp(command, "set_provisioned")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__SET_PROVISIONED;
		goto send_message;
	}
	if (!strcasecmp(command, "get_provisioned")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_PROVISIONED;
		goto send_message;
	}
	if (!strcasecmp(command, "device_stats")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_DEVICE_STATS;
		goto send_message;
	}
	if (!strcasecmp(command, "push_guestos_config")) {
		if (optind + 2 >= argc)
			print_usage(argv[0]);

		const char *cfgfile = argv[optind++];
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0)
			FATAL("Error accessing config file %s.", cfgfile);

		const char *sigfile = argv[optind++];
		off_t siglen = file_size(sigfile);
		if (siglen < 0)
			FATAL("Error accessing signature file %s.", sigfile);

		const char *certfile = argv[optind++];
		off_t certlen = file_size(certfile);
		if (certlen < 0)
			FATAL("Error accessing certificate file %s.", certfile);

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char *)cfg, cfglen) < 0)
			FATAL("Error reading %s. Aborting.", cfgfile);
		unsigned char *sig = mem_alloc(siglen);
		if (file_read(sigfile, (char *)sig, siglen) < 0)
			FATAL("Error reading %s. Aborting.", sigfile);
		unsigned char *cert = mem_alloc(certlen);
		if (file_read(certfile, (char *)cert, certlen) < 0)
			FATAL("Error reading %s. Aborting.", certfile);

		INFO("Pushing cfg %s (len %zu), sig %s (len %zu), and cert %s (len %zu).", cfgfile,
		     (size_t)cfglen, sigfile, (size_t)siglen, certfile, (size_t)certlen);

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
	if (!strcasecmp(command, "remove_guestos")) {
		// need exactly one more argument (container config file)
		if (optind != argc - 1)
			print_usage(argv[0]);

		char *os_name = argv[optind++];
		INFO("Removing Guestos: %s", os_name);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__REMOVE_GUESTOS;
		msg.guestos_name = os_name;
		goto send_message;
	}
	if (!strcasecmp(command, "ca_register")) {
		// need exactly one more argument (container config file)
		if (optind != argc - 1)
			print_usage(argv[0]);

		const char *ca_cert_file = argv[optind++];
		off_t ca_cert_len = file_size(ca_cert_file);
		if (ca_cert_len < 0)
			FATAL("Error accessing certificate file %s.", ca_cert_file);
		uint8_t *ca_cert = mem_alloc(ca_cert_len);
		if (file_read(ca_cert_file, (char *)ca_cert, ca_cert_len) < 0)
			FATAL("Error reading %s.", ca_cert_file);

		INFO("Registering new CA by cert %s (len %zu).", ca_cert_file, (size_t)ca_cert_len);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__REGISTER_NEWCA;
		msg.has_guestos_rootcert = true;
		msg.guestos_rootcert.len = ca_cert_len;
		msg.guestos_rootcert.data = ca_cert;
		goto send_message;
	}
	if (!strcasecmp(command, "pull_csr")) {
		// need exactly one more argument (certificate file)
		if (optind != argc - 1)
			print_usage(argv[0]);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__PULL_DEVICE_CSR;
		goto send_message;
	}
	if (!strcasecmp(command, "push_cert")) {
		// need exactly one more argument (certificate file)
		if (optind != argc - 1)
			print_usage(argv[0]);

		const char *dev_cert_file = argv[optind++];
		off_t dev_cert_len = file_size(dev_cert_file);
		if (dev_cert_len < 0)
			FATAL("Error accessing certificate file %s.", dev_cert_file);
		uint8_t *dev_cert = mem_alloc(dev_cert_len);
		if (file_read(dev_cert_file, (char *)dev_cert, dev_cert_len) < 0)
			FATAL("Error reading %s.", dev_cert_file);

		INFO("Pushing new device certifcate from file %s (len %zu).", dev_cert_file,
		     (size_t)dev_cert_len);
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__PUSH_DEVICE_CERT;
		msg.has_device_cert = true;
		msg.device_cert.len = dev_cert_len;
		msg.device_cert.data = dev_cert;
		goto send_message;
	}
	if (!strcasecmp(command, "create")) {
		// need at least one more argument (container config)
		if (optind >= argc)
			print_usage(argv[0]);

		const char *cfgfile = argv[optind++];
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0)
			FATAL("Error accessing container config file %s.", cfgfile);

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char *)cfg, cfglen) < 0)
			FATAL("Error reading %s. Aborting.", cfgfile);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CREATE_CONTAINER;
		msg.has_container_config_file = true;
		msg.container_config_file.len = cfglen;
		msg.container_config_file.data = cfg;

		const char *sigfile = (optind > argc - 1) ? NULL : argv[optind++];
		if (sigfile) {
			off_t siglen = file_size(sigfile);
			if (siglen < 0)
				FATAL("Error accessing container signature file %s.", sigfile);
			unsigned char *sig = mem_alloc(siglen);
			if (file_read(sigfile, (char *)sig, siglen) < 0)
				FATAL("Error reading %s. Aborting.", sigfile);
			msg.has_container_config_signature = true;
			msg.container_config_signature.len = siglen;
			msg.container_config_signature.data = sig;
		}

		const char *certfile = (optind > argc - 1) ? NULL : argv[optind++];
		if (sigfile && certfile) {
			off_t certlen = file_size(certfile);
			if (certlen < 0)
				FATAL("Error accessing cotainer certificate file %s.", certfile);
			unsigned char *cert = mem_alloc(certlen);
			if (file_read(certfile, (char *)cert, certlen) < 0)
				FATAL("Error reading %s. Aborting.", certfile);

			msg.has_container_config_certificate = true;
			msg.container_config_certificate.len = certlen;
			msg.container_config_certificate.data = cert;
		}

		INFO("Creating container with cfg %s (len %zu).", cfgfile, (size_t)cfglen);
		goto send_message;
	}

	/*
	 * container specific commands
	 */

	// need at least one more argument (container string)
	if (optind >= argc)
		print_usage(argv[0]);

	sock = sock_connect(socket_file);
	uuid = get_container_uuid_new(argv[optind], sock);

	ContainerStartParams container_start_params = CONTAINER_START_PARAMS__INIT;
	if (!strcasecmp(command, "remove")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__REMOVE_CONTAINER;
	} else if (!strcasecmp(command, "start")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START;
		msg.container_start_params = NULL;
		bool ask_for_password = true;
		bool usb_pin_entry = get_container_usb_pin_entry(uuid, sock);
		// parse specific options for start command
		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0;
		     - 1 != (c = getopt_long(start_argc, start_argv, "k::s", start_options,
					     &option_index));) {
			switch (c) {
			case 'k':
				container_start_params.key = optarg;
				ask_for_password = false;
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
		if (usb_pin_entry && !ask_for_password)
			printf("WARN: argument --key will be ignored for containers configured with USB pin reader\n");
		if (usb_pin_entry) {
			printf("Please Enter your password via pin reader\n");
		} else if (ask_for_password) {
			container_start_params.key = get_password_new("Password: ");
			has_container_start_params_key = true;
		}
		msg.container_start_params = &container_start_params;
		optind += argc - start_argc; // adjust optind to be used with argv
	} else if (!strcasecmp(command, "stop")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP;
		msg.container_start_params = NULL;
		bool ask_for_password = true;
		bool usb_pin_entry = get_container_usb_pin_entry(uuid, sock);
		// parse specific options for start command
		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0;
		     - 1 != (c = getopt_long(start_argc, start_argv, "k", start_options,
					     &option_index));) {
			switch (c) {
			case 'k':
				container_start_params.key = optarg;
				ask_for_password = false;
				break;
			default:
				print_usage(argv[0]);
				ASSERT(false); // never reached
			}
		}
		if (usb_pin_entry && !ask_for_password)
			printf("WARN: argument --key will be ignored for containers configured with USB pin reader\n");
		if (usb_pin_entry) {
			printf("Please Enter your password via pin reader\n");
		} else if (ask_for_password) {
			container_start_params.key = get_password_new("Password: ");
			has_container_start_params_key = true;
		}
		msg.container_start_params = &container_start_params;
		optind += argc - start_argc; // adjust optind to be used with argv
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
	} else if (!strcasecmp(command, "config")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG;
	} else if (!strcasecmp(command, "update_config")) {
		optind++;
		// need at least one more argument (container config)
		if (optind >= argc)
			print_usage(argv[0]);

		const char *cfgfile = argv[optind++];
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0)
			FATAL("Error accessing container config file %s.", cfgfile);

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char *)cfg, cfglen) < 0)
			FATAL("Error reading %s. Aborting.", cfgfile);

		INFO("Creating container with cfg %s (len %zu).", cfgfile, (size_t)cfglen);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UPDATE_CONFIG;
		msg.has_container_config_file = true;
		msg.container_config_file.len = cfglen;
		msg.container_config_file.data = cfg;

		const char *sigfile = (optind > argc - 1) ? NULL : argv[optind++];
		if (sigfile) {
			off_t siglen = file_size(sigfile);
			if (siglen < 0)
				FATAL("Error accessing container signature file %s.", sigfile);
			unsigned char *sig = mem_alloc(siglen);
			if (file_read(sigfile, (char *)sig, siglen) < 0)
				FATAL("Error reading %s. Aborting.", sigfile);
			msg.has_container_config_signature = true;
			msg.container_config_signature.len = siglen;
			msg.container_config_signature.data = sig;
		}

		const char *certfile = (optind > argc - 1) ? NULL : argv[optind++];
		if (sigfile && certfile) {
			off_t certlen = file_size(certfile);
			if (certlen < 0)
				FATAL("Error accessing cotainer certificate file %s.", certfile);
			unsigned char *cert = mem_alloc(certlen);
			if (file_read(certfile, (char *)cert, certlen) < 0)
				FATAL("Error reading %s. Aborting.", certfile);

			msg.has_container_config_certificate = true;
			msg.container_config_certificate.len = certlen;
			msg.container_config_certificate.data = cert;
		}
	} else if (!strcasecmp(command, "ifaces")) {
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_LIST_IFACES;
	} else if (!strcasecmp(command, "assign_iface") || !strcasecmp(command, "unassign_iface")) {
		AssignInterfaceParams assign_iface_params = ASSIGN_INTERFACE_PARAMS__INIT;
		msg.assign_iface_params = &assign_iface_params;

		optind--;
		char **start_argv = &argv[optind];
		int start_argc = argc - optind;
		optind = 0; // reset optind to scan command-specific options
		for (int c, option_index = 0;
		     - 1 != (c = getopt_long(start_argc, start_argv, "i::p", assign_iface_options,
					     &option_index));) {
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
		optind += argc - start_argc; // adjust optind to be used with argv

		if (!strcasecmp(command, "assign_iface")) {
			msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ASSIGNIFACE;
		} else if (!strcasecmp(command, "unassign_iface")) {
			msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNASSIGNIFACE;
		} else
			ASSERT(false); // should never be reached
	} else if (!strcasecmp(command, "run")) {
		optind++;
		if (optind > argc - 1)
			print_usage(argv[0]);

		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_CMD;

		int argcount = 0;

		msg.has_exec_pty = true;

		if (!strcmp(argv[optind], "nopty")) {
			TRACE("Got nopty option");
			msg.exec_pty = 0;
			optind++;
		} else {
			msg.exec_pty = 1;
		}

		if (optind > argc - 1)
			print_usage(argv[0]);

		msg.exec_command = argv[optind];

		if (optind < argc) {
			size_t len = MUL_WITH_OVERFLOW_CHECK((size_t)sizeof(char *), argc);
			TRACE("[CLIENT] Allocating %zu bytes for arguments (argc = %d)", len, argc);
			msg.exec_args = mem_alloc(len);

			while (optind < argc) {
				TRACE("[CLIENT] Parsing command arguments at index %d, optind: %d: %s",
				      argcount, optind, argv[optind]);
				msg.exec_args[argcount] = mem_strdup(argv[optind]);

				optind++;
				argcount++;
			}
		}

		TRACE("[CLIENT] Done parsing arguments, got %d arguments", argcount);
		msg.n_exec_args = argcount;
		TRACE("after set n_exec_args");

	} else if (!strcasecmp(command, "change_pin")) {
		char *newpin_verify = NULL;
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CHANGE_TOKEN_PIN;
		msg.device_pin = get_password_new("Current Password: ");
		msg.device_newpin = get_password_new("New Password: ");
		newpin_verify = get_password_new("Re-enter New Password: ");

		if (strcmp(msg.device_newpin, newpin_verify) != 0)
			FATAL("Passwords don't match!");

		mem_memset0(newpin_verify, strlen(newpin_verify));
		mem_free0(newpin_verify);
	} else if (!strcasecmp(command, "dev_access")) {
		optind++;
		// need at least one more argument (dev access rule)
		if (optind >= argc)
			print_usage(argv[0]);

		char *dev_rule = argv[optind++];

		INFO("Setting device access rule %s", dev_rule);
		msg.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_DEV_ACCESS;
		msg.dev_rule = dev_rule;
	} else
		print_usage(argv[0]);

	msg.n_container_uuids = 1;
	msg.container_uuids = mem_new(char *, 1);
	msg.container_uuids[0] = mem_strdup(uuid_string(uuid));

send_message:
	if (!sock)
		sock = sock_connect(socket_file);
	send_message(sock, &msg);

	if (!strcasecmp(command, "run")) {
		TRACE("[CLIENT] Processing response for run command");

		if (msg.exec_pty) {
			TRACE("[CLIENT] Setting termios for PTY");
			struct termios termios_run = termios_before;
			termios_run.c_cflag &= ~(ICRNL | IXON | IXOFF);
			termios_run.c_oflag &= ~(OPOST);
			termios_run.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOCTL);
			tcsetattr(STDIN_FILENO, TCSANOW, &termios_run);
		}

		//free exec arguments
		TRACE("[CLIENT] Freeing %zu args at %p", msg.n_exec_args, (void *)msg.exec_args);
		mem_free_array((void **)msg.exec_args, msg.n_exec_args);
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
					inputmsg.container_uuids = mem_new(char *, 1);
					inputmsg.container_uuids[0] = (char *)uuid_string(uuid);
					inputmsg.n_container_uuids = 1;
					inputmsg.command =
						CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_INPUT;
					inputmsg.exec_input = buf;

					TRACE("[CLIENT] Sending input for exec'ed process in container %s",
					      argv[optind]);

					send_message(sock, &inputmsg);
					mem_free0(inputmsg.container_uuids);
					TRACE("[CLIENT] Sent input to cmld");
				}
			}
		} else {
			TRACE("[CLIENT] Exec'ed process outputreceiving  child forked, PID: %i",
			      getpid());

			while (1) {
				TRACE("[CLIENT] Waiting for command output message from cmld");
				DaemonToController *resp = recv_message(sock);

				TRACE("[CLIENT] Got message from exec'ed process\n");

				size_t written = 0, current = 0;
				if (resp->code == DAEMON_TO_CONTROLLER__CODE__EXEC_OUTPUT) {
					TRACE("[CLIENT] Message length; %zu\n",
					      resp->exec_output.len);
					while (written < resp->exec_output.len) {
						TRACE("[CLIENT] Writing exec output to stdout");
						if ((current = write(
							     STDOUT_FILENO,
							     resp->exec_output.data + written,
							     resp->exec_output.len - written))) {
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

handle_resp:
	TRACE("[CLIENT] Awaiting response");

	DaemonToController *resp = recv_message(sock);

	TRACE("[CLIENT] Got response. Processing");

	// do command-specific response processing
	switch (resp->code) {
	case DAEMON_TO_CONTROLLER__CODE__DEVICE_CSR: {
		const char *dev_csr_file = argv[optind];
		if (!resp->has_device_csr) {
			ERROR("DEVICE_CSR_ERROR: Device not in Provisioning mode!");
		} else if (-1 == file_write(dev_csr_file, (char *)resp->device_csr.data,
					    resp->device_csr.len)) {
			ERROR("writing device csr to %s", dev_csr_file);
		} else {
			INFO("device csr written to %s", dev_csr_file);
		}
	} break;
	case DAEMON_TO_CONTROLLER__CODE__RESPONSE: {
		if (!resp->has_response)
			break;
		switch (resp->response) {
		case DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_INSTALL_STARTED: {
			INFO("Waiting for images to be transfered ...");
			protobuf_free_message((ProtobufCMessage *)resp);
			goto handle_resp;
		} break;
		default:
			protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *)resp);
		}
	} break;
	case DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE_FRAGMENT: {
		if (!log_dir) {
			WARN("log_dir is null. Did not except to receive a LOG_MESSAGE");
			protobuf_free_message((ProtobufCMessage *)resp);
			goto handle_resp;
		}

		if (!resp->log_message) {
			ERROR("resp->log_message is null.");
			protobuf_free_message((ProtobufCMessage *)resp);
			goto handle_resp;
		}
		INFO("Received fragment of logfile %s", resp->log_message->name);

		str_t *file_str = str_new(str_buffer(log_dir));
		str_append(file_str, resp->log_message->name);

		if (file_write_append(str_buffer(file_str), resp->log_message->msg, -1) < 0) {
			INFO("logfile %s could not be written.", resp->log_message->name);
		}
		protobuf_free_message((ProtobufCMessage *)resp);
		goto handle_resp;
	} break;
	case DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE_FINAL: {
		if (!log_dir) {
			WARN("log_dir is null. Did not except to receive a LOG_MESSAGE");
			protobuf_free_message((ProtobufCMessage *)resp);
			goto handle_resp;
		}

		if (!resp->log_message) {
			ERROR("resp->log_message is null.");
			protobuf_free_message((ProtobufCMessage *)resp);
			goto handle_resp;
		}
		INFO("Received final fragment of logfile %s", resp->log_message->name);

		str_t *file_str = str_new(str_buffer(log_dir));
		str_append(file_str, resp->log_message->name);

		if (file_write_append(str_buffer(file_str), resp->log_message->msg, -1) < 0) {
			INFO("logfile %s could not be written.", resp->log_message->name);
		}
		protobuf_free_message((ProtobufCMessage *)resp);
		goto handle_resp;
	} break;

	default:
		// TODO for now just dump the response in text format
		protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *)resp);
	}
	protobuf_free_message((ProtobufCMessage *)resp);

exit:
	close(sock);
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &termios_before);

	if (msg.has_container_config_file)
		mem_free0(msg.container_config_file.data);
	if (msg.has_guestos_rootcert)
		mem_free0(msg.guestos_rootcert.data);
	if (msg.has_guestos_config_file)
		mem_free0(msg.guestos_config_file.data);
	if (msg.has_guestos_config_signature)
		mem_free0(msg.guestos_config_signature.data);
	if (msg.has_guestos_config_certificate)
		mem_free0(msg.guestos_config_certificate.data);
	if (msg.has_device_cert)
		mem_free0(msg.device_cert.data);

	if (has_container_start_params_key) {
		mem_memset0(container_start_params.key, strlen(container_start_params.key));
		mem_free0(container_start_params.key);
	}
	if (msg.device_pin) {
		mem_memset0(msg.device_pin, strlen(msg.device_pin));
		mem_free0(msg.device_pin);
	}
	if (msg.device_newpin) {
		mem_memset0(msg.device_newpin, strlen(msg.device_newpin));
		mem_free0(msg.device_newpin);
	}

	for (size_t i = 0; i < msg.n_container_uuids; ++i)
		mem_free0(msg.container_uuids[i]);
	mem_free0(msg.container_uuids);
	if (uuid)
		uuid_free(uuid);
	if (log_dir)
		str_free(log_dir, true);

	return 0;
}
