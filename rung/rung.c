/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "oci_control.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/event.h"

#include <getopt.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>

// clang-format off
#define CONTROL_SOCKET SOCK_PATH(oci-control)
// clang-format on

#define OCI_CONTROL_ROOT "/tmp/rung"

static void
print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s <socket file>] <command> [<command args>]\n", cmd);
	printf("\n");
	printf("commands:\n");
	printf("   create <container-id> <path-to-bundle>\n"
	       "        Creates a container from the given oci bundle.\n\n");
	printf("   delete <container-id>\n"
	       "        Removes the specified container (completely).\n\n");
	printf("   start <container-id> \n"
	       "        Starts the container. \n\n");
	printf("   kill <container-id> \n"
	       "        Stops/Kills the specified container.\n\n");
	printf("   state <container-id>\n"
	       "        Prints the OCI-compatible state of the specified container.\n\n");
	exit(-1);
}

UNUSED static char *state_fmt = "{\"ociVersion\":\"1.0.2\","
				"\"id\":\"%s\","
				"\"status\":\"%s\","
				"\"bundle\":\"%s\","
				"\"annotations\":{}}";

static int
sock_connect(const char *socket_file)
{
	int sock = sock_unix_create_and_connect(SOCK_STREAM, socket_file);
	if (sock < 0)
		FATAL("Failed to create and connect to socket %s!", socket_file);
	return sock;
}

static void
send_message(int sock, OciCommand *msg)
{
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)msg);
	if (msg_size < 0)
		FATAL("error sending protobuf message\n");
}

static OciResponse *
recv_message(int sock)
{
	OciResponse *resp = (OciResponse *)protobuf_recv_message(sock, &oci_response__descriptor);
	if (!resp)
		FATAL("error receiving message\n");
	return resp;
}

static const struct option global_options[] = {
	{ "socket", required_argument, 0, 's' }, { "root", required_argument, 0, 'r' },
	{ "log", required_argument, 0, 'l' },	 { "log-format", required_argument, 0, 'f' },
	{ "help", no_argument, 0, 'h' },	 { 0, 0, 0, 0 }
};

static const struct option create_options[] = { { "bundle", required_argument, 0, 'b' },
						{ "pid-file", required_argument, 0, 'p' },
						{ "console-socket", required_argument, 0, 'c' },
						{ "help", no_argument, 0, 'h' },
						{ 0, 0, 0, 0 } };

static void
dummy_child_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGINT..");
	//	char *state = data;
	//printf("%s", state);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int ret = 0;
	logf_register(&logf_test_write, stderr);

	const char *socket_file = CONTROL_SOCKET;
	const char *oci_control_root = OCI_CONTROL_ROOT;
	char *oci_control_log_file = NULL;

	const char *bundle_path = ".";
	const char *pid_file = NULL;

	int sock = 0;

	for (int c, option_index = 1;
	     - 1 != (c = getopt_long(argc, argv, "+s:r:l:f:h", global_options, &option_index));) {
		switch (c) {
		case 's':
			socket_file = optarg;
			break;
		case 'r':
			oci_control_root = optarg;
			break;
		case 'l':
			oci_control_log_file = mem_strdup(optarg);
			break;
		case 'f':
			// ignore for now
			break;
		default: // includes cases 'h' and '?'
			TRACE("option :%s\n", optarg);
			print_usage(argv[0]);
		}
	}

	// build ControllerToDaemon message
	OciCommand msg = OCI_COMMAND__INIT;

	if (NULL == oci_control_log_file)
		oci_control_log_file = mem_printf("%s/%s.log", OCI_CONTROL_ROOT, msg.container_id);

	const char *command = argv[optind++];

	// need at least one more argument (container id as string)
	if (optind >= argc)
		print_usage(argv[0]);

	//msg.container_id = argv[argc-1];
	//char *state_file = mem_printf("%s/state.json", state_path);

	// dirname may modify original string, thus strdup
	char *log_path_dirname = mem_strdup(oci_control_log_file);
	if (dir_mkdir_p(dirname(log_path_dirname), 0755) < 0) {
		ERROR("Could not create path for log_file node");
		ret = -1;
		goto out;
	}

	logf_register(&logf_file_write, logf_file_new(oci_control_log_file));

	DEBUG("argc = %d", argc);
	for (int i = 0; i < argc; ++i)
		DEBUG("%s", argv[i]);

	if (!strcasecmp(command, "state")) {
		fprintf(stderr, "OCI_STATE");
		msg.operation = OCI_COMMAND__OPERATION__STATE;
		msg.container_id = argv[optind++];

		goto send_message;
	}
	if (!strcasecmp(command, "create")) {
		fprintf(stderr, "OCI_CREATE");

		const char *console_sock = NULL;
		if (optind >= argc)
			print_usage(argv[0]);
		for (int c, option_index = optind;
		     - 1 !=
		     (c = getopt_long(argc, argv, "+b:p:c:h", create_options, &option_index));) {
			switch (c) {
			case 'b':
				bundle_path = optarg;
				break;
			case 'p':
				pid_file = optarg;
				DEBUG("pid_file :%s", optarg);
				break;
			case 'c':
				console_sock = optarg;
				DEBUG("console_sock :%s", optarg);
				break;
			default: // includes cases 'h' and '?'
				DEBUG("option :%s\n", optarg);
				print_usage(argv[0]);
			}
		}

		const char *cfgfile = mem_printf("%s/config.json", bundle_path);
		off_t cfglen = file_size(cfgfile);
		if (cfglen < 0)
			FATAL("Error accessing config file %s.", cfgfile);

		unsigned char *cfg = mem_alloc(cfglen);
		if (file_read(cfgfile, (char *)cfg, cfglen) < 0)
			FATAL("Error reading %s. Aborting.", cfgfile);

		msg.operation = OCI_COMMAND__OPERATION__CREATE;
		msg.container_id = argv[optind++];
		msg.has_oci_config_file = true;
		msg.oci_config_file.len = cfglen;
		msg.oci_config_file.data = cfg;
		msg.bundle_path = mem_strdup(bundle_path);

		DEBUG("config: %s", (char *)msg.oci_config_file.data);

		DEBUG("console_sock :%s", console_sock);
		pid_t pid = fork();
		if (pid == -1) {
			return ret;
		} else if (pid == 0) {
			// dummy child for containerd shim
			//char *state = mem_printf(state_fmt, msg.container_id,
			//			 "stopped", msg.bundle_path);
			event_init();
			event_signal_t *sig_int =
				event_signal_new(SIGINT, &dummy_child_sigint_cb, NULL);
			event_add_signal(sig_int);
			event_loop();
		}
		// store dummy pid
		DEBUG("sorting pid %d in pid_file", pid);
		file_printf(pid_file, "%d", pid);

		goto send_message;
	}
	if (!strcasecmp(command, "start")) {
		msg.operation = OCI_COMMAND__OPERATION__START;
		msg.container_id = argv[optind++];
		fprintf(stderr, "OCI_START");
		goto send_message;
	}
	if (!strcasecmp(command, "kill")) {
		fprintf(stderr, "OCI_KILL");
		for (int i = 0; i < argc; ++i)
			fprintf(stderr, " %s,", argv[i]);
		fprintf(stderr, "\n");
		if (optind >= argc)
			print_usage(argv[0]);
		msg.operation = OCI_COMMAND__OPERATION__KILL;
		msg.container_id = argv[optind++];
		msg.has_signal = true;
		msg.signal = atoi(argv[optind++]);
		goto send_message;
	}
	if (!strcasecmp(command, "delete")) {
		fprintf(stderr, "OCI_DELETE");
		msg.operation = OCI_COMMAND__OPERATION__DELETE;
		msg.container_id = argv[optind++];
	} else {
		FATAL("Command not supported!");
	}

send_message:

	if (!file_exists(socket_file)) {
		ERROR("Could not find socket file %s. Aborting.\n", socket_file);
		return -1;
	}

	sock = sock_connect(socket_file);
	send_message(sock, &msg);

	TRACE("[CLIENT] Awaiting response");

	OciResponse *resp = recv_message(sock);

	TRACE("[CLIENT] Got response. Processing");

	// do command-specific response processing
	switch (resp->code) {
	case OCI_RESPONSE__CODE__RESPONSE: {
		if (!resp->has_response)
			break;
		switch (resp->response) {
		case OCI_RESPONSE__RESPONSE__CMD_OK: {
			DEBUG("Command %s ok", command);
		} break;
		default:
			FATAL("Command %s faild", command);
		}
	} break;
	case OCI_RESPONSE__CODE__STATE: {
		printf("%s", resp->state);
		DEBUG("recv state for id (%s) '%s'", msg.container_id, resp->state);
		//NANOSLEEP(1, 0);
		// store state created on response -> move code there
		// file_printf(state_file, state_fmt, msg.container_id, "created",
		//bundle_path);
		char *state_path = mem_printf("%s/%s", oci_control_root, msg.container_id);
		char *state_file = mem_printf("%s/state.json", state_path);
		if (dir_mkdir_p(state_path, 0755) < 0) {
			ERROR("Could not create path for state file");
			ret = -1;
			goto out;
		}
		file_printf(state_file, "%s", resp->state);
		//if (resp->has_pid)
		//	file_printf(pid_file, "%d", resp->pid);

		//printf("%s", resp->state);
		fflush(stdout);

		if (resp->status && !strcmp(resp->status, "stopped")) {
			int child_pid = -1;
			char *child_str = file_read_new(pid_file, file_size(pid_file));
			if (child_str && sscanf(child_str, "%d", &child_pid) == 1) {
				if (child_pid > 0) {
					DEBUG("killing shim dummy child process with pid %d",
					      child_pid);
					kill(child_pid, SIGINT);
				}
			}
		}

		break;
	}
	default:
		// TODO for now just dump the response in text format
		protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *)resp);
	}
	protobuf_free_message((ProtobufCMessage *)resp);

out:

	if (msg.has_oci_config_file)
		mem_free0(msg.oci_config_file.data);
	if (oci_control_log_file)
		mem_free0(oci_control_log_file);

	close(sock);

	return ret;
}
