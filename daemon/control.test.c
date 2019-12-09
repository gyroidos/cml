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

#include "control.c"
#include "device/fraunhofer/common/cml/daemon/control.pb-c.h"

#include "cmld.stub.h"
#include "container.stub.h"
#include "guestos.stub.h"

#include "common/macro.h"
#include "common/file.h"
#include "common/event.h"
#include "common/str.h"
#include "common/protobuf.h"
#include "common/sock.h"

#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

/**
 * Reads a feedback string from the given file descriptor and compares it
 * with the expected result.
 */
bool
check_feedback_str(int fd, const char *expected_format, ...)
{
	char expected_buf[4096];
	va_list argptr;
	va_start(argptr, expected_format);
	vsnprintf(expected_buf, sizeof(expected_buf), expected_format, argptr);
	va_end(argptr);
	char buf[4096];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0)
		return false;
	buf[n] = '\0';
	bool res = 0 == strncmp(buf, expected_buf, sizeof(buf));
	//logD("Checking expected result \"%s\": %s", expected_buf, res ? "OK" : "FAIL");
	if (!res) {
		DEBUG("Invalid result:\n  Received: \"%s\"\nExpected: \"%s\"", buf, expected_buf);
	}
	return res;
}

/**
 * Forks a child with a control module instance and running the event loop.
 *
 * @param sock_path path of the socket file to bind the socket to
 * @return the pid of the child process
 */
static pid_t
fork_child(const char *sock_path)
{
	static int sync_pipe[2];
	int res = pipe(sync_pipe);
	ASSERT(res == 0);

	pid_t pid = fork();

	if (-1 == pid) {
		perror("fork");
		exit(EXIT_FAILURE);
	}

	if (0 == pid) {
		control_t *control = control_local_new(sock_path);

		close(sync_pipe[0]);
		write(sync_pipe[1], "x", 1);
		close(sync_pipe[1]);

		event_loop();
		control_free(control);
		_exit(0);
	} else {
		close(sync_pipe[1]);
		char c = '\0';
		do {
			int res = read(sync_pipe[0], &c, 1);
			if (res == -1) {
				if (errno == EINTR)
					continue;
				perror("read sync");
			} else if (res == 1 && c == 'x')
				break;
			exit(EXIT_FAILURE);
		} while (true);
		close(sync_pipe[0]);
	}
	return pid;
}

/**
 * Injects the given ControllerToDaemon message to the handle_control_message()
 * function in the control module (static test of control module logic).
 */
void
inject_message_static(ControllerToDaemon *msg, void *data)
{
	int csock_write_fd = (int)data;
	control_handle_message(msg, csock_write_fd);
}

/**
 * Injects the given ControllerToDaemon message to the control module through a socket
 * connected to the control module (integration test of control module including
 * event loop).
 */
void
inject_message_sock(ControllerToDaemon *msg, void *data)
{
	int csock_fd = (int)data;
	protobuf_send_message(csock_fd, (ProtobufCMessage *)msg);
}

/**
 * Performs one test case on the control_handle_message() function.
 *
 * The control_handle_message() function is called with the given ControllerToDaemon message.
 * The logic in the control module then triggers certain actions in the cmld stub module,
 * which are then matched with the expected results.
 *
 * @param msg       pointer to the ControllerToDaemon message (protobuf-generated struct)
 * @param inject    inject_* function that injects the message to the control module
 *                  (either by calling a static method or by sending it through a socket)
 * @param data      data for the inject function
 * @param cmld_fd   file descriptor through which results are returned from the cmld stub
 * @param expected_results  array with expected result strings (NULL-terminated)
 */
bool
test_handle_message(ControllerToDaemon *msg, void (*inject)(ControllerToDaemon *msg, void *data), void *data,
		    int cmld_fd, const char **expected_results)
{
	int bytes_available = 0;
	// make sure there is no unhandled feedback (from previous test case)
	ioctl(cmld_fd, FIONREAD, &bytes_available);
	ASSERT(0 == bytes_available);

	// invoke handle_message routine in control module
	inject(msg, data);

	// check if feedback for triggered actions in cmld module
	// matches the expected results (in their given order)
	if (expected_results)
		for (const char *expected; (expected = *expected_results++);)
			ASSERT(check_feedback_str(cmld_fd, expected));

	// make sure there is no unexpected feedback left unhandled
	ioctl(cmld_fd, FIONREAD, &bytes_available);
	ASSERT(0 == bytes_available);

	return true;
}

/**
 * Helper function to create a socket pair.
 */
void
make_socketpair(int fds[2])
{
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == -1) {
		perror("socketpair");
		exit(EXIT_FAILURE);
	}
}

/**
 * Runs the test suite sending different control messages to the control method
 * through the specific inject function.
 *
 * @param cmld_fd   file descriptor where feedback from the cmld stub can be read
 * @param inject    inject_* function that injects the message to the control module
 *                  (either by calling a static method or by sending it through a socket)
 * @param data      data for the inject function
 * @param csock_read_fdr     file descriptor responses from the control module can be read
 */
void
run_testsuite(int cmld_fd, void (*inject)(ControllerToDaemon *msg, void *data), void *data, int csock_read_fd)
{
	container_t *a0 = cmld_container_get_by_index(0);
	container_t *a1 = cmld_container_get_by_index(1);

	ControllerToDaemon msg_in = CONTROLLER_TO_DAEMON__INIT;

	// test empty message
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	// test message with empty control
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);

	// test message with control but bad UUID
	msg_in.n_container_uuids = 1;
	msg_in.container_uuids = mem_new(char *, 1);
	msg_in.container_uuids[0] = "BAD-UUID-1234567890";
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);

	// test message with control and bad command
	msg_in.container_uuids[0] = (char *)uuid_string(container_get_uuid(a0));
	msg_in.command = -1;
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);

	// test CONTAINER_START
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START;
	test_handle_message(&msg_in, inject, data, cmld_fd,
			    (const char *[]){ "cmld_container_start: A0, key=NULL, no_switch=false",
					      "cmld_container_switch: A0", /* start switches by default */
					      NULL });
	//ASSERT(cmld_containers_get_foreground() == a0);

	// test CONTAINER_START with key without switch
	ContainerStartParams start_params = CONTAINER_START_PARAMS__INIT;
	start_params.no_switch = true;
	start_params.has_no_switch = true;
	start_params.key = "ABCD";
	msg_in.container_start_params = &start_params;
	msg_in.container_uuids[0] = (char *)uuid_string(container_get_uuid(a1));
	test_handle_message(&msg_in, inject, data, cmld_fd,
			    (const char *[]){ "cmld_container_start: A1, key=ABCD, no_switch=true",
					      /* no switch this time! */
					      NULL });
	//ASSERT(cmld_containers_get_foreground() == a0);
	msg_in.container_start_params = NULL;

	// test CONTAINER_SWITCH
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SWITCH;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_switch: A1", NULL });
	//ASSERT(cmld_containers_get_foreground() == a1);

	// test CONTAINER_STOP
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_stop: A1", NULL });

	// test CONTAINER_FREEZE
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_FREEZE;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_freeze: A1", NULL });

	// test CONTAINER_UNFREEZE
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNFREEZE;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_unfreeze: A1", NULL });

	// test CONTAINER_WIPE
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_WIPE;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_wipe: A1", NULL });

	// test CONTAINER_SNAPSHOT
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SNAPSHOT;
	test_handle_message(&msg_in, inject, data, cmld_fd, (const char *[]){ "cmld_container_snapshot: A1", NULL });

	// test GET_CONTAINER_STATUS
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS;
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	// recv container state, decode and check
	DaemonToController *cout =
		(DaemonToController *)protobuf_recv_message(csock_read_fd, &daemon_to_controller__descriptor);
	ASSERT(cout->n_container_status == 1);
	ASSERT(cout->container_status != NULL);
	ASSERT(cout->container_status[0]->uuid &&
	       !strcmp(cout->container_status[0]->uuid, uuid_string(container_get_uuid(a1))));
	ASSERT(cout->container_status[0]->name && !strcmp(cout->container_status[0]->name, container_get_name(a1)));
	ASSERT(cout->container_status[0]->foreground == true);
	protobuf_free_message((ProtobufCMessage *)cout);

	// test Container_GET_CONTAINER_CONFIG 1
	DEBUG("test Container_GET_CONTAINER_CONFIG 1");
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG;
	msg_in.n_container_uuids = 0;
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	cout = (DaemonToController *)protobuf_recv_message(csock_read_fd, &daemon_to_controller__descriptor);
	ASSERT(cout->n_container_configs == 0);
	ASSERT(cout->container_configs == NULL);
	protobuf_free_message((ProtobufCMessage *)cout);

	// test Container_GET_CONTAINER_CONFIG 2
	DEBUG("test Container_GET_CONTAINER_CONFIG 2");
	file_write("test_A0.conf", "name: \"a0\"\nguest_os: \"a0os\"\nguestos_version: 20150408\ncolor: 1426918911",
		   -1);
	file_write("test_A1.conf", "name: \"a1\"\nguest_os: \"a1os\"\nguestos_version: 20150409\ncolor: 1426918912",
		   -1);
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG;
	msg_in.n_container_uuids = 0;
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	cout = (DaemonToController *)protobuf_recv_message(csock_read_fd, &daemon_to_controller__descriptor);
	ASSERT(cout->n_container_configs == 2);
	ASSERT(cout->container_configs != NULL);
	ASSERT(cout->container_configs[0]->name && !strcmp(cout->container_configs[0]->name, "a0"));
	ASSERT(cout->container_configs[1]->name && !strcmp(cout->container_configs[1]->name, "a1"));
	ASSERT(cout->container_configs[0]->guest_os && !strcmp(cout->container_configs[0]->guest_os, "a0os"));
	ASSERT(cout->container_configs[1]->guest_os && !strcmp(cout->container_configs[1]->guest_os, "a1os"));
	ASSERT(cout->container_configs[0]->guestos_version == 20150408);
	ASSERT(cout->container_configs[1]->guestos_version == 20150409);
	ASSERT(cout->container_configs[0]->color == 1426918911);
	ASSERT(cout->container_configs[1]->color == 1426918912);
	protobuf_free_message((ProtobufCMessage *)cout);
	remove("test_A0.conf");
	remove("test_A1.conf");

	// test GET_LAST_LOG with no files present
	//msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__GET_LAST_LOG;
	//test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	//cout = (DaemonToController *)protobuf_recv_message(csock_read_fd, &daemon_to_controller__descriptor);
	//ASSERT(cout->log_message && !strcmp(cout->log_message->msg, "Last line of log"));
	//protobuf_free_message((ProtobufCMessage *)cout);

	// test LIST_CONTAINERS
	msg_in.command = CONTROLLER_TO_DAEMON__COMMAND__LIST_CONTAINERS;
	msg_in.n_container_uuids = 0;
	test_handle_message(&msg_in, inject, data, cmld_fd, NULL);
	cout = (DaemonToController *)protobuf_recv_message(csock_read_fd, &daemon_to_controller__descriptor);
	//protobuf_dump_message(STDOUT_FILENO, (ProtobufCMessage *)cout);
	ASSERT(cout->container_status == NULL);
	ASSERT(cout->n_container_uuids == (size_t)cmld_containers_get_count());
	ASSERT(cout->container_uuids);
	for (size_t i = 0; i < cout->n_container_uuids; i++) {
		container_t *container = cmld_container_get_by_index(i);
		ASSERT(cout->container_uuids[i] &&
		       !strcmp(cout->container_uuids[i], uuid_string(container_get_uuid(container))));
	}
	protobuf_free_message((ProtobufCMessage *)cout);
}

int
main()
{
	logf_register(&logf_test_write, stdout);

	// SETUP test environment
	INFO("Unit test: setup");
	int cmld_fd[2]; // 0=read, 1=write
	make_socketpair(cmld_fd);
	struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(cmld_fd[0], SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

	cmld_stub_init(cmld_fd[1]);
	UNUSED container_t *a0 = cmld_stub_container_create("A0");
	UNUSED container_t *a1 = cmld_stub_container_create("A1");
	const char *control_sock_path = "control.test.sock";
	pid_t child = fork_child(control_sock_path); // fork child (use same setup for unit and integration tests)

	// STAGE 1 (unit test): directly call handle_message
	// (tests internal logic only; needs access to static function)
	{
		INFO("Unit test: start");

		int csock_fd[2]; // 0=read, 1=write
		make_socketpair(csock_fd);

		run_testsuite(cmld_fd[0], inject_message_static, (void *)csock_fd[1], csock_fd[0]);

		INFO("Unit test: done");
	}

	// STAGE 2 (module integration test): send messages over control socket
	// (tests entire module; handling via event loop in fork()ed process)
	{
		INFO("Integration test: start");

		int sock = sock_unix_create_and_connect(SOCK_STREAM, control_sock_path);
		if (sock == -1) {
			ERROR_ERRNO("Failed to create local control socket file %s.", control_sock_path);
			kill(child, SIGKILL); // kill child
			return -1;
		}

		run_testsuite(cmld_fd[0], inject_message_sock, (void *)sock, sock);

		close(sock);

		INFO("Integration test: done");
	}

	kill(child, SIGKILL); // kill child
	return 0;
}
