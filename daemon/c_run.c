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

#define MOD_NAME "c_run"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <pty.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <linux/sockios.h>
#include <sched.h>
#include <sys/mman.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include <macro.h>

#include "common/audit.h"
#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/proc.h"
#include "common/ns.h"
#include "container.h"
#include "cmld.h"

#define CLONE_STACK_SIZE 8192

#define SESSION_WBUF_SIZE 1024

typedef struct c_run {
	container_t *container;
	list_t *sessions;
} c_run_t;

typedef struct c_run_session {
	c_run_t *run;
	int fd;
	pid_t active_exec_pid;
	int console_sock_cmld;
	int console_sock_container;
	int pty_master;
	char *pty_slave_name;
	int pty_slave_fd;
	event_io_t *pty_master_io;
	event_io_t *console_sock_container_io;
	int create_pty;
	char *cmd;
	ssize_t argc;
	char **argv;
	char *console_sock_container_wbuf;
	int console_sock_container_wbuf_count;
	char *pty_master_wbuf;
	int pty_master_wbuf_count;
} c_run_session_t;

static void *
c_run_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_run_t *run = mem_new0(c_run_t, 1);
	run->container = compartment_get_extension_data(compartment);

	run->sessions = NULL;
	return run;
}

static c_run_session_t *
c_run_session_new(c_run_t *run, int create_pty, char *cmd, ssize_t argc, char **argv,
		  int session_fd)
{
	if (argv == NULL || argc < 1) {
		ERROR("No command was specified to execute.");
		return NULL;
	}

	// Create a socketpair for communication with the console task
	TRACE("Setting up sockets");
	int cfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, cfd)) {
		ERROR_ERRNO("Could not create socketpair for communication with console task!");
		return NULL;
	}

	c_run_session_t *session = mem_new0(c_run_session_t, 1);
	session->fd = session_fd;
	session->run = run;
	session->pty_master = -1;
	session->active_exec_pid = -1;
	session->pty_slave_name = NULL;
	session->pty_slave_fd = -1;
	session->pty_master_io = NULL;
	session->console_sock_container_io = NULL;

	session->console_sock_cmld = cfd[0];
	session->console_sock_container = cfd[1];

	TRACE("Making cmld console socket nonblocking");
	fd_make_non_blocking(session->console_sock_cmld);
	fd_make_non_blocking(session->console_sock_container);

	session->cmd = mem_strdup(cmd);
	session->argc = argc;
	session->create_pty = create_pty;

	ssize_t i = 0;
	size_t total_len = ADD_WITH_OVERFLOW_CHECK(session->argc, (size_t)1);
	total_len = MUL_WITH_OVERFLOW_CHECK(sizeof(char *), total_len);
	session->argv = mem_alloc0(total_len);

	while (i < argc) {
		TRACE("Got argument: %s", argv[i]);
		session->argv[i] = mem_strdup(argv[i]);
		i++;
	}
	session->argv[i] = NULL;

	session->console_sock_container_wbuf = mem_new0(char, SESSION_WBUF_SIZE);
	session->pty_master_wbuf = mem_new0(char, SESSION_WBUF_SIZE);
	session->console_sock_container_wbuf_count = 0;
	session->pty_master_wbuf_count = 0;

	return session;
}

static void
c_run_session_free(c_run_session_t *session)
{
	ASSERT(session);
	if (session->cmd)
		mem_free0(session->cmd);
	if (session->pty_slave_name)
		mem_free0(session->pty_slave_name);
	mem_free_array((void *)session->argv, session->argc);
	if (session->console_sock_container_wbuf)
		mem_free0(session->console_sock_container_wbuf);
	if (session->pty_master_wbuf)
		mem_free0(session->pty_master_wbuf);
	mem_free0(session);
}

static void
c_run_free(void *runp)
{
	c_run_t *run = runp;
	ASSERT(run);
	mem_free0(run);
}

static void
c_run_session_cleanup(c_run_session_t *session)
{
	IF_NULL_RETURN(session);

	if (session->active_exec_pid != -1) {
		TRACE("Cleanup exec'ed process: %d", session->active_exec_pid);

		if (!kill(session->active_exec_pid, SIGKILL)) {
			TRACE("Killed process injected by control run with PID: %d",
			      session->active_exec_pid);
		} else {
			TRACE("Failed to kill process inside container");
		}
	}

	if (session->pty_master_io) {
		event_remove_io(session->pty_master_io);
		event_io_free(session->pty_master_io);
		session->pty_master_io = NULL;
	}
	if (session->console_sock_container_io) {
		event_remove_io(session->console_sock_container_io);
		event_io_free(session->console_sock_container_io);
		session->console_sock_container_io = NULL;
	}

	/*
	 * closing the last master reference hangs up the pty: the shell, which
	 * is session leader inside the pidns, and its jobs receive SIGHUP
	 */
	if (session->pty_master != -1) {
		TRACE("Closing PTY master: %d", session->pty_master);
		close(session->pty_master);
		session->pty_master = -1;
	}
	if (session->pty_slave_fd != -1) {
		close(session->pty_slave_fd);
		session->pty_slave_fd = -1;
	}

	TRACE("Shutting down console sockets");
	if (session->console_sock_container != -1)
		shutdown(session->console_sock_container, SHUT_RDWR);
	if (session->console_sock_cmld != -1)
		shutdown(session->console_sock_cmld, SHUT_RDWR);

	session->console_sock_container_wbuf_count = 0;
	session->pty_master_wbuf_count = 0;

	mem_memset0(session->console_sock_container_wbuf, SESSION_WBUF_SIZE);
	mem_memset0(session->pty_master_wbuf, SESSION_WBUF_SIZE);
}

static void
c_run_cleanup(void *runp, UNUSED bool is_rebooting)
{
	c_run_t *run = runp;
	ASSERT(run);

	TRACE("Called c_run cleanup");
	for (list_t *l = run->sessions; l; l = l->next) {
		c_run_session_t *session = l->data;
		c_run_session_cleanup(session);
	}
	list_delete(run->sessions);
	run->sessions = NULL;
}

static int
do_clone(int (*func)(void *), unsigned long flags, void *data)
{
	int ret = 0;
	void *exec_stack = NULL;
	// Allocate node stack

	if (MAP_FAILED == (exec_stack = mmap(NULL, CLONE_STACK_SIZE, PROT_READ | PROT_WRITE,
					     MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0))) {
		WARN_ERRNO("Not enough memory for allocating c_run stack");
		return -1;
	}

	void *exec_stack_high = (void *)((const char *)exec_stack + CLONE_STACK_SIZE);

	ret = clone(func, exec_stack_high, flags, data);

	if (exec_stack && munmap(exec_stack, CLONE_STACK_SIZE) == -1)
		WARN("Could not unmap c_run exec_stack!");

	return ret;
}

static c_run_session_t *
c_run_get_session_by_fd(const c_run_t *run, int session_fd)
{
	for (list_t *l = run->sessions; l; l = l->next) {
		c_run_session_t *session = l->data;
		if (session_fd == session->fd)
			return session;
	}
	ERROR("Session for fd=%d does not exist!", session_fd);
	return NULL;
}

static int
c_run_get_console_sock_cmld(void *runp, int session_fd)
{
	c_run_t *run = runp;
	ASSERT(run);

	c_run_session_t *session = c_run_get_session_by_fd(run, session_fd);
	IF_NULL_RETVAL(session, -1);

	return session->console_sock_cmld;
}

static int
c_run_write_exec_input(void *runp, const uint8_t *exec_input, size_t len, int session_fd)
{
	c_run_t *run = runp;
	ASSERT(run);

	c_run_session_t *session = c_run_get_session_by_fd(run, session_fd);
	IF_NULL_RETVAL(session, -1);

	if (session->active_exec_pid == -1) {
		ERROR("Currently no process executing. Can't write input");
		return -1;
	}
	if (len == 0)
		return 0;

	/*
	 * console_sock_cmld is non-blocking; if the pty side is not draining
	 * and the socket buffer is full, report the partial write to the caller
	 * instead of stalling cmld or pretending the tail was delivered
	 */
	ssize_t total = 0;
	while ((size_t)total < len) {
		ssize_t n = write(session->console_sock_cmld, exec_input + total, len - total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			return -1;
		}
		total += n;
	}
	return total;
}

static int
c_run_set_exec_winsize(void *runp, uint16_t rows, uint16_t cols, int session_fd)
{
	c_run_t *run = runp;
	ASSERT(run);

	c_run_session_t *session = c_run_get_session_by_fd(run, session_fd);
	IF_NULL_RETVAL(session, -1);

	if (session->pty_master < 0)
		return -1;

	struct winsize ws = { .ws_row = rows, .ws_col = cols };
	if (ioctl(session->pty_master, TIOCSWINSZ, &ws) < 0) {
		WARN_ERRNO("Could not set winsize (%hu x %hu) on pty master", rows, cols);
		return -1;
	}
	return 0;
}

static void
c_run_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	c_run_session_t *session = data;

	c_run_t *run = session->run;
	if (NULL == run) {
		// cleanup of c_run subsystem already done just remove signal handler
		TRACE("SIGCHLD handler called for already dead c_run session");
		event_remove_signal(sig);
		event_signal_free(sig);
		return;
	}

	TRACE("SIGCHLD handler called for c_run injected process in container %s with PID %d",
	      container_get_description(run->container), container_get_pid(run->container));
	/*
	 * Wait for the exec helper (active_exec_pid) only. The command itself
	 * runs as the helper's child inside the pidns and is reaped by the
	 * helper, which then exits with the command's status.
	 */
	pid_t exec_pid = session->active_exec_pid;
	pid_t pid = 0;
	int status = 0;
	while ((pid = waitpid(session->active_exec_pid, &status, WNOHANG))) {
		TRACE("Got exited child with PID: %d, exec pid: %d", pid, exec_pid);

		if (pid == exec_pid) {
			TRACE("Injected process exited. Cleaning up.");
			if (WIFEXITED(status)) {
				INFO("Exec'ed process in container %s terminated (status=%d)",
				     container_get_description(run->container),
				     WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				INFO("Injected process in container %s killed by signal %d",
				     container_get_description(run->container), WTERMSIG(status));
			} else {
				continue;
			}

			// remove the sigchld callback for this container from the event loop
			event_remove_signal(sig);
			event_signal_free(sig);

			// Close sockets of the session
			run->sessions = list_remove(run->sessions, session);
			c_run_session_cleanup(session);
			c_run_session_free(session);
			break;
		} else {
			DEBUG("Reaped a descendant process with PID %d of injected process in container %s",
			      pid, container_get_description(run->container));
		}
	}

	TRACE("No more childs to reap. Exiting handler.");
}

static int
c_run_join_container(c_run_t *run)
{
	ASSERT(run);

	if (audit_kernel_write_loginuid(container_audit_get_loginuid(run->container)) < 0) {
		ERROR("Could not set audit uid!");
		goto error;
	}
	if (container_add_pid_to_cgroups(run->container, getpid()) < 0) {
		ERROR("Could not join container cgroups!");
		goto error;
	}
	if (ns_join_all(container_get_pid(run->container), true) < 0) {
		ERROR("Could not set namespaces!");
		goto error;
	}
	if (container_setuid0(run->container)) {
		ERROR("Could not become root in userns!");
		goto error;
	}
	if (container_set_cap_current_process(run->container) < 0) {
		ERROR("Could set container caps!");
		goto error;
	}

	return 0;
error:
	return -1;
}

/*
 * Runs in the innermost child (the one that actually execs the shell), i.e.,
 * the one which is in the container's pid namespace. Only from here setsid()
 * and TIOCSCTTY produce a session/foreground process group inside the pidns,
 * as job control in the executed shell expects. Any failure is fatal: the
 * command must never run on cmld's inherited stdio.
 */
static void
do_pty_setup_in_child(c_run_session_t *session)
{
	if (!session->create_pty)
		return;

	/*
	 * the slave was opened by cmld before joining the container mnt ns
	 * (the pts host node is only visible there) and inherited down here
	 */
	if (session->pty_slave_fd < 0) {
		ERROR("[EXEC] pty slave fd not inherited into shell child");
		_exit(EXIT_FAILURE);
	}

	// setsid() also detaches from any controlling tty inherited from cmld
	if (setsid() < 0) {
		ERROR_ERRNO("[EXEC] setsid in shell child failed");
		_exit(EXIT_FAILURE);
	}

	// TIOCSCTTY makes our pgrp the tty's initial foreground process group
	if (ioctl(session->pty_slave_fd, TIOCSCTTY, 0) < 0) {
		ERROR_ERRNO("[EXEC] TIOCSCTTY in shell child failed");
		_exit(EXIT_FAILURE);
	}

	if (dup2(session->pty_slave_fd, STDIN_FILENO) < 0 ||
	    dup2(session->pty_slave_fd, STDOUT_FILENO) < 0 ||
	    dup2(session->pty_slave_fd, STDERR_FILENO) < 0) {
		ERROR_ERRNO("[EXEC] dup2 pty slave in shell child failed");
		_exit(EXIT_FAILURE);
	}
	if (session->pty_slave_fd > STDERR_FILENO)
		close(session->pty_slave_fd);
}

static int
do_exec(void *data)
{
	ASSERT(data);
	c_run_session_t *session = data;

	IF_TRUE_GOTO(-1 == c_run_join_container(session->run), error);

	TRACE("[EXEC]: Executing command %s in process with PID: %d, PGID: %d, PPID: %d",
	      session->cmd, getpid(), getpgid(getpid()), getppid());

	/*
	 * fork again to also join the pidns, since setns does not switch the
	 * current process into the pidns but sets the childs to be created in
	 * the new ns. Only the inner child sets up the pty as its controlling
	 * terminal, so job control in the executed shell works.
	 */
	pid_t child = fork();
	if (child < 0) {
		ERROR_ERRNO("fork for pidns join failed");
		goto error;
	}
	if (child == 0) {
		/*
		 * cmld only knows this helper's pid; when it kills the helper on
		 * session cleanup, hang up the command as a closed terminal would
		 */
		if (prctl(PR_SET_PDEATHSIG, SIGHUP) < 0)
			WARN_ERRNO("Could not set parent death signal for %s", session->argv[0]);
		do_pty_setup_in_child(session);
		if (setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) < 0)
			WARN_ERRNO("Could not set PATH for %s", session->argv[0]);
		execvp(session->argv[0], session->argv);
		_exit(127);
	}

	int status = 0;
	if (proc_waitpid(child, &status, 0) < 0) {
		ERROR_ERRNO("waitpid for shell child failed");
		_exit(EXIT_FAILURE);
	}
	_exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));

error:
	ERROR_ERRNO("An error occured while trying to execute command. Giving up...");
	_exit(EXIT_FAILURE);
}

static int
readloop(int from_fd, int to_fd, char *buf, int *count)
{
	TRACE("[EXEC] Starting read loop in process %d; from fd %d, to fd %d, PPID: %d", getpid(),
	      from_fd, to_fd, getppid());

	// write pending null
	if (*count == -1) {
		if (write(to_fd, "\0", 1) < 0) {
			TRACE_ERRNO("[READLOOP] write failed.");
			return -1;
		}
		*count = 0;
	}

	// write pending data
	if (*count > 0) {
		TRACE("[READLOOP] Pending %d bytes from fd: %d: %s", *count, from_fd, buf);
		IF_TRUE_RETVAL(*count + 1 > SESSION_WBUF_SIZE, -1);

		if (write(to_fd, buf, *count + 1) < 0) {
			if (errno == EAGAIN)
				return 0; // try again;

			TRACE_ERRNO("[READLOOP] write failed.");
			return -1;
		}
	}

	while (0 < (*count = read(from_fd, buf, SESSION_WBUF_SIZE - 1))) {
		buf[*count] = 0;
		TRACE("[READLOOP] Read %d bytes from fd: %d: %s", *count, from_fd, buf);
		int written = write(to_fd, buf, *count + 1);
		if (written < 0) {
			if (errno == EAGAIN)
				return 0; // try again;

			TRACE_ERRNO("[READLOOP] write failed.");
			return -1;
		}
		if (written == *count) {
			*count = -1;
		} else if (written < *count + 1) {
			*count -= written;
			memmove(buf, buf + written, written);
		}
	}
	if (*count < 0 && errno != EAGAIN) {
		TRACE_ERRNO("[READLOOP] read failed.");
		return -1;
	}

	// all pending data written to to_fd, reset input/output parameter count
	*count = 0;

	return 0;
}

static void
c_run_cb_read_pty(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	ASSERT(data);
	c_run_session_t *session = data;

	if (events & EVENT_IO_EXCEPT) {
		TRACE("Exception on reading pty fd %d", fd);
		event_remove_io(io);
		event_io_free(io);
		session->pty_master_io = NULL;
		close(fd);
		session->pty_master = -1;
		return;
	}

	TRACE("Entering PTY master reading loop");
	if (-1 == readloop(session->pty_master, session->console_sock_container,
			   session->console_sock_container_wbuf,
			   &session->console_sock_container_wbuf_count)) {
		ERROR("Readloop returned an error, cleanup!");
		c_run_session_cleanup(session);
	}
}

static void
c_run_cb_write_pty(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{
	ASSERT(data);
	c_run_session_t *session = data;

	if (events & EVENT_IO_EXCEPT) {
		TRACE("Exception on console socket fd %d", fd);
		event_remove_io(io);
		event_io_free(io);
		session->console_sock_container_io = NULL;
		close(fd);
		session->console_sock_container = -1;
		return;
	}

	TRACE("Entering console sock reading loop");
	if (-1 == readloop(session->console_sock_container, session->pty_master,
			   session->pty_master_wbuf, &session->pty_master_wbuf_count)) {
		ERROR("Readloop returned an error, cleanup!");
		c_run_session_cleanup(session);
	}
}

static int
c_run_prepare_exec(c_run_session_t *session)
{
	// create new PTY
	if (session->create_pty) {
		TRACE("[EXEC] Starting to create new pty");

		int pty_master = 0;

		// CLOEXEC: the command must not inherit its own pty master
		if (-1 == (pty_master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC))) {
			ERROR("[EXEC] Failed to get new PTY master fd\n");
			goto error;
		}

		TRACE("Storing PTY master fd to c_run_t: %d", pty_master);
		session->pty_master = pty_master;

		if (0 != grantpt(pty_master)) {
			ERROR("Failed to grantpt()\n");
			goto error;
		}

		if (0 != unlockpt(pty_master)) {
			ERROR("Failed to unlockpt()\n");
			goto error;
		}

		//TODO get name to alloc sufficient memory?
		session->pty_slave_name = mem_alloc(100);

		ptsname_r(pty_master, session->pty_slave_name, 100);
		TRACE("Created new pty with fd: %i, slave name: %s\n", pty_master,
		      session->pty_slave_name);

		/*
		 * set sane default termios on the pty so the executed shell sees
		 * a functional line discipline (echo, canonical mode, ISIG on
		 * for ^C/^Z, ONLCR, etc.); the client sets its own tty to raw
		 * and forwards the input bytes verbatim
		 */
		struct termios tio;
		if (tcgetattr(pty_master, &tio) == 0) {
			tio.c_iflag |= ICRNL | IXON;
			tio.c_iflag &= ~IGNCR;
			tio.c_oflag |= OPOST | ONLCR;
			tio.c_lflag |=
				ECHO | ECHOE | ECHOK | ECHOKE | ECHOCTL | ISIG | ICANON | IEXTEN;
			tio.c_cflag |= CREAD;
			// control chars: ^C, ^\, DEL, ^U, ^D, ^Z
			tio.c_cc[VINTR] = 3;
			tio.c_cc[VQUIT] = 28;
			tio.c_cc[VERASE] = 127;
			tio.c_cc[VKILL] = 21;
			tio.c_cc[VEOF] = 4;
			tio.c_cc[VSUSP] = 26;
			tio.c_cc[VMIN] = 1;
			tio.c_cc[VTIME] = 0;
			tcsetattr(pty_master, TCSANOW, &tio);
		}

		fd_make_non_blocking(session->pty_master);

		/*
		 * open the pts slave right here in cmld (host mount ns);
		 * the container's mount ns has an empty /dev/pts, so any child
		 * that already joined it cannot open the slave by name
		 */
		// CLOEXEC is dropped by the dup2() onto stdio in the shell child
		session->pty_slave_fd =
			open(session->pty_slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
		if (session->pty_slave_fd < 0) {
			ERROR_ERRNO("Failed to open pty slave %s", session->pty_slave_name);
			goto error;
		}

		// clone child to execute command
		TRACE("clone child process to execute command with PTY");
		session->active_exec_pid = do_clone(do_exec, SIGCHLD, (void *)session);

		if (session->active_exec_pid == -1) {
			TRACE("Failed to fork() ...\n");
			goto error;
		}

		// the exec child inherited the slave fd; cmld no longer needs it
		close(session->pty_slave_fd);
		session->pty_slave_fd = -1;

		// register the pump watchers only once there is a child to serve
		DEBUG("Registering read callback for console socket");
		session->console_sock_container_io =
			event_io_new(session->console_sock_container,
				     EVENT_IO_READ | EVENT_IO_EXCEPT, c_run_cb_write_pty, session);
		event_add_io(session->console_sock_container_io);

		DEBUG("Registering read callback for PTY master fd");
		session->pty_master_io = event_io_new(session->pty_master,
						      EVENT_IO_READ | EVENT_IO_EXCEPT,
						      c_run_cb_read_pty, session);
		event_add_io(session->pty_master_io);

		return 0;
	} else {
		// attach executed process directly to console socket
		TRACE("Executing without PTY");

		// clone child to execute command
		TRACE("Clone child process to execute command without PTY");
		session->active_exec_pid = do_clone(do_exec, SIGCHLD, (void *)session);

		if (session->active_exec_pid == -1) {
			TRACE("Failed to fork() ...\n");
			goto error;
		}

		return 0;
	}

error:
	TRACE("An error occurred. Exiting...");
	return -1;
}

static int
c_run_exec_process(void *runp, int create_pty, char *cmd, ssize_t argc, char **argv, int session_fd)
{
	c_run_t *run = runp;
	ASSERT(run);

	switch (container_get_state(run->container)) {
	case COMPARTMENT_STATE_BOOTING:
	case COMPARTMENT_STATE_RUNNING:
	case COMPARTMENT_STATE_SETUP:
		break;
	default:
		WARN("Container %s is not running thus no command could be exec'ed",
		     container_get_description(run->container));
		return -1;
	}

	ASSERT(cmd);
	TRACE("Trying to excute command \"%s\" inside container", cmd);

	c_run_session_t *session = c_run_session_new(run, create_pty, cmd, argc, argv, session_fd);
	IF_NULL_RETVAL(session, -1);

	run->sessions = list_append(run->sessions, session);

	IF_TRUE_GOTO(c_run_prepare_exec(session) < 0, error);

	TRACE("Registering SIGCHLD handler for injected processes");
	event_signal_t *sig = event_signal_new(SIGCHLD, c_run_sigchld_cb, session);
	event_add_signal(sig);

	return 0;

error:
	TRACE("An error occurred.");
	run->sessions = list_remove(run->sessions, session);
	c_run_session_cleanup(session);
	c_run_session_free(session);
	return -1;
}

static compartment_module_t c_run_module = {
	.name = MOD_NAME,
	.compartment_new = c_run_new,
	.compartment_free = c_run_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = NULL,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_run_cleanup,
	.join_ns = NULL,
};

static void INIT
c_run_init(void)
{
	// register this module in container.c
	container_register_compartment_module(&c_run_module);

	// register relevant handlers implemented by this module
	container_register_run_handler(MOD_NAME, c_run_exec_process);
	container_register_write_exec_input_handler(MOD_NAME, c_run_write_exec_input);
	container_register_set_exec_winsize_handler(MOD_NAME, c_run_set_exec_winsize);
	container_register_get_console_sock_cmld_handler(MOD_NAME, c_run_get_console_sock_cmld);
}

static void DEINIT
c_run_deinit(void)
{
	// unregister handlers implemented by this module
	container_unregister_run_handler(MOD_NAME, c_run_exec_process);
	container_unregister_write_exec_input_handler(MOD_NAME, c_run_write_exec_input);
	container_unregister_set_exec_winsize_handler(MOD_NAME, c_run_set_exec_winsize);
	container_unregister_get_console_sock_cmld_handler(MOD_NAME, c_run_get_console_sock_cmld);

	// unregister this module from container.c
	container_unregister_compartment_module(&c_run_module);
}
