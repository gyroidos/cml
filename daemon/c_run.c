#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <linux/sockios.h>
#include <sched.h>

#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include <macro.h>

#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/proc.h"
#include "hardware.h"
#include "container.h"
#include "c_run.h"
#include "cmld.h"

//TODO define in container.h?
#define CLONE_STACK_SIZE 8192

struct c_run {
	container_t *container;
	int console_sock_cmld;
	int console_sock_container;
	int pty_master;
	pid_t active_exec_pid;
	event_io_t *pty_master_read_io;
	event_io_t *pty_master_write_io;
	char *pty_slave_name;
	int pty_slave_fd;
	int create_pty;
	char *cmd;
	ssize_t argc;
	char **argv;
};

c_run_t *
c_run_new(container_t *container)
{
	c_run_t *run = mem_new0(c_run_t, 1);
	run->container = container;
	run->console_sock_cmld = -1;
	run->console_sock_container = -1;
	run->pty_master = -1;
	run->active_exec_pid = -1;
	run->pty_master_read_io = NULL;
	run->pty_master_write_io = NULL;
	run->pty_slave_name = NULL;
	run->pty_slave_fd = -1;
	run->create_pty = -1;
	run->cmd = NULL;
	run->argc = 0;

	return run;
}

void
c_run_free(c_run_t *run)
{
	ASSERT(run);
	mem_free(run);
}

// to be called from exec event loop
static void
c_run_internal_cleanup(c_run_t *run)
{
	ASSERT(run);

	TRACE("Called c_run cleanup, active_exec_pid: %d", run->active_exec_pid);

	if (run->active_exec_pid != -1) {
		TRACE("Cleanup exec'ed process: %d", run->active_exec_pid);

		if (!kill(run->active_exec_pid, SIGKILL)) {
			TRACE("Killed process injected by control run with PID: %d",
			      run->active_exec_pid);
		} else {
			TRACE("Failed to kill process inside container");
		}
		run->active_exec_pid = -1;
	}
	if (run->pty_master != -1) {
		TRACE("Shutting down PTY master: %d", run->pty_master);
		shutdown(run->pty_master, SHUT_WR);
		TRACE("Shuttind down read direction of console container socket: %d",
		      run->console_sock_container);
		shutdown(run->console_sock_container, SHUT_RD);

		TRACE("Shutting down console_sock_container: %d", run->console_sock_container);
		shutdown(run->console_sock_container, SHUT_RDWR);
		TRACE("Shutting down console_sock_cmld: %d", run->console_sock_cmld);
		shutdown(run->console_sock_cmld, SHUT_RDWR);
		TRACE("Finished socket shutdown. Exiting cleanup.");
	} else {
		TRACE("Shutting down console sockets");
		shutdown(run->console_sock_container, SHUT_RDWR);
		shutdown(run->console_sock_cmld, SHUT_RDWR);
	}
}

void
c_run_cleanup(c_run_t *run)
{
	c_run_internal_cleanup(run);
}

static int
do_clone(int (*func)(void *), unsigned long flags, void *data)
{
	void *exec_stack = NULL;
	/* Allocate node stack */
	if (!(exec_stack = alloca(CLONE_STACK_SIZE))) {
		WARN_ERRNO("Not enough memory for allocating container stack");
		return -1;
	}

	void *exec_stack_high = (void *)((const char *)exec_stack + CLONE_STACK_SIZE);

	return clone(func, exec_stack_high, flags, data);
}

int
c_run_get_console_sock_cmld(const c_run_t *run)
{
	ASSERT(run);
	return run->console_sock_cmld;
}

int
c_run_write_exec_input(c_run_t *run, char *exec_input)
{
	if (run->active_exec_pid != -1) {
		TRACE("Write message \"%s\" to fd: %d", exec_input, run->console_sock_cmld);
		return write(run->console_sock_cmld, exec_input, strlen(exec_input));
	} else {
		WARN("Currently no process executing. Can't write input");
		return -1;
	}
}

void
c_run_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	c_run_t *run = data;

	ASSERT(run);

	TRACE("SIGCHLD handler called for c_run injected process in container %s with PID %d",
	      container_get_description(run->container), container_get_pid(run->container));
	/* The exec loop is started in a new session having it's PID as PGID.
	 * Therefore wait for this PGID. If a descendant process call setsid it doesn't
	 * get reaped by this handler. This enables the user to inject processes who
	 * continue running after the command injected by control exits */
	pid_t exec_pid = run->active_exec_pid;
	pid_t pid = 0;
	int status = 0;
	while ((pid = waitpid(run->active_exec_pid, &status, WNOHANG))) {
		TRACE("Got exited child with PID: %d, exec pid: %d", pid, exec_pid);

		//if (pid == exec_pid || pid == run->pty_master_read_pid || run->pty_master_write_pid) {
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

			/* remove the sigchld callback for this container from the event loop */
			event_remove_signal(sig);
			event_signal_free(sig);

			/* Close sockets */
			c_run_internal_cleanup(run);

			return;
		} else {
			DEBUG("Reaped a descendant process with PID %d of injected process in container %s",
			      pid, container_get_description(run->container));
		}
	}

	TRACE("No more childs to reap. Exiting handler.");
}

int
setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}

#define MAX_NS 10
int fd[MAX_NS] = { 0 };

static bool
is_self_userns_file(char *file)
{
	struct stat s, userns_s;
	IF_TRUE_RETVAL_TRACE(stat(file, &s) == -1, false);
	IF_TRUE_RETVAL_TRACE(stat("/proc/self/ns/user", &userns_s) == -1, false);

	return (s.st_dev == userns_s.st_dev) && (s.st_ino == userns_s.st_ino) ? true : false;
}

static int
setns_cb(const char *path, const char *file, void *data)
{
	int *i = data;

	char *ns_file = mem_printf("%s%s", path, file);
	TRACE("Opening namespace file %s", ns_file);

	if (is_self_userns_file(ns_file)) {
		TRACE("Joining same user namespace, not allowed and also not necessary -> skip.");
		mem_free(ns_file);
		return EXIT_SUCCESS;
	}

	if (*i >= MAX_NS) {
		ERROR("Too many namespace files found in %s", path);
		goto error;
	}

	fd[*i] = open(ns_file, O_RDONLY);
	if (fd[*i] == -1) {
		ERROR_ERRNO("Could not open namespace file %s", ns_file);
		goto error;
	}

	*i = *i + 1;

	mem_free(ns_file);
	return EXIT_SUCCESS;

error:
	TRACE("An error occurred. Exiting...");
	mem_free(ns_file);
	exit(EXIT_FAILURE);
}

static int
c_run_set_namespaces(pid_t pid)
{
	char *pid_string = mem_printf("%d", pid);

	TRACE("Setting namespaces to match namespaces of pid %s", pid_string);

	// set namespaces
	char *folder = mem_printf("/proc/%d/ns/", pid);

	int i = 0;
	if (dir_foreach(folder, &setns_cb, &i)) {
		ERROR("Could not traverse PID dir in procfs, wrong PID?");
		goto error;
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) { /* Join that namespace */
			ERROR_ERRNO("Could not join namespace");
			goto error;
		}
	}

	TRACE("Successfully joined all namespaces");

	mem_free(pid_string);
	mem_free(folder);
	return 0;

error:
	TRACE("An error occurred. Exiting...");
	mem_free(pid_string);
	mem_free(folder);
	return -1;
}

static int
do_exec(c_run_t *run)
{
	//Add NULL pointer to end of argv
	char **exec_args = NULL;

	if (run->argc > 0 && run->argv != NULL) {
		ssize_t i = 0;
		size_t total_len = ADD_WITH_OVERFLOW_CHECK(run->argc, (size_t)1);
		total_len = MUL_WITH_OVERFLOW_CHECK(sizeof(char *), total_len);
		exec_args = mem_alloc(total_len);

		while (i < run->argc) {
			TRACE("Got argument: %s", run->argv[i]);
			exec_args[i] = mem_strdup(run->argv[i]);
			i++;
		}

		exec_args[i] = NULL;
	}

	if (container_add_pid_to_cgroups(run->container, getpid()) < 0) {
		ERROR("Could not join container cgroups!");
		goto error;
	}
	if (c_run_set_namespaces(container_get_pid(run->container)) < 0) {
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

	TRACE("[EXEC]: Executing command %s in process with PID: %d, PGID: %d, PPID: %d", run->cmd,
	      getpid(), getpgid(getpid()), getppid());

	if (-1 == dup2(run->pty_slave_fd, STDIN_FILENO)) {
		ERROR("Failed to redirect stdin to cmld socket. Exiting...");
		goto error;
	}

	if (-1 == dup2(run->pty_slave_fd, STDOUT_FILENO)) {
		ERROR("Failed to redirect stdout to cmld socket. Exiting...");
		goto error;
	}

	if (-1 == dup2(run->pty_slave_fd, STDERR_FILENO)) {
		ERROR("Failed to redirect stderr to cmld. Exiting...");
		goto error;
	}

	if (NULL == exec_args) {
		ERROR("No command was specified to execute. Exiting...");
		exit(EXIT_FAILURE);
	}

	/*
	 * fork again to also join the pidns, since setns does not switch
	 * the current process into the pidns but sets the childs to be created
	 * in the new ns.
	 */
	IF_TRUE_GOTO(proc_fork_and_execvp((const char *const *)exec_args) < 0, error);
	mem_free_array((void *)exec_args, run->argc);
	exit(EXIT_SUCCESS);

error:
	ERROR_ERRNO("An error occured while trying to execute command. Giving up...");
	mem_free_array((void *)exec_args, run->argc);
	exit(EXIT_FAILURE);
}

static int
do_pty_exec(void *data)
{
	ASSERT(data);
	c_run_t *run = (c_run_t *)data;

	run->active_exec_pid = getpid();

	TRACE("[EXEC] Prepare command execution in process with PID: %d, PGID: %d", getpid(),
	      getpgid(getpid()));
	run->pty_slave_fd = -1;

	// open PTY slave
	if (-1 == (run->pty_slave_fd = open(run->pty_slave_name, O_RDWR))) {
		TRACE("Failed to open pty slave: %s\n", run->pty_slave_name);
		//TODO avoid access to pty master from child ?
		goto error;
	}

	const char *current_pty = ctermid(NULL);
	TRACE("[EXEC] Current controlling PTY is: %s\n", current_pty);

	if (-1 == ioctl(STDIN_FILENO, TIOCNOTTY)) {
		TRACE("[EXEC] Failed to release current controlling pty.\n");
	}

	// make process session leader
	// necessary for TIOCSCTTY
	setsid();

	if (-1 == ioctl(run->pty_slave_fd, TIOCSCTTY, NULL)) {
		ERROR("[EXEC] Failed to set controlling pty slave\n");
		goto error;
	}

	do_exec(run);
error:
	TRACE("An error occurred. Exiting...");
	exit(EXIT_FAILURE);
}

static int
readloop(int from_fd, int to_fd)
{
	TRACE("[EXEC] Starting read loop in process %d; from fd %d, to fd %d, PPID: %d", getpid(),
	      from_fd, to_fd, getppid());

	int count = 0;
	char buf[1024];

	while (0 < (count = read(from_fd, &buf, sizeof(buf) - 1))) {
		buf[count] = 0;
		TRACE("[READLOOP] Read %d bytes from fd: %d: %s", count, from_fd, buf);
		if (write(to_fd, buf, count + 1) < 0) {
			TRACE_ERRNO("[READLOOP] write failed.");
			return -1;
		}
	}
	if (count < 0 && errno != EAGAIN) {
		TRACE_ERRNO("[READLOOP] read failed.");
		return -1;
	}
	return 0;
}

static void
c_run_cb_read_pty(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	c_run_t *run = (c_run_t *)data;

	if (events & EVENT_IO_EXCEPT) {
		TRACE("Exception on reading pty fd %d", fd);
		event_remove_io(io);
		event_io_free(io);
		run->pty_master_read_io = NULL;
		close(fd);
		return;
	}

	TRACE("Entering PTY master reading loop");
	if (-1 == readloop(run->pty_master, run->console_sock_container)) {
		ERROR("Readloop returned an error, cleanup!");
		c_run_internal_cleanup(run);
	}
}

static void
c_run_cb_write_pty(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	c_run_t *run = (c_run_t *)data;

	if (events & EVENT_IO_EXCEPT) {
		TRACE("Exception on console socket fd %d", fd);
		event_remove_io(io);
		event_io_free(io);
		run->pty_master_write_io = NULL;
		close(fd);
		return;
	}

	TRACE("Entering console sock reading loop");
	if (-1 == readloop(run->console_sock_container, run->pty_master)) {
		ERROR("Readloop returned an error, cleanup!");
		c_run_internal_cleanup(run);
	}
}

static int
c_run_prepare_exec(c_run_t *run)
{
	//create new PTY
	if (run->create_pty) {
		TRACE("[EXEC] Starting to create new pty");

		int pty_master = 0;

		if (-1 == (pty_master = posix_openpt(O_RDWR))) {
			ERROR("[EXEC] Failed to get new PTY master fd\n");
			goto error;
		}

		if (0 != grantpt(pty_master)) {
			ERROR("Failed to grantpt()\n");
			goto error;
		}

		if (0 != unlockpt(pty_master)) {
			ERROR("Failed to unlockpt()\n");
			goto error;
		}

		//TODO get name to alloc sufficient memory?
		run->pty_slave_name = mem_alloc(100);

		ptsname_r(pty_master, run->pty_slave_name, 100);
		TRACE("Created new pty with fd: %i, slave name: %s\n", pty_master,
		      run->pty_slave_name);

		TRACE("Storing PTY master fd to c_run_t: %d", pty_master);
		run->pty_master = pty_master;

		fd_make_non_blocking(run->pty_master);

		DEBUG("Registering read callback for PTY master fd");
		run->pty_master_write_io =
			event_io_new(run->console_sock_container, EVENT_IO_READ | EVENT_IO_EXCEPT,
				     c_run_cb_write_pty, run);
		event_add_io(run->pty_master_write_io);

		DEBUG("Registering read callback for console socket");
		run->pty_master_read_io = event_io_new(
			run->pty_master, EVENT_IO_READ | EVENT_IO_EXCEPT, c_run_cb_read_pty, run);
		event_add_io(run->pty_master_read_io);

		//clone child to execute command
		TRACE("clone child process to execute command with PTY");
		run->active_exec_pid = do_clone(do_pty_exec, SIGCHLD, (void *)run);

		if (run->active_exec_pid == -1) {
			TRACE("Failed to fork() ...\n");
			goto error;
		}

		return 0;
	} else {
		// attach executed process directly to console socket
		TRACE("Executing without PTY");

		//clone child to execute command
		TRACE("Clone child process to execute command without PTY");
		run->active_exec_pid = do_clone(do_pty_exec, SIGCHLD, (void *)run);

		if (run->active_exec_pid == -1) {
			TRACE("Failed to fork() ...\n");
			goto error;
		}

		return 0;
	}

error:
	TRACE("An error occurred. Exiting...");
	return -1;
}

int
c_run_exec_process(c_run_t *run, int create_pty, char *cmd, ssize_t argc, char **argv)
{
	TRACE("Trying to excute command \"%s\" inside container", cmd);
	ASSERT(cmd);

	if (run->active_exec_pid != -1) {
		TRACE("Already executing command. Aborting request.");
		return -1;
	}

	/* Create a socketpair for communication with the console task */
	TRACE("Setting up sockets");
	int cfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, cfd)) {
		ERROR_ERRNO("Could not create socketpair for communication with console task!");
		return -1;
	}

	run->console_sock_cmld = cfd[0];
	run->console_sock_container = cfd[1];

	TRACE("Making cmld console socket nonblocking");
	fd_make_non_blocking(run->console_sock_cmld);
	fd_make_non_blocking(run->console_sock_container);

	// prepare c_run_t
	run->create_pty = create_pty;
	run->cmd = cmd;
	run->argc = argc;
	run->argv = argv;

	IF_TRUE_GOTO(c_run_prepare_exec(run) < 0, error);

	TRACE("Registering SIGCHLD handler for injected processes");
	event_signal_t *sig = event_signal_new(SIGCHLD, c_run_sigchld_cb, run);
	event_add_signal(sig);

	return 0;

error:
	TRACE("An error occurred.");
	c_run_internal_cleanup(run);
	return -1;
}
