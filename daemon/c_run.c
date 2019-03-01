#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include <macro.h>

#include "common/mem.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/fd.h"
#include "hardware.h"
#include "container.h"
#include "c_run.h"

struct c_run {
	container_t *container;
	int console_sock_cmld;
	int console_sock_container;
	pid_t active_exec_pid;
};

c_run_t *
c_run_new(container_t *container)
{
	c_run_t *run = mem_new0(c_run_t, 1);
	run->container = container;
	run->console_sock_cmld = -1;
	run->console_sock_container = -1;
	run->active_exec_pid = -1;
	return run;
}

void
c_run_free(c_run_t *run)
{
	ASSERT(run);
	mem_free(run);
}

void
c_run_cleanup(c_run_t *run)
{
	ASSERT(run);

	if (run->active_exec_pid != -1) {
		if (! kill(run->active_exec_pid, SIGKILL)) {
			// Happens if called from sigchld_handler
			DEBUG("Failed to kill process inside container");
		}

		shutdown(run->console_sock_container, SHUT_WR);
		shutdown(run->console_sock_cmld, SHUT_WR);
		run->active_exec_pid = -1;
	}
}

int
c_run_get_console_sock_cmld(const c_run_t * run)
{
	ASSERT(run);
	return run->console_sock_cmld;
}

int
c_run_get_active_exec_pid(const c_run_t * run)
{
	ASSERT(run);
	return run->active_exec_pid;
}

int
c_run_write_exec_input(c_run_t *run, char *exec_input)
{
	if (run->active_exec_pid != -1) {
		return write(run->console_sock_cmld, exec_input, strlen(exec_input));
	} else {
		return -1;
	}
}

static int
setns(int fd, int nstype)
{
	return syscall(__NR_setns, fd, nstype);
}

#define MAX_NS 10
int fd[MAX_NS] = { 0 };

static int
setns_cb(const char *path, const char *file, void *data)
{
	int *i = data;

	char *ns_file = mem_printf("%s%s", path, file);
	TRACE("Opening namespace file %s", ns_file);

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
	mem_free(ns_file);
	exit(EXIT_FAILURE);
}

static int
c_run_set_namespaces(pid_t pid)
{
	char *pid_string = mem_printf("%d", pid);

	TRACE("Setting namespaces for pid %s", pid_string);

	// set namespaces
	char *folder = mem_printf("/proc/%d/ns/", pid);

	int i = 0;
	if (dir_foreach(folder, &setns_cb, &i)) {
		FATAL("Could not traverse PID dir in procfs, wrong PID?");
		goto error;
	}

	for (int j = 0; j < i; j++) {
		if (setns(fd[j], 0) == -1) {	/* Join that namespace */
			FATAL_ERRNO("Could not join namespace");
			goto error;
		}
	}

	TRACE("Successfully joined all namespaces");

	mem_free(pid_string);
	mem_free(folder);
	return 0;

error:
	mem_free(pid_string);
	mem_free(folder);
	exit(EXIT_FAILURE);
}

static int
do_exec (c_run_t *run, char *cmd, char **argv, int fd)
{
	if (-1 == dup2(fd, STDIN_FILENO)) {
		ERROR("Failed to redirect stdin to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if (-1 == dup2(fd, STDOUT_FILENO)) {
		ERROR ("Failed to redirect stdout to cmld socket. Exiting...");
		exit(EXIT_FAILURE);
	}

	if (-1 == dup2(fd, STDERR_FILENO)) {
		ERROR("Failed to redirect stderr to cmld. Exiting...");
		exit(EXIT_FAILURE);
	}

	container_add_pid_to_cgroups(run->container, getpid());

	c_run_set_namespaces(container_get_pid(run->container));

	container_set_cap_current_process(run->container);

	TRACE("[EXEC: Executing command %s]", cmd);
	execve(cmd, argv, NULL);

	ERROR_ERRNO("Failed to execve");

	exit(EXIT_FAILURE);
}

static void
readloop(int from_fd, int to_fd)
{
	int count = 0;
	char buf[1024];

	while (1) {
		if (0 < (count = read(from_fd, &buf, sizeof(buf)-1))) {
			buf[count] = 0;
			write(to_fd, buf, count+1);
		} else {
			exit(EXIT_FAILURE);
		}
	}
}

static int
c_run_prepare_pty(c_run_t *run, int create_pty, char *cmd, char **argv)
{
	//create new PTY
	if (create_pty) {
		TRACE("[EXEC] Starting to create new pty");

		int pty_master = 0;

		if (-1 == (pty_master = posix_openpt(O_RDWR))) {
			ERROR("[EXEC] Failed to get new PTY master fd\n");
			exit(EXIT_FAILURE);
		}

		if (0 != grantpt(pty_master)) {
			printf("Failed to grantpt()\n");
			exit(EXIT_FAILURE);
		}

		if (0 != unlockpt(pty_master)) {
			printf("Failed to unlockpt()\n");
			exit(EXIT_FAILURE);;
		}

		char pty_slave_name[50];
		ptsname_r(pty_master, pty_slave_name, sizeof(pty_slave_name));
		TRACE("Created new pty with fd: %i, slave name: %s\n", pty_master, pty_slave_name);

		//fork childs for reading/writing PTY master fd
		int pid = fork();

		if (pid == -1) {
			ERROR("Failed to fork(), exiting...\n");
			exit(EXIT_FAILURE);
		} else if (pid == 0) {
			TRACE("[EXEC] Forked PTY master output reading process, PID: %d", getpid());
			readloop(pty_master, run->console_sock_container);
		} else {
			// fork child to execute command
			int pid2 = fork();

			if (pid2 < 0) {
				ERROR("[EXEC] Failed to fork child to excute command.");
				exit(EXIT_FAILURE);
			} else if (pid2 == 0) {
				TRACE("[EXEC] Command executing child forked, PID: %d", getpid());
				int pty_slave_fd = -1;

				// open PTY slave
				if (-1 == (pty_slave_fd = open(pty_slave_name, O_RDWR))) {
						ERROR("Failed to open pty slave: %s\n", pty_slave_name);
					shutdown(pty_master, SHUT_WR);
					exit(EXIT_FAILURE);
				}

				const char *current_pty = ctermid(NULL);
				DEBUG("[EXEC] Current controlling PTY is: %s\n", current_pty);

				setsid();

				if (-1 == ioctl(STDIN_FILENO, TIOCNOTTY)) {
					TRACE("[EXEC] Failed to release current controlling pty.\n");
				}

				if (-1 == ioctl(pty_slave_fd, TIOCSCTTY, NULL)) {
				ERROR("[EXEC] Failed to set controlling pty slave\n");
					exit(EXIT_FAILURE);
				}

				// attach executed process to new PTY slave
				do_exec(run, cmd, argv, pty_slave_fd);
			} else {
				while (1) {
					TRACE("[EXEC] Starting console socket read loop in process %d", getpid());
					readloop(run->console_sock_container, pty_master);
				}
			}

			exit(EXIT_SUCCESS);
		}

		 exit(EXIT_SUCCESS);
	} else {
		// attach executed process directly to console socket
		TRACE("Executing without PTY");
		int ret = do_exec(run, cmd, argv, run->console_sock_container);
		exit(ret);
	}
}

int
c_run_exec_process(c_run_t *run, int create_pty, char *cmd, ssize_t argc, char **argv)
{
	TRACE("Trying to excute command \"%s\" inside container", cmd);
	ASSERT(cmd);

	if (run->active_exec_pid != -1) {
		TRACE("[C_RUN] Already executing command. Aborting request.");
		return -1;
	}

	TRACE("Trying to excute command inside container");

	/* Create a socketpair for communication with the console task */
	int cfd[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, cfd)) {
		WARN("Could not create socketpair for communication with console task!");
		exit(EXIT_FAILURE);
	}

	run->console_sock_cmld = cfd[0];
	run->console_sock_container = cfd[1];

	TRACE("Making cmld console socket nonblocking");
	fd_make_non_blocking(run->console_sock_cmld);

	pid_t pid = fork();

	if (pid < 0) {
		exit(EXIT_FAILURE);
	} else if ( pid == 0 ) {
		TRACE("Exec child forked, pid: %d", getpid());
		//Add NULL pointer to end of argv
		char ** exec_args = NULL;

		if (argc > 0 && argv != NULL) {
			ssize_t i = 0;
			exec_args = mem_alloc(sizeof(char *) * (argc + 1));

			while (i < argc)
			{
				TRACE("Got argument: %s", argv[i]);
				exec_args[i] = mem_strdup(argv[i]);
				i++;
			}

			exec_args[i] = NULL;
		}

		if (setpgid(0, container_get_pid(run->container)) < 0) {
			ERROR("Failed to set GID of exec child to container PID: %d", container_get_service_pid(run->container));
			exit(EXIT_FAILURE);
		}

		// close the cmld end of the console task sockets
		close(run->console_sock_cmld);

		c_run_prepare_pty(run, create_pty, cmd, exec_args);
		// free argv
		mem_free_array((void *) exec_args, argc);
		exit(EXIT_FAILURE);
	}

	TRACE("Storing PID of active container: %d", pid);
	run->active_exec_pid = pid;

	return 0;
}
