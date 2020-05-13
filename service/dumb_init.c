/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Yelp, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "common/macro.h"

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dumb_init.h"

static pid_t child_pid = -1;
static char use_setsid = 1;

static void
forward_signal(int signum)
{
	kill(use_setsid ? -child_pid : child_pid, signum);
	DEBUG("Forwarded signal %d to children.\n", signum);
}

/*
 * The dumb-init signal handler.
 *
 * The main job of this signal handler is to forward signals along to our child
 * process(es). In setsid mode, this means signaling the entire process group
 * rooted at our child. In non-setsid mode, this is just signaling the primary
 * child.
 *
 * In most cases, simply proxying the received signal is sufficient. If we
 * receive a job control signal, however, we should not only forward it, but
 * also sleep dumb-init itself.
 *
 * This allows users to run foreground processes using dumb-init and to
 * control them using normal shell job control features (e.g. Ctrl-Z to
 * generate a SIGTSTP and suspend the process).
 *
 * The libc manual is useful:
 * https://www.gnu.org/software/libc/manual/html_node/Job-Control-Signals.html
 *
 * When running in setsid mode, however, it is not sufficient to forward
 * SIGTSTP/SIGTTIN/SIGTTOU in most cases. If the process has not added a custom
 * signal handler for these signals, then the kernel will not apply default
 * signal handling behavior (which would be suspending the process) since it is
 * a member of an orphaned process group.
 *
 * Sadly this doesn't appear to be well documented except in the kernel itself:
 * https://github.com/torvalds/linux/blob/v4.2/kernel/signal.c#L2296-L2299
 *
 * Forwarding SIGSTOP instead is effective, though not ideal; unlike SIGTSTP,
 * SIGSTOP cannot be caught, and so it doesn't allow processes a change to
 * clean up before suspending. In non-setsid mode, we proxy the original signal
 * instead of SIGSTOP for this reason.
*/
static void
dumb_init_handle_signal(int signum)
{
	DEBUG("Received signal %d.\n", signum);
	if (signum == SIGCHLD) {
		int status, exit_status;
		pid_t killed_pid;
		while ((killed_pid = waitpid(-1, &status, WNOHANG)) > 0) {
			if (WIFEXITED(status)) {
				exit_status = WEXITSTATUS(status);
				DEBUG("A child with PID %d exited with exit status %d.\n",
				      killed_pid, exit_status);
			} else {
				assert(WIFSIGNALED(status));
				exit_status = 128 + WTERMSIG(status);
				DEBUG("A child with PID %d was terminated by signal %d.\n",
				      killed_pid, exit_status - 128);
			}

			if (killed_pid == child_pid) {
				forward_signal(SIGTERM); // send SIGTERM to any remaining children
				DEBUG("Child exited with status %d. Goodbye.\n", exit_status);
				//exit(exit_status);
			}
		}
	} else if (signum == SIGTSTP || // tty: background yourself
		   signum == SIGTTIN || // tty: stop reading
		   signum == SIGTTOU	// tty: stop writing
	) {
		if (use_setsid) {
			DEBUG("Running in setsid mode, so forwarding SIGSTOP instead.\n");
			forward_signal(SIGSTOP);
		} else {
			DEBUG("Not running in setsid mode, so forwarding the original signal (%d).\n",
			      signum);
			forward_signal(signum);
		}

		DEBUG("Suspending self due to TTY signal.\n");
		kill(getpid(), SIGSTOP);
	} else {
		forward_signal(signum);
	}
}

void
dumb_init_set_child_pid(pid_t pid)
{
	child_pid = pid;
}

void
dumb_init_signal_handler()
{
	int signum;
	sigset_t all_signals;
	sigfillset(&all_signals);
	sigprocmask(SIG_BLOCK, &all_signals, NULL);

	for (;;) {
		sigwait(&all_signals, &signum);
		dumb_init_handle_signal(signum);
	}
}
