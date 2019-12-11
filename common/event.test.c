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

/** @file event.test.c
  *
  * Unit Test file for event.c
  */

#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "logf.h"
#include "event.h"
#include "macro.h"

/** Test callback for timer
  *
  * The test callback is responsible to test the remove and free
  * timer functions
  */
void
timer_cb(event_timer_t *timer, void *data)
{
	int *count = (int *)data;

	DEBUG("timer cb: timer=%p, count=%d", (void *)timer, *count);
	if (!(*count)--) {
		event_remove_timer(timer);
		event_timer_free(timer);
	}
}

/** Test callback for timer
  *
  * This test callback is just a dummy call
  */
void
timer_cb2(event_timer_t *timer, void *data)
{
	char *payload = (char *)data;

	DEBUG("timer cb: timer=%p, payload=%s", (void *)timer, payload);
}

/** Test callback for signal events
  *
  * The test callback is responsible to remove an io event when a signal
  * occurs
  */
void
signal_cb(int signum, event_signal_t *sig, void *data)
{
	DEBUG("received signal");
	event_remove_io((event_io_t *)data);
	event_io_free((event_io_t *)data);
}

/** Test callback for io events
  *
  * The test callback is responsible to raise a signal in order
  * to react to an input event
  */
void
io_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	DEBUG("received io");
	raise(SIGCHLD);

	INFO("received from fd %d: %d", fd, events);
}

/** This timer callback removes signals
  *
  */
void
timer_cb3(event_timer_t *timer, void *data)
{
	DEBUG("event timer 3 called");
	event_remove_signal((event_signal_t *)data);
	event_signal_free((event_signal_t *)data);
}

/** Dummy timer callback
  *
  */
void
timer_cb4(event_timer_t *timer, void *data)
{
	DEBUG("event timer 4 called");
}

/** Timer callback removing another timer
  *
  */
void
timer_cb5(event_timer_t *timer, void *data)
{
	DEBUG("event timer 5 called");
	event_remove_timer((event_timer_t *)data);
	event_timer_free((event_timer_t *)data);
}

/** Main unit test function for event queue
  *
  */
int
main(void)
{
	int c0 = 8, c1 = 4;
	char *p1 = "t2", *p2 = "t3";

	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: event.test.c");

	DEBUG("add timer events");
	event_timer_t *t0 = event_timer_new(30, 1, &timer_cb, &c0);
	event_add_timer(t0);
	event_timer_t *t1 = event_timer_new(50, 1, &timer_cb, &c1);
	event_add_timer(t1);
	event_timer_t *t2 = event_timer_new(1000, 1, &timer_cb2, p1);
	event_add_timer(t2);
	event_timer_t *t3 = event_timer_new(2500, 1, &timer_cb2, p2);
	event_add_timer(t3);

	DEBUG("add signal and io events and raise signals");
	event_io_t *io = event_io_new(0, EVENT_IO_WRITE, &io_cb, NULL);

	event_signal_t *s0 = event_signal_new(SIGCHLD, &signal_cb, io);
	event_add_signal(s0);

	event_timer_t *t4 = event_timer_new(3500, 1, &timer_cb3, s0);
	event_add_timer(t4);

	event_add_io(io);

	DEBUG("add and remove further events");
	event_timer_t *t6 = event_timer_new(3900, 1, &timer_cb4, NULL);
	event_add_timer(t6);

	event_timer_t *t5 = event_timer_new(3800, 1, &timer_cb5, t6);
	event_add_timer(t5);

	event_loop();

	return 0;
}
