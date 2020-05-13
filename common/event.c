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

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include "event.h"

#include "mem.h"
#include "list.h"
#include "macro.h"

#include <errno.h>
#include <limits.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>

#define timespec_cmp(a, b, CMP)                                                                    \
	(((a)->tv_sec == (b)->tv_sec) ? ((a)->tv_nsec CMP(b)->tv_nsec) :                           \
					((a)->tv_sec CMP(b)->tv_sec))

#define timespec_add(a, b, result)                                                                 \
	do {                                                                                       \
		(result)->tv_sec = (a)->tv_sec + (b)->tv_sec;                                      \
		(result)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec;                                   \
		if ((result)->tv_nsec >= 1000000000L) {                                            \
			(result)->tv_nsec -= 1000000000L;                                          \
			++(result)->tv_sec;                                                        \
		}                                                                                  \
	} while (0)

#define timespec_sub(a, b, result)                                                                 \
	do {                                                                                       \
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;                                      \
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;                                   \
		if ((result)->tv_nsec < 0) {                                                       \
			(result)->tv_nsec += 1000000000L;                                          \
			--(result)->tv_sec;                                                        \
		}                                                                                  \
	} while (0)

#define timespec_set(a, result)                                                                    \
	do {                                                                                       \
		(result)->tv_sec = (a)->tv_sec;                                                    \
		(result)->tv_nsec = (a)->tv_nsec;                                                  \
	} while (0)

#define timespec_now(result) ASSERT(clock_gettime(CLOCK_MONOTONIC_RAW, result) >= 0)

#define timespec_debug(msg, a)                                                                     \
	DEBUG(msg ": (%s)->tv_sec=%u, (%s)->tv_nsec=%09u", #a, (unsigned)(a)->tv_sec, #a,          \
	      (unsigned)(a)->tv_nsec)

struct event_timer {
	void (*func)(event_timer_t *timer,
		     void *data); /**< the function to call when the event is triggered */
	void *data;		  /**< a data pointer to pass to the callback function */
	struct timespec diff;	  /**< interval, relative value */
	struct timespec next;	  /**< next timeout, absolute value */
	int repeat;		  /**< how often to repeat, -1 means repeat indefinitely */
	int repeated;		  /**< how often the timer already expired */
};

struct event_io {
	void (*func)(int fd, unsigned events, event_io_t *io,
		     void *data); /**< the function to call when the event is triggered */
	void *data;		  /**< a data pointer to pass to the callback function */
	int fd;			  /**< the file descriptor which should be watched */
	unsigned events;	  /**< mask of events to listen for */
};

struct event_inotify {
	void (*func)(const char *path, uint32_t mask, event_inotify_t *inotify,
		     void *data); /**< the function to call when the event is triggered */
	void *data;		  /**< a data pointer to pass to the callback function */
	char *path;		  /**< the path to be watched */
	uint32_t mask;		  /**< a bit-mask of events to be watched for */
	int wd;			  /**< the watch descriptor */
	bool todo;		  /**< helper variable for event_inotify_handler() */
};

struct event_signal {
	void (*func)(int signum, event_signal_t *sig,
		     void *data); /**< the function to call when the event is triggered */
	void *data;		  /**< a data pointer to pass to the callback function */
	int signum;		  /**< the signal number of interes */
	bool todo;		  /**< helper variable for event_signal_handler() */
};

static list_t *event_timer_list = NULL;
static list_t *event_signal_list = NULL;
static list_t *event_inotify_list = NULL;
static bool event_signal_received0[NSIG] = { false };
static bool event_signal_received1[NSIG] = { false };
static bool *event_signal_received = event_signal_received0;
static unsigned event_io_active = 0;
static bool event_initialized = false;

/******************************************************************************/

static int
event_timeout(void)
{
	struct timespec next, now, diff;
	event_timer_t *timer;
	list_t *l;

	if (!event_timer_list)
		return -1;

	l = event_timer_list;
	timer = l->data;

	ASSERT(timer);

	timespec_set(&timer->next, &next);

	// find the smallest next time in list
	for (l = l->next; l; l = l->next) {
		timer = l->data;

		ASSERT(timer);

		if (timespec_cmp(&next, &timer->next, >))
			timespec_set(&timer->next, &next);
	}

	timespec_now(&now);

	if (timespec_cmp(&next, &now, <))
		return 0;

	timespec_sub(&next, &now, &diff);

	// should not happen, because timeout was an int too
	ASSERT(diff.tv_sec <= (INT_MAX / 1000));

	// we always round up
	return (diff.tv_sec * 1000) + ((diff.tv_nsec + 999999L) / 1000000L);
}

static void
event_timeout_handler(void)
{
	struct timespec now;

	IF_NULL_RETURN(event_timer_list);

	timespec_now(&now);

	for (list_t *l = event_timer_list; l;) {
		event_timer_t *timer = l->data;

		ASSERT(timer);

		if (timespec_cmp(&now, &timer->next, >)) {
			if (!timer->repeated) {
				event_remove_timer(timer);
			} else {
				if (timer->repeated > 0)
					timer->repeated--;
				if (!timer->repeated)
					event_remove_timer(timer);
				else
					timespec_add(&timer->diff, &timer->next, &timer->next);

				TRACE("Handling timer event %p (func=%p, data=%p, diff=%u.%09us, repeat=%d)",
				      (void *)timer, CAST_FUNCPTR_VOIDPTR timer->func, timer->data,
				      (unsigned)timer->diff.tv_sec, (unsigned)timer->diff.tv_nsec,
				      timer->repeat);

				(timer->func)(timer, timer->data);
			}

			// event_timer_remove modifies the timer list
			// and timer->func might modify the timer list
			// so we will start again at its head...
			if (event_timer_list)
				l = event_timer_list;
			else
				break;
		} else {
			l = l->next;
		}
	}
}

event_timer_t *
event_timer_new(int timeout, int repeat, void (*func)(event_timer_t *timer, void *data), void *data)
{
	event_timer_t *timer;

	IF_FALSE_RETVAL(timeout >= 0, NULL);
	IF_NULL_RETVAL(func, NULL);

	timer = mem_new(event_timer_t, 1);
	timer->func = func;
	timer->data = data;
	timer->diff.tv_sec = timeout / 1000;
	timer->diff.tv_nsec = (timeout % 1000) * 1000000L;
	timer->next.tv_sec = 0;
	timer->next.tv_nsec = 0;
	timer->repeat = repeat;

	return timer;
}

void
event_timer_free(event_timer_t *timer)
{
	IF_NULL_RETURN(timer);

	mem_free(timer);
}

void
event_add_timer(event_timer_t *timer)
{
	struct timespec now;

	IF_NULL_RETURN(timer);

	timespec_now(&now);
	timespec_add(&now, &timer->diff, &timer->next);
	timer->repeated = timer->repeat;

	event_timer_list = list_append(event_timer_list, timer);

	TRACE("Added timer event %p (func=%p, data=%p, diff=%u.%09us, repeat=%d)", (void *)timer,
	      CAST_FUNCPTR_VOIDPTR timer->func, timer->data, (unsigned)timer->diff.tv_sec,
	      (unsigned)timer->diff.tv_nsec, timer->repeat);
}

void
event_remove_timer(event_timer_t *timer)
{
	IF_NULL_RETURN(timer);

	TRACE("Removing timer event %p from list %p", (void *)timer, (void *)event_timer_list);
	event_timer_list = list_remove(event_timer_list, timer);

	TRACE("Removed timer event %p (func=%p, data=%p, diff=%u.%09us, repeat=%d)", (void *)timer,
	      CAST_FUNCPTR_VOIDPTR timer->func, timer->data, (unsigned)timer->diff.tv_sec,
	      (unsigned)timer->diff.tv_nsec, timer->repeat);
}

/******************************************************************************/

static int
event_epoll_fd(int reset)
{
	static int fd = -1;

	if (fd < 0 || (fd >= 0 && reset == 1)) {
		if (fd >= 0 && close(fd) < 0) {
			ERROR_ERRNO("Failed to cleanly close old epoll fd");
		}

		fd = epoll_create(1);

		ASSERT(fd >= 0);

		DEBUG("epoll_create returned %d", fd);

		// set close-on-exec flag
		int oldflags;
		oldflags = fcntl(fd, F_GETFD, 0);
		if (oldflags < 0)
			WARN_ERRNO("fcntl failed");
		oldflags |= FD_CLOEXEC;
		if (fcntl(fd, F_SETFD, oldflags) < 0)
			WARN_ERRNO("fcntl failed");
	}

	return fd;
}

static void
event_reset_fd(void)
{
	event_epoll_fd(1);
}

// compiling with -Wall, -Werror
// must cast types appropriately in wrapper functions
static void
wrapped_remove_timer(void *elem)
{
	event_remove_timer((event_timer_t *)elem);
	event_timer_free(elem);
}

static void
wrapped_remove_signal(void *elem)
{
	event_remove_signal((event_signal_t *)elem);
	event_signal_free(elem);
}

static void
wrapped_remove_inotify(void *elem)
{
	event_remove_inotify((event_inotify_t *)elem);
	event_inotify_free(elem);
}

void
event_reset()
{
	TRACE("Resetting event epoll fd");
	event_reset_fd();

	TRACE("Resetting event timers");
	list_foreach(event_timer_list, wrapped_remove_timer);
	event_timer_list = NULL;

	TRACE("Resetting event signal handler list");
	list_foreach(event_signal_list, wrapped_remove_signal);
	event_signal_list = NULL;

	TRACE("Resetting event inotify list");
	list_foreach(event_inotify_list, wrapped_remove_inotify);
	event_inotify_list = NULL;
}

event_io_t *
event_io_new(int fd, unsigned events,
	     void (*func)(int fd, unsigned events, event_io_t *io, void *data), void *data)
{
	event_io_t *io;

	IF_FALSE_RETVAL(events, NULL);
	IF_NULL_RETVAL(func, NULL);

	io = mem_new(event_io_t, 1);
	io->func = func;
	io->data = data;
	io->fd = fd;
	io->events = events;

	return io;
}

void
event_io_free(event_io_t *io)
{
	IF_NULL_RETURN(io);

	mem_free(io);
}

void
event_add_io(event_io_t *io)
{
	struct epoll_event epoll_event;

	IF_NULL_RETURN(io);

	epoll_event.events = 0;
	epoll_event.events |= (io->events & EVENT_IO_READ) ? EPOLLIN : 0;
	epoll_event.events |= (io->events & EVENT_IO_WRITE) ? EPOLLOUT : 0;
	epoll_event.events |= (io->events & EVENT_IO_PRI) ? EPOLLPRI : 0;
	epoll_event.data.ptr = io;

	if (epoll_ctl(event_epoll_fd(0), EPOLL_CTL_ADD, io->fd, &epoll_event) < 0)
		WARN_ERRNO("epoll_ctl failed"); // TODO: handle error?
	else
		event_io_active++;

	TRACE("Added io event %p (func=%p, data=%p, fd=%d, events=0x%x)", (void *)io,
	      CAST_FUNCPTR_VOIDPTR io->func, io->data, io->fd, io->events);
}

void
event_remove_io(event_io_t *io)
{
	IF_NULL_RETURN(io);
	TRACE("Removing io event %p", (void *)io);

	if (epoll_ctl(event_epoll_fd(0), EPOLL_CTL_DEL, io->fd, NULL) < 0)
		WARN_ERRNO("epoll_ctl failed"); // TODO: handle error?
	else
		event_io_active--;

	TRACE("Removed io event %p (func=%p, data=%p, fd=%d, events=0x%x)", (void *)io,
	      CAST_FUNCPTR_VOIDPTR io->func, io->data, io->fd, io->events);
	//TODO unlink?
}

static int
event_epoll(int timeout)
{
	struct epoll_event epoll_events[128];
	int n, i;

	TRACE("Calling epoll_wait with timeout=%ums", timeout);
	n = epoll_wait(event_epoll_fd(0), epoll_events, ELEMENTSOF(epoll_events), timeout);
	if (n < 0) {
		if (errno == EINTR) // caused by suspend (no real error)
			TRACE_ERRNO("epoll_wait interrupted by system");
		else
			DEBUG_ERRNO("epoll_wait failed");

	} else if (n > 0) {
		for (i = 0; i < n; i++) {
			event_io_t *io = epoll_events[i].data.ptr;
			uint32_t events = epoll_events[i].events;
			unsigned e;

			ASSERT(io);

			e = 0;
			e |= (events & EPOLLIN) ? EVENT_IO_READ : 0;
			e |= (events & EPOLLOUT) ? EVENT_IO_WRITE : 0;
			e |= (events & EPOLLERR) ? EVENT_IO_EXCEPT : 0;
			e |= (events & EPOLLHUP) ? EVENT_IO_EXCEPT : 0;
			e |= (events & EPOLLPRI) ? EVENT_IO_PRI : 0;

			TRACE("Handling io event %p (func=%p, data=%p, fd=%d, events=0x%x)",
			      (void *)io, CAST_FUNCPTR_VOIDPTR io->func, io->data, io->fd,
			      io->events);

			(io->func)(io->fd, e, io, io->data);

			TRACE("Finished io handling");
		}
	} // else timeout

	return n;
}

/******************************************************************************/

static void
event_inotify_handler(int wd, const char *path, uint32_t mask)
{
	for (list_t *l = event_inotify_list; l; l = l->next) {
		event_inotify_t *inotify = l->data;

		ASSERT(inotify);

		// mark all elements before any inotify->func is called
		inotify->todo = true;
	}

	for (list_t *l = event_inotify_list; l;) {
		event_inotify_t *inotify = l->data;

		ASSERT(inotify);

		/* inotify events on the same path get the same watch descriptor!
		 * therefore we have to check for a match in the mask additionally */
		if (inotify->todo && inotify->wd == wd && mask & inotify->mask) {
			inotify->todo = false;

			TRACE("Handling inotify event %p (func=%p, data=%p, wd=%d, path=%s, mask=0x%08x)",
			      (void *)inotify, CAST_FUNCPTR_VOIDPTR inotify->func, inotify->data,
			      wd, inotify->path, inotify->mask);

			if (path) {
				char *full_path = mem_printf("%s/%s", inotify->path, path);
				(inotify->func)(full_path, mask, inotify, inotify->data);
				mem_free(full_path);
			} else {
				(inotify->func)(inotify->path, mask, inotify, inotify->data);
			}

			// inotify->func might modify the inotify list
			// so we will start again at its head
			if (event_inotify_list)
				l = event_inotify_list;
			else
				break;
		} else {
			l = l->next;
		}
	}
}

static void
event_inotify_cb(int fd, unsigned events, UNUSED event_io_t *io, UNUSED void *data)
{
	char buf[(8 * (sizeof(struct inotify_event) + NAME_MAX + 1))] __attribute__((aligned(8)));
	char *p;
	ssize_t n;

	if (!(events & EVENT_IO_READ))
		return;

	n = read(fd, buf, sizeof(buf));
	ASSERT(n >= 0);

	if (!n)
		return;

	for (p = buf; p < buf + n;) {
		struct inotify_event *e = (struct inotify_event *)p;
		const char *name = e->len ? e->name : NULL;

		TRACE("Read inotify event %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
		      "(wd=%d, mask=0x%08x, cookie=0x%08x, name=%s)",
		      e->mask & IN_ACCESS ? "IN_ACCESS " : "",
		      e->mask & IN_MODIFY ? "IN_MODIFY " : "",
		      e->mask & IN_ATTRIB ? "IN_ATTRIB " : "",
		      e->mask & IN_CLOSE_WRITE ? "IN_CLOSE_WRITE " : "",
		      e->mask & IN_CLOSE_NOWRITE ? "IN_CLOSE_NOWRITE " : "",
		      e->mask & IN_OPEN ? "IN_OPEN " : "",
		      e->mask & IN_MOVED_FROM ? "IN_MOVED_FROM " : "",
		      e->mask & IN_MOVED_TO ? "IN_MOVED_TO " : "",
		      e->mask & IN_CREATE ? "IN_CREATE " : "",
		      e->mask & IN_DELETE ? "IN_DELETE " : "",
		      e->mask & IN_DELETE_SELF ? "IN_DELETE_SELF " : "",
		      e->mask & IN_MOVE_SELF ? "IN_MOVE_SELF " : "",
		      e->mask & IN_UNMOUNT ? "IN_UNMOUNT " : "",
		      e->mask & IN_Q_OVERFLOW ? "IN_Q_OVERFLOW " : "",
		      e->mask & IN_IGNORED ? "IN_IGNORED " : "", e->wd, e->mask, e->cookie, name);

		event_inotify_handler(e->wd, name, e->mask);

		p += sizeof(struct inotify_event) + e->len;
	}
}

static int
event_inotify_fd(void)
{
	static int fd = -1;

	if (fd >= 0)
		return fd;

	fd = inotify_init();
	if (fd < 0)
		FATAL_ERRNO("Could not init inotify");

	event_io_t *io = event_io_new(fd, EVENT_IO_READ, &event_inotify_cb, NULL);
	event_add_io(io);

	return fd;
}

event_inotify_t *
event_inotify_new(const char *path, uint32_t mask,
		  void (*func)(const char *path, uint32_t mask, event_inotify_t *inotify,
			       void *data),
		  void *data)
{
	event_inotify_t *inotify;

	IF_NULL_RETVAL(path, NULL);
	IF_NULL_RETVAL(func, NULL);

	inotify = mem_new(event_inotify_t, 1);
	inotify->func = func;
	inotify->data = data;
	inotify->path = mem_strdup(path);
	inotify->mask = mask;
	inotify->wd = -1;
	inotify->todo = false;

	return inotify;
}

void
event_inotify_free(event_inotify_t *inotify)
{
	IF_NULL_RETURN(inotify);

	if (inotify->path)
		mem_free(inotify->path);

	mem_free(inotify);
}

int
event_add_inotify(event_inotify_t *inotify)
{
	IF_NULL_RETVAL(inotify, -1);

	inotify->wd =
		inotify_add_watch(event_inotify_fd(), inotify->path, inotify->mask | IN_MASK_ADD);
	if (inotify->wd < 0) {
		WARN_ERRNO("Could not add inotify watch for %s", inotify->path);
		return -1;
	}

	event_inotify_list = list_append(event_inotify_list, inotify);

	TRACE("Added inotify event %p (func=%p, data=%p, wd=%d, path=%s, mask=0x%08x)",
	      (void *)inotify, CAST_FUNCPTR_VOIDPTR inotify->func, inotify->data, inotify->wd,
	      inotify->path, inotify->mask);

	return 0;
}

void
event_remove_inotify(event_inotify_t *inotify)
{
	IF_NULL_RETURN(inotify);

	TRACE("Removing inotify event %p", (void *)inotify);
	event_inotify_list = list_remove(event_inotify_list, inotify);

	/* walk through list and check if there are other handlers on the same
	 * watch descriptor */
	bool others = false;
	for (list_t *l = event_inotify_list; l; l = l->next) {
		event_inotify_t *inotify_cur = l->data;
		if (inotify_cur->wd == inotify->wd) {
			if (!others)
				/* If the handler is the first of the others it should overwrite the mask */
				inotify_cur->wd = inotify_add_watch(
					event_inotify_fd(), inotify_cur->path, inotify_cur->mask);
			else
				/* There was already another handler which reset the mask, so we add now */
				inotify_cur->wd =
					inotify_add_watch(event_inotify_fd(), inotify_cur->path,
							  inotify_cur->mask | IN_MASK_ADD);
			others = true;
		}
	}

	if (!others) {
		/* If there were no other handlers with the same watch descriptor we remove it completely */
		if (inotify_rm_watch(event_inotify_fd(), inotify->wd) < 0) {
			WARN_ERRNO("Could not remove inotify watch for %s", inotify->path);
			return;
		}
	}

	TRACE("Removed inotify event %p (func=%p, data=%p, wd=%d, path=%s, mask=0x%08x)",
	      (void *)inotify, CAST_FUNCPTR_VOIDPTR inotify->func, inotify->data, inotify->wd,
	      inotify->path, inotify->mask);
}

/******************************************************************************/

event_signal_t *
event_signal_new(int signum, void (*func)(int signum, event_signal_t *sig, void *data), void *data)
{
	event_signal_t *sig;

	IF_NULL_RETVAL(func, NULL);
	IF_FALSE_RETVAL(signum > 0, NULL);
	IF_FALSE_RETVAL(signum < NSIG, NULL);

	sig = mem_new(event_signal_t, 1);
	sig->func = func;
	sig->data = data;
	sig->signum = signum;
	sig->todo = false;

	return sig;
}

void
event_signal_free(event_signal_t *sig)
{
	IF_NULL_RETURN(sig);

	mem_free(sig);
}

void
event_add_signal(event_signal_t *sig)
{
	IF_NULL_RETURN(sig);

	event_signal_list = list_append(event_signal_list, sig);

	TRACE("Added signal event %p (func=%p, data=%p, signal=%d (%s))", (void *)sig,
	      CAST_FUNCPTR_VOIDPTR sig->func, sig->data, sig->signum, strsignal(sig->signum));
}

void
event_remove_signal(event_signal_t *sig)
{
	IF_NULL_RETURN(sig);

	TRACE("Removing signal event %p from list", (void *)sig);
	event_signal_list = list_remove(event_signal_list, sig);

	TRACE("Removed signal event %p (func=%p, data=%p, signal=%d (%s))", (void *)sig,
	      CAST_FUNCPTR_VOIDPTR sig->func, sig->data, sig->signum, strsignal(sig->signum));
}

static void
event_signal_handler(void)
{
	bool *received;

	TRACE("event_signal_handler() called");

	/* We have two arrays to allow atomic switching from one array to the
	 * other to guarantee that we do not miss signals entirely. It is still
	 * possible that the handler is only called once for multiple signals
	 * of the same type.
	 */
	received = event_signal_received;
	if (event_signal_received == event_signal_received0)
		event_signal_received = event_signal_received1;
	else
		event_signal_received = event_signal_received0;

	for (list_t *l = event_signal_list; l; l = l->next) {
		event_signal_t *sig = l->data;

		ASSERT(sig);

		// mark all elements before any sig->func is called
		sig->todo = true;
	}

	for (list_t *l = event_signal_list; l;) {
		event_signal_t *sig = l->data;

		ASSERT(sig);
		ASSERT(sig->signum > 0);
		ASSERT(sig->signum < NSIG);

		if (sig->todo && received[sig->signum]) {
			sig->todo = false;

			TRACE("Handling signal event %p (func=%p, data=%p, signal=%d (%s))",
			      (void *)sig, CAST_FUNCPTR_VOIDPTR sig->func, sig->data, sig->signum,
			      strsignal(sig->signum));

			(sig->func)(sig->signum, sig, sig->data);

			// sig->func might modify the signal list
			// so we will start again at its head
			if (event_signal_list)
				l = event_signal_list;
			else
				break;
		} else {
			l = l->next;
		}
	}

	for (int i = 0; i < NSIG; i++)
		received[i] = false;
}

/******************************************************************************/

static void
event_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
	if (sigaction(signum, act, oldact) < 0)
		WARN_ERRNO("sigaction failed for signal %s (%d)", strsignal(signum), signum);
}

static void
event_sa_handler(int signum)
{
	TRACE("Received signal %d (%s)", signum, strsignal(signum));
	if (signum < NSIG)
		event_signal_received[signum] = true;
}

void
event_init(void)
{
	if (event_initialized)
		return;

	struct sigaction action;

	action.sa_handler = event_sa_handler;
	ASSERT(sigemptyset(&action.sa_mask) >= 0);
	action.sa_flags = 0;

	event_sigaction(SIGTERM, &action, NULL);
	event_sigaction(SIGQUIT, &action, NULL);
	event_sigaction(SIGINT, &action, NULL);
	event_sigaction(SIGALRM, &action, NULL);
	event_sigaction(SIGCHLD, &action, NULL);
	event_sigaction(SIGPIPE, &action, NULL);
	event_sigaction(SIGUSR1, &action, NULL);
	event_sigaction(SIGUSR2, &action, NULL);
	event_sigaction(SIGHUP, &action, NULL);

	event_initialized = true;
}

void
event_loop(void)
{
	if (!event_initialized) {
		WARN("Called event_loop() without prior initialization through event_init(). Signals might have been lost!.");
		event_init();
	}
	DEBUG("Starting event loop");

	while (event_signal_list || event_timer_list || event_io_active) {
		int timeout;

		event_signal_handler();

		timeout = event_timeout();
		if (!event_epoll(timeout))
			event_timeout_handler();

		TRACE("Handled event");
	}

	DEBUG("Leaving event loop");
}
