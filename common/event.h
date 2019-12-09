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

/**
 * @file event.h
 *
 * Provides functionality for handling timer, I/O, and signal events.
 * A single timer may expire periodically for a specified number of times or
 * it may periodically expire indefinitely until it gets explicitly removed. Upon
 * each timer expiration, the registered callback function will be invoked. The
 * registered callback functions for I/O and signal events will be invoked whenever
 * one of the monitored events or signals occur, respectively. Both I/O and signal
 * events will be active until they get explicitly removed.
 */

#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>

typedef struct event_timer event_timer_t;

#define EVENT_TIMER_REPEAT_FOREVER -1

/**
 * Creates a new timer.
 *
 * @param timeout The timeout in milliseconds.
 * @param repeat How often func should be called or EVENT_TIMER_REPEAT_FOREVER.
 * @param func Pointer to a callback function.
 * @param data Payload data that will be passed to the callback function.
 * @return The newly created timer.
 */
event_timer_t *
event_timer_new(int timeout, int repeat, void (*func)(event_timer_t *timer, void *data), void *data);

/**
 * Frees the allocated memory of the timer.
 *
 * @param timer The timer to be freed.
 */
void
event_timer_free(event_timer_t *timer);

/**
 * Adds the timer to the event loop.
 *
 * @param timer The timer to be added to the event loop.
 */
void
event_add_timer(event_timer_t *timer);

/**
 * Removes the timer from the event loop.
 *
 * @param timer The timer to be removed from the event loop.
 */
void
event_remove_timer(event_timer_t *timer);

#define EVENT_IO_READ (1 << 0)
#define EVENT_IO_WRITE (1 << 1)
#define EVENT_IO_EXCEPT (1 << 2)
#define EVENT_IO_PRI (1 << 3)

typedef struct event_io event_io_t;

/**
 * Creates a new I/O event.
 *
 * @param fd The file descriptor to be monitored.
 * @param events Bitwise-or'd events to be monitored on the fd.
 *               May be a combination of EVENT_IO_READ, EVENT_IO_WRITE, and EVENT_IO_EXCEPT.
 * @param func A pointer to the callback function.
 * @param data Payload data to be passed to the callback function.
 * @return The newly created I/O event.
 */
event_io_t *
event_io_new(int fd, unsigned events, void (*func)(int fd, unsigned events, event_io_t *io, void *data), void *data);

/**
 * Frees the allocated memory of the I/O event.
 *
 * @param io The I/O event to be freed.
 */
void
event_io_free(event_io_t *io);

/**
 * Adds the I/O event to the event loop.
 *
 * @param io The I/O event to be added to the event loop.
 */
void
event_add_io(event_io_t *io);

/**
 * Removes the I/O event from the event loop.
 *
 * @param io The I/O event to be removed from the event loop.
 */
void
event_remove_io(event_io_t *io);

/**
 * Resets the event subsystem to its initial state
 * As this sets all event lists to zero,
 * the event_loop() call currently executing will exit
 */
void
event_reset();

// TODO: doxygen for event_inotify*

typedef struct event_inotify event_inotify_t;

event_inotify_t *
event_inotify_new(const char *path, uint32_t mask,
		  void (*func)(const char *path, uint32_t mask, event_inotify_t *inotify, void *data), void *data);

void
event_inotify_free(event_inotify_t *inotify);

int
event_add_inotify(event_inotify_t *inotify);

void
event_remove_inotify(event_inotify_t *inotify);

typedef struct event_signal event_signal_t;

/**
 * Creates a new signal event.
 *
 * @param signum Any valid signal except SIGKILL and SIGSTOP.
 * @param func A pointer to the callback function.
 * @param data Payload data to be passed to the callback function.
 * @return The newly created signal event.
 */
event_signal_t *
event_signal_new(int signum, void (*func)(int signum, event_signal_t *sig, void *data), void *data);

/**
 * Frees the allocated memory of the signal event.
 *
 * @param sig The signal event to be freed.
 */
void
event_signal_free(event_signal_t *sig);

/**
 * Adds the signal event to the event loop.
 *
 * @param sig The signal event to be added to the event loop.
 */
void
event_add_signal(event_signal_t *sig);

/**
 * Removes the signal event from the event loop.
 *
 * @param sig The signal event to be removed from the event loop.
 */
void
event_remove_signal(event_signal_t *sig);

/**
 * Initializes the event loop. Should be called before event_add_signal() is used;
 * otherwise, signals that occur before event_loop() is started might be lost and
 * not get delivered to their registered signal handlers.
 */
void
event_init(void);

/**
 * Invokes the event loop that handles all registered timer, I/O, and signal
 * events. The function returns if there are no more registered timer, I/O, and
 * signal events.
 */
void
event_loop(void);

#endif /* EVENT_H */
