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

/**
 * @file uevent.h
 *
 * This module handles uevents from the netlink interface coming from the kernel or udev.
 * It parses those events into a dedicated uevent struct and handles them.
 */
#ifndef UEVENT_H_
#define UEVENT_H_

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "uuid.h"

#define UEVENT_BUF_LEN 64 * 1024

#define UEVENT_ACTION_ADD (1 << 0)
#define UEVENT_ACTION_BIND (1 << 1)
#define UEVENT_ACTION_CHANGE (1 << 2)
#define UEVENT_ACTION_REMOVE (1 << 3)
#define UEVENT_ACTION_UNBIND (1 << 4)
#define UEVENT_ACTION_MOVE (1 << 5)

typedef struct uevent_uev uevent_uev_t;

typedef struct uevent_event uevent_event_t;

typedef enum { UEVENT_UEV_TYPE_KERNEL = 1, UEVENT_UEV_TYPE_UDEV } uevent_uev_type_t;

/**
 * Trigger cold boot events to allow user namespaced containers to fixup
 * their device nodes by udevd in container.
 * The uuid of a container can be used for synthetic events to allow directing
 * events to corresponding container only.
 *
 * @param synth_uuid uuid used for syth event paramter in uevent.
 * @param filter callback function which is called for each major:minor.
 * @param data generic data pointer which is given to filter callback data.
 */
void
uevent_udev_trigger_coldboot(const uuid_t *synth_uuid,
			     bool (*filter)(int major, int minor, void *data), void *data);

/**
 * Creates a new uev event.
 *
 * @param type The type of uevent UEVENT_TYPE_KERNEL or UEVENT_TYPE_UDEV to be registered.
 * @param actions Bitwise-or'd events to be monitored of the registered type.
 *                May be a combination of UEVENT_ACTION_ADD, UEVENT_ACTION_REMOVE,
 *                UEVENT_ACTION_BIND and EVENT_IO_EXCEPT.
 * @param func A pointer to the callback function.
 * @param data Payload data to be passed to the callback function.
 * @return The newly created uev event.
 */
uevent_uev_t *
uevent_uev_new(uevent_uev_type_t type, unsigned actions,
	       void (*func)(unsigned actions, uevent_event_t *event, void *data), void *data);
/**
 * Adds the uev event to the event loop.
 *
 * @param uev The uev event to be added to the event loop.
 */
int
uevent_add_uev(uevent_uev_t *uev);

/**
 * Removes the uev event from the event loop.
 *
 * @param uev The uev event to be removed from the event loop.
 */
void
uevent_remove_uev(uevent_uev_t *uev);

/**
 * Frees the allocated memory of the uev event.
 *
 * @param uev The uev event to be freed.
 */
void
uevent_uev_free(uevent_uev_t *uev);

uint16_t
uevent_event_get_usb_vendor(const uevent_event_t *uevent);

uint16_t
uevent_event_get_usb_product(const uevent_event_t *uevent);

char *
uevent_event_get_synth_uuid(const uevent_event_t *event);

char *
uevent_event_get_devname(const uevent_event_t *event);

char *
uevent_event_get_devtype(const uevent_event_t *event);

char *
uevent_event_get_devpath(const uevent_event_t *event);

char *
uevent_event_get_subsystem(const uevent_event_t *event);

char *
uevent_event_get_interface(const uevent_event_t *event);

int
uevent_event_get_major(const uevent_event_t *event);

int
uevent_event_get_minor(const uevent_event_t *event);

uevent_event_t *
uevent_event_replace_synth_uuid_new(const uevent_event_t *event, char *uuid_string);

uevent_event_t *
uevent_replace_member(const uevent_event_t *uevent, char *oldmember, char *newmember);

uevent_event_t *
uevent_event_copy_new(const uevent_event_t *event);

/**
 * This function forks a new child in the target netns (and userns) of netns_pid
 * in which the uevents should be injected. In the child the UEVENT netlink socket
 * is connected and a new message containing the raw uevent will be created and
 * sent to that socket.
 */
int
uevent_event_inject_into_netns(uevent_event_t *event, pid_t netns_pid, bool join_userns);

/**
 * Parses string representation of a uevent and returns a pointer to a uevent_event_t.
 * Separation of fields via newlines as read from sysfs, for instance, is supported.
 *
 * @param uev String representation of the uevent to be parsed.
 * @return The newly created uevent_event_t event.
 */
uevent_event_t *
uevent_parse_from_string_new(const char *uev);
#endif /* UEVENT_H_ */
