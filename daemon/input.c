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

#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>

#include "hardware.h"
#include "cmld.h"
#include "input.h"

#include "common/macro.h"
#include "common/event.h"

/* define the time a power button press must last to be a switch-to-a0 button press (in ms) */
#define PB_SWITCH_TIMEOUT 500

#define UINPUT_PATH "/dev/uinput"

#define CMLD_WAKE_LOCK_PB "PowerButtonPressed"

int input_inject_fd = -1;

bool input_pb_injecting_enabled = true;

event_timer_t *input_powerbutton_timer = NULL;

static void
input_cleanup_switch_timeout()
{
	ASSERT(input_powerbutton_timer);

	event_remove_timer(input_powerbutton_timer);
	event_timer_free(input_powerbutton_timer);
	input_powerbutton_timer = NULL;
}

/**
 * Check if bit i in byte-buffer buf is set.
 * @return 1 if set, 0 if not
 */
int
is_bit_set(int i, const uint8_t *buf)
{
	return buf[i / CHAR_BIT] & (1 << i % CHAR_BIT);
}
/**
 * Clones the device given by the file descriptor by creating and returning
 * a new uinput device with the exact same feature set plus the ability to
 * handle KEY_POWER_INJECT events.
 *
 * @return A file descriptor of the newly created cloned device or -1 on error
 */
static int
input_device_clone_with_power_inject(int devin)
{
	int newdev_fd;
	newdev_fd = open(UINPUT_PATH, O_WRONLY | O_NONBLOCK);
	if (newdev_fd < 0) {
		ERROR_ERRNO("Could not open uinput device");
		return -1;
	}

	struct uinput_user_dev newdev;
	memset(&newdev, 0, sizeof(newdev));

	if (ioctl(devin, (int) EVIOCGID, &newdev.id) == -1) {
		ERROR_ERRNO("Could not read device id from input device");
		return -1;
	}

	if (ioctl(devin, EVIOCGNAME(UINPUT_MAX_NAME_SIZE), newdev.name) == -1) {
		ERROR_ERRNO("Could not read device name from input device");
		return -1;
	}

	/***************************************************/
	/* Clone features of device into new uinput device */

	uint8_t types[EV_MAX / CHAR_BIT + 1] = {0};

	/* Read event types supported by input device into buffer */
	if (ioctl(devin, (int) EVIOCGBIT(0, sizeof(types)), types) == -1) {
		ERROR_ERRNO("Could not read event types information from input device");
		return -1;
	}

	/* Iterate over event types supported by the device */
	for (int i = 0; i < EV_MAX; ++i) {
		/* skip not supported event types */
		if (!is_bit_set(i, types))
			continue;

		/* Find out which event type we are dealing with */
		int op;
		switch (i) {
			case EV_KEY: op = UI_SET_KEYBIT; break;
			case EV_REL: op = UI_SET_RELBIT; break;
			case EV_ABS: op = UI_SET_ABSBIT; break;
			case EV_MSC: op = UI_SET_MSCBIT; break;
			case EV_LED: op = UI_SET_LEDBIT; break;
			case EV_SND: op = UI_SET_SNDBIT; break;
			case EV_SW: op = UI_SET_SWBIT; break;
			default: continue;
		}

		/* Configure the new device to support the event type as well */
		if (ioctl(newdev_fd, UI_SET_EVBIT, i) == -1) {
			ERROR_ERRNO("Could not set EVBIT for newly cloned input device");
			return -1;
		}

		/* Read the supported event codes for the current event type into buffer */
		uint8_t codes[KEY_MAX / CHAR_BIT + 1] = {0};
		if (ioctl(devin, (int) EVIOCGBIT(i, sizeof(codes)), codes) == -1) {
			ERROR_ERRNO("Could not get event bits");
			return -1;
		}
		/* Iterate over the codes */
		for (int code = 0; code < KEY_MAX; code++) {
			/* Set code in new device if it is set in the original device */
			if (is_bit_set(code, codes)) {
				if (ioctl(newdev_fd, op, code) == -1) {
					ERROR_ERRNO("Could not set event bit");
					return -1;
				}
			}
		}
	}

	/* Add the KEY_POWER_INJECT keybit to the newly created uinput device */
	if (ioctl(newdev_fd, UI_SET_KEYBIT, hardware_get_key_power_inject())) {
		ERROR_ERRNO("Could not set KEYBIT for uinput device");
		return -1;
	}

	/* write device configuration to uinput */
	if (write(newdev_fd, &newdev, sizeof(newdev)) <= 0) {
		ERROR_ERRNO("Could not write uinput device config to uinput");
		return -1;
	}
	/* create device */
	if (ioctl(newdev_fd, UI_DEV_CREATE) == -1) {
		ERROR_ERRNO("Could not create uinput device");
		return -1;
	}

	return newdev_fd;
}

void
input_pb_injecting_disable()
{
	if (input_pb_injecting_enabled) {
		DEBUG("disabled power button injecting");
	}
	input_pb_injecting_enabled = false;
}

void
input_pb_injecting_enable()
{
	if (!input_pb_injecting_enabled) {
		DEBUG("enabled power button injecting");
	}
	input_pb_injecting_enabled = true;
}

static void
input_powerbutton_switch_timeout_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	INFO("Long power button press detected, switching to a0");

	// Allow system going to sleep when the timeout happens
	hardware_suspend_unblock(CMLD_WAKE_LOCK_PB, sizeof(CMLD_WAKE_LOCK_PB));

	if (cmld_container_switch_to_a0() < 0)
		ERROR("Could not switch to a0 after long power button press");

	input_cleanup_switch_timeout();
}

static int
input_inject_power_button(int value) {
	/* only forward power button if injecting is enabled */
	if (!input_pb_injecting_enabled)
		return 0;

	struct input_event event;

	memset(&event, 0, sizeof(event));

	event.type = EV_KEY;
	event.code = hardware_get_key_power_inject();
	event.value = value;
	int n = write(input_inject_fd, &event, sizeof(event));
	if (n != sizeof(event)) {
		ERROR_ERRNO("Could not write event to input file");
		return -1;
	}
	return 0;
}

static int
input_inject_syn() {
	struct input_event event;

	memset(&event, 0, sizeof(event));
	event.type = EV_SYN;
	event.code = SYN_REPORT;
	event.value = 0;
	int n = write(input_inject_fd, &event, sizeof(event));
	if (n != sizeof(event)) {
		ERROR_ERRNO("Could not write event to input file");
		return -1;
	}
	return 0;
}

static void
input_inject_power_button_short() {
	/* First, inject power down event */
	if (input_inject_power_button(1) < 0) {
		WARN("Could not inject power button down event");
	}
	/* Second, inject power up event */
	if (input_inject_power_button(0) < 0) {
		WARN("Could not inject power button up event");
	}
	/* Finally, send syn event */
	if (input_inject_syn() < 0) {
		WARN("Could not inject power button up event");
	}
}

static void
input_handle(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	struct input_event event;
	ssize_t n;

	if (events & EVENT_IO_EXCEPT) {
		ERROR("Received an IO_EXCEPT event for the power button input device");
		// TODO maybe we should try to reopen the input file?
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	n = read(fd, &event, sizeof(event));
	if (n <= 0) {
		return;
	} else {
		DEBUG("%s: n=%zd event %d:%d:%d", __func__, n,
		      event.type, event.code, event.value);

		if (!(event.type == EV_KEY && event.code == KEY_POWER)) {
			/* we only care about power key events */
			return;
		}

		if (cmld_containers_get_a0() == cmld_containers_get_foreground()) {
			/* a0 is in foreground, so simply forward event and return */
			input_inject_power_button(event.value);
			input_inject_syn();
			return;
		}

		/* Handle power button events */
		if (event.value == 1) {
			/* power button pressed */
			INFO("Power button pressed");
			// Do not allow system going to sleep until the button is released
			hardware_suspend_block(CMLD_WAKE_LOCK_PB, sizeof(CMLD_WAKE_LOCK_PB));
			if (input_powerbutton_timer) {
				WARN("Received two power button down events in a row which should not happen..");
				input_cleanup_switch_timeout();
			}
			/* register timer for switch-to-a0 timeout */
			input_powerbutton_timer = event_timer_new(PB_SWITCH_TIMEOUT, 1, &input_powerbutton_switch_timeout_cb, NULL);
			event_add_timer(input_powerbutton_timer);
		} else if (event.value == 0) {
			/* power button released */
			INFO("Power button released");
			/* check if the timer is still there */
			if (input_powerbutton_timer) {
				/* the timer is still there, so it was a short button press */
				/* simply inject power button and remove timeout timer */
				input_inject_power_button_short();

				input_cleanup_switch_timeout();

				// Allow system going to sleep when the button is released
				hardware_suspend_unblock(CMLD_WAKE_LOCK_PB,
							 sizeof(CMLD_WAKE_LOCK_PB));
			}
		}
	}
}

/******************************************************************************/

int
input_init(void)
{
	const char *input_file = hardware_get_powerbutton_input_path();
	int input_file_fd;

	DEBUG("%s", __func__);
	IF_NULL_RETVAL(input_file, 1);

	/* open input device to receive power events */
	input_file_fd = open(input_file, O_RDWR | O_NONBLOCK);
	if (input_file_fd < 0) {
		WARN_ERRNO("Could not open %s", input_file);
		return -1;
	}
	INFO("%s: %s opened", __func__, input_file);

	event_io_t *io_comm;
	io_comm = event_io_new(input_file_fd, EVENT_IO_READ, &input_handle, 0);
	event_add_io(io_comm);

	/* create virtual input device for injecting power button presses into containers
	 * which is simply a clone of the original input file delivering KEY_POWER events
	 * plus the ability to handle KEY_POWER_INJECT events */
	input_inject_fd = input_device_clone_with_power_inject(input_file_fd);
	if (input_inject_fd < 0) {
		ERROR("Could not clone input file");
		return -1;
	}

	return 0;
}
