/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <linux/ioctl.h>
#include <linux/input.h>
#include <unistd.h>
#include "fcntl.h"

#include "control.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "container.h"
#include "uevent.h"
#include "input.h"
#include "cmld.h"

// The following defines represent parts of the syntax of /proc/bus/input/devices
#define IFACE_PREFIX "I:"
#define HANDLER_PREFIX "H: Handlers="
#define EVENT "event"
#define SYSRQ_EVENT "sysrq"
#define PIN_ENTRY_TIMEOUT_MS 60000
#define MAX_PIN_LEN 64

typedef struct {
	control_t *control;
	container_t *container;
} container_start_cb_data_t;

typedef struct {
	control_t *control;
} pin_entry_timer_cb_data_t;

// TODO required global static because it needs to be freed in the
// in the timer callback in case of pin entry timeout
// Better solution?
static char *input_key = NULL;
static int input_key_index = 0;

static int input_fd = 0;
static event_io_t *input_event_io = NULL;
static event_timer_t *input_timer = NULL;
static bool input_pin_entry_active = false;

/**
 * Converts a keyboard scan code value into its ASCII digit representation
 *
 * @param int in    The input keyboard scan code value
 * @param char* out Its ASCII digit representation
 * @return          0 in case of success, -1 if the scan code value was not a digit code
 */
static int
input_event_code_to_ascii_num(int in, char *out)
{
	if (in == KEY_1 || in == KEY_KP1) {
		*out = '1';
		return 0;
	} else if (in == KEY_2 || in == KEY_KP2) {
		*out = '2';
		return 0;
	} else if (in == KEY_3 || in == KEY_KP3) {
		*out = '3';
		return 0;
	} else if (in == KEY_4 || in == KEY_KP4) {
		*out = '4';
		return 0;
	} else if (in == KEY_5 || in == KEY_KP5) {
		*out = '5';
		return 0;
	} else if (in == KEY_6 || in == KEY_KP6) {
		*out = '6';
		return 0;
	} else if (in == KEY_7 || in == KEY_KP7) {
		*out = '7';
		return 0;
	} else if (in == KEY_8 || in == KEY_KP8) {
		*out = '8';
		return 0;
	} else if (in == KEY_9 || in == KEY_KP9) {
		*out = '9';
		return 0;
	} else if (in == KEY_0 || in == KEY_KP0) {
		*out = '0';
		return 0;
	} else {
		return -1;
	}
}

/**
 * Parses /proc/bus/input/devices to find the /dev/input/eventx input file for the
 * usb devices specified by vendor_id and product_id
 *
 * @param vendor_id     The vendor ID of the usb device to get the input file for
 * @param product_id    The product ID of the usb device to get the input file for
 * @return              The /dev/input/eventx file of the usb device
 */
static char *
input_get_usb_input_event_file(uint16_t vendor_id, uint16_t product_id)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	ssize_t n;
	uint16_t bus;
	uint16_t vid;
	uint16_t pid;
	uint16_t ver;
	char *event = NULL;
	char *event_path = NULL;

	fp = fopen("/proc/bus/input/devices", "r");
	IF_NULL_RETVAL(fp, NULL);

	while ((n = getline(&line, &len, fp)) != -1) {
		if (strncmp(IFACE_PREFIX, line, strlen(IFACE_PREFIX)) == 0) {
			sscanf(line, "I: Bus=%04hx Vendor=%04hx Product=%04hx Version=%04hx\n",
			       &bus, &vid, &pid, &ver);
		}

		if ((vid == vendor_id) && (pid == product_id) &&
		    (strncmp(HANDLER_PREFIX, line, strlen(IFACE_PREFIX)) == 0) &&
		    strstr(line, SYSRQ_EVENT)) {
			event = strtok(strstr(line, EVENT), " ");
			event_path = mem_printf("/dev/input/%s", event);
			break;
		}
	}

	fclose(fp);
	mem_free(line);
	return event_path;
}

void
pin_entry_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	pin_entry_timer_cb_data_t *timer_data = data;

	WARN("Pin entry failed: Timeout");
	int resp_fd = control_get_client_sock(timer_data->control);
	control_send_message(CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL, resp_fd);

	if (ioctl(input_fd, EVIOCGRAB, NULL) != 0) {
		WARN("Failed to release exclusive access to pin reader");
	}

	event_remove_io(input_event_io);
	event_io_free(input_event_io);

	input_key_index = 0;
	if (input_key) {
		memset(input_key, 0x0, strlen(input_key));
		mem_free(input_key);
	}
	event_remove_timer(timer);
	event_timer_free(timer);
	timer = NULL;
	close(input_fd);

	input_pin_entry_active = false;
}

void
input_clean_pin_entry(void)
{
	if (!input_pin_entry_active) {
		return;
	}

	WARN("The pin entry was aborted by the user");

	if (ioctl(input_fd, EVIOCGRAB, NULL) != 0) {
		WARN("Failed to release exclusive access to pin reader");
	}

	event_remove_io(input_event_io);
	event_io_free(input_event_io);

	input_key_index = 0;
	if (input_key) {
		memset(input_key, 0x0, strlen(input_key));
		mem_free(input_key);
	}
	event_remove_timer(input_timer);
	event_timer_free(input_timer);
	input_timer = NULL;
	close(input_fd);

	input_pin_entry_active = false;
}

static void
input_cb_request_pin_start_container(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	char c;
	char *tmp_key = NULL;
	container_start_cb_data_t *cb_data = data;

	IF_TRUE_GOTO(events & EVENT_IO_EXCEPT, exit_fail);

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	if (!cb_data->control || !cb_data->container) {
		WARN("Invalid parameters for container start callback");
		goto exit_fail;
	}

	struct input_event keyboard_event;
	TRACE("Reading pin from pin reader");
	while (read(fd, &keyboard_event, sizeof(keyboard_event)) > 0) {
		if ((keyboard_event.type != 0x1) || (keyboard_event.value != 0x1)) {
			continue;
		}

		switch (keyboard_event.code) {
		case KEY_BACKSPACE:
			// Backspace was pressed, remove last entered digit
			if (input_key_index > 0) {
				input_key_index--;
			}
			break;

		case KEY_ENTER:
		case KEY_KPENTER:
			// Enter was pressed, add trailing zero to pin and start container with pin
			input_key_index++;
			tmp_key = (char *)mem_realloc(input_key, input_key_index * sizeof(char));
			IF_NULL_GOTO(tmp_key, exit_fail);
			input_key = tmp_key;
			input_key[input_key_index - 1] = '\0';

			DEBUG("Starting container %s with smartcard from callback",
			      container_get_name(cb_data->container));
			if (cmld_container_start_with_smartcard(
				    cb_data->control, cb_data->container, input_key) != 0) {
				// the container start function will send a control message
				// so we do not need to go to exit fail and send a message here
				ERROR("Failed to start container %s",
				      container_get_name(cb_data->container));
			}
			goto exit;

		case KEY_ESC:
			// Escape was pressed, abort
			WARN("The pin entry was aborted by the user (ESC)");
			goto exit_fail;

		default:
			// Another key was pressed, check if pressed key is a digit and store it
			if (input_event_code_to_ascii_num(keyboard_event.code, &c) == 0) {
				input_key_index++;
				if (input_key_index > MAX_PIN_LEN) {
					ERROR("Pin exceeds maximum pin length of %d", MAX_PIN_LEN);
					goto exit_fail;
				}
				tmp_key = (char *)mem_realloc(input_key,
							      input_key_index * sizeof(char));
				IF_NULL_GOTO(tmp_key, exit_fail);
				input_key = tmp_key;
				input_key[input_key_index - 1] = c;
			}
		}
	}

	// Pin entry is not yet finished, just return to wait for more keystrokes
	return;

exit_fail:
	control_send_message(CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL,
			     control_get_client_sock(cb_data->control));

exit:
	TRACE("Remove container pin entry timer for %s", container_get_name(cb_data->container));
	event_remove_timer(input_timer);
	event_timer_free(input_timer);
	input_timer = NULL;

	if (ioctl(fd, EVIOCGRAB, NULL) != 0) {
		WARN("Failed to release exclusive access to pin reader");
	}
	event_remove_io(io);
	event_io_free(io);
	close(fd);

	mem_free(cb_data);
	if (input_key) {
		memset(input_key, 0x0, input_key_index);
		mem_free(input_key);
	}
	input_key_index = 0;
	input_pin_entry_active = false;
}

int
input_register_container_start_cb(control_t *control, container_t *container)
{
	char *input_file = NULL;

	TRACE("Searching for USB pin reader for interactive pin entry");

	// Iterate through usb-dev list and look for USB_PIN_ENTRY device
	uevent_usbdev_t *usbdev_pinreader = NULL;
	for (list_t *l = container_get_usbdev_list(container); l; l = l->next) {
		uevent_usbdev_t *usbdev = (uevent_usbdev_t *)l->data;
		if (uevent_usbdev_get_type(usbdev) == UEVENT_USBDEV_TYPE_PIN_ENTRY) {
			usbdev_pinreader = usbdev;
			break;
		}
	}
	IF_FALSE_GOTO(usbdev_pinreader, err);

	TRACE("Found USB pin reader. Device Serial: %s. Vendor:Product: %x:%x",
	      uevent_usbdev_get_i_serial(usbdev_pinreader),
	      uevent_usbdev_get_id_vendor(usbdev_pinreader),
	      uevent_usbdev_get_id_product(usbdev_pinreader));

	input_file = input_get_usb_input_event_file(uevent_usbdev_get_id_vendor(usbdev_pinreader),
						    uevent_usbdev_get_id_product(usbdev_pinreader));
	IF_FALSE_GOTO(input_file, err);

	TRACE("Found USB pin reader input file: %s", input_file);

	input_fd = open(input_file, O_RDONLY | O_NONBLOCK);
	IF_TRUE_GOTO(input_fd == -1, err);

	if (ioctl(input_fd, EVIOCGRAB, (void *)1) != 0) {
		WARN("Failed to get exclusive access to pin reader");
		close(input_fd);
		goto err;
	}

	// Read in pin in asynchronous callback
	container_start_cb_data_t *cb_data = mem_new0(container_start_cb_data_t, 1);
	cb_data->control = control;
	cb_data->container = container;
	input_event_io = event_io_new(input_fd, EVENT_IO_READ | EVENT_IO_EXCEPT,
				      input_cb_request_pin_start_container, cb_data);

	// Start pin entry timeout timer
	pin_entry_timer_cb_data_t *timer_data = mem_new0(pin_entry_timer_cb_data_t, 1);
	timer_data->control = control;
	input_timer = event_timer_new(PIN_ENTRY_TIMEOUT_MS, 1, &pin_entry_timeout_cb, timer_data);
	event_add_timer(input_timer);

	TRACE("Registering callback for pin entry");
	event_add_io(input_event_io);
	mem_free(input_file);

	input_pin_entry_active = true;

	return 0;

err:
	mem_free(input_file);
	return -1;
}
