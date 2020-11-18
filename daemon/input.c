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

#include "common/macro.h"
#include "common/mem.h"
#include "container.h"

// The following defines represent parts of the syntax of /proc/bus/input/devices
#define IFACE_PREFIX "I:"
#define HANDLER_PREFIX "H: Handlers="
#define EVENT "event"
#define SYSRQ_EVENT "sysrq"

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

char *
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

int
input_open_usb_input_event_file(char *input_file)
{
	int fd = open(input_file, O_RDONLY | O_NONBLOCK);
	if (fd == -1) {
		WARN("Failed to open usb input event file for pin reader");
	}
	return fd;
}

char *
input_read_usb_input_event_file_pin(int fd)
{
	char *key = NULL;
	char *tmp_key = NULL;

	int ret = ioctl(fd, EVIOCGRAB, (void *)1);
	if (ret != 0) {
		WARN("Failed to get exclusive access to pin reader");
		return key;
	}
	struct input_event keyboard_event;

	TRACE("Reading pin from pin reader");
	int index = 0;
	while (1) {
		if (read(fd, &keyboard_event, sizeof(keyboard_event)) != -1) {
			if ((keyboard_event.type == 0x1) &&
			    (keyboard_event.code == KEY_BACKSPACE) &&
			    (keyboard_event.value == 0x1)) {
				// Backspace was pressed, remove last entered digit
				if (index > 0) {
					index--;
				}
			} else if ((keyboard_event.type == 0x1) &&
				   ((keyboard_event.code == KEY_ENTER) ||
				    (keyboard_event.code == KEY_KPENTER)) &&
				   (keyboard_event.value == 0x1)) {
				// Enter was pressed, finish
				break;
			} else if ((keyboard_event.type == 0x1) && (keyboard_event.value == 0x1)) {
				// Another key was pressed..
				char c;
				// ..Check if pressed key is a digit and store it
				if (input_event_code_to_ascii_num(keyboard_event.code, &c) == 0) {
					index++;
					tmp_key = (char *)mem_realloc(key, index * sizeof(char));
					if (tmp_key) {
						key = tmp_key;
						key[index - 1] = c;
					} else {
						WARN("Failed to allocate memory for pin");
						free(key);
						return key;
					}
				}
			}
		}
	}

	ret = ioctl(fd, EVIOCGRAB, NULL);
	if (ret != 0) {
		WARN("Failed to release exclusive access to pin reader");
	}

	return key;
}

int
close_usb_input_event_file(int fd)
{
	return close(fd);
}