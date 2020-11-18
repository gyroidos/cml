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

/**
 * @file input.h
 *
 * This module implements functionality to search for an external usb
 * input pin reader and to read in pins from that device
 */

#ifndef DAEMON_INPUT_H_
#define DAEMON_INPUT_H_

/**
 * Parses /proc/bus/input/devices to find the /dev/input/eventx input file for the 
 * usb devices specified by vendor_id and product_id
 * 
 * @param vendor_id     The vendor ID of the usb device to get the input file for
 * @param product_id    The product ID of the usb device to get the input file for
 * @return              The /dev/input/eventx file of the usb device
 */
char *
input_get_usb_input_event_file(uint16_t vendor_id, uint16_t product_id);

/**
 * Opens the /dev/input/eventx file to enable reading the keystrokes of the usb device
 * 
 * @param char* input_file  The /dev/input/eventx file to be opened
 * return                   The file descriptor or -1 if an error occurred
 */
int
input_open_usb_input_event_file(char *input_file);

/**
 * Read a pin from an external usb pin reader device fd points to
 * 
 * @param fd    The file descriptor that represents the input file
 * @return      The read in pin
 */
char *
input_read_usb_input_event_file_pin(int fd);

/**
 * Closes the usb input file
 * 
 * @param int fd    The file descriptor of the file to be closed
 * @return          0 on success, otherwise -1
 */
int
close_usb_input_event_file(int fd);

#endif // DAEMON_INPUT_H_