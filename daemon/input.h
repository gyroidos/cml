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
 * Register callback to interactively read input from USB pin entry device
 * and exeute a callback to handle that input afterwards. The userinput of
 * the callback will contain the input done by the user or NULL in case of
 * an error.
 *
 * @param vendor_id vendor id of the usb device used for input
 * @param product_id product id of the usb device used for input
 * @param exec_cb callback called after input is handled
 * 		  (ENTER pressed, aborted or timed out)
 * @param exec_cb_data generic data pointer for data used in exec_cb
 * @return 0 on success, -1 on error
 */
int
input_read_exec(uint16_t vendor_id, uint16_t product_id,
		void (*exec_cb)(char *userinput, void *exec_cb_data), void *exec_cb_data);

void
input_clean_pin_entry(void);

#endif // DAEMON_INPUT_H_
