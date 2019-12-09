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

/* @file logf.test.c
 *
 * (Dummy) Unit Test for logf.c
 * Since there is not much to be inspected with ASSERTs,
 * applicable functions are only triggered.
 */
#include <stdio.h>
#include <errno.h>

#include "logf.h"
#include "macro.h"

/*
 * Triggers logging functions to be tested, which are
 * given due to logf.h and macro.h
 */
int
main(int argc, char **argv)
{
	/*
	logf_register(&logf_file_write, stdout);
	logf_register(&logf_file_write, stderr);
	logf_register(&logf_file_write, fopen("log.cmld", "a"));
	logf_register(&logf_file_write, logf_file_new("log.cmld"));
	logf_register(&logf_syslog_write, logf_syslog_new("trustme-cmld"));
	logf_register(&logf_android_write, logf_android_new("trustme-cmld"));
	logf_register(&logf_klog_write, logf_klog_new("trustme-cmld"));

	logf_debug("debug test");
	logf_info("info test");
	logf_warn("warn test");
	logf_error("error test");

	logf_debug_errno("debug errno test");
	errno = 1;
	logf_info_errno("info errno test");
	errno = 2;
	logf_warn_errno("warn errno test");
	errno = 3;
	logf_error_errno("error errno test");

	return 0;
*/
	logf_register(&logf_test_write, stdout);
	DEBUG("Unit Test: logf.test.c");

	DEBUG("Test logf_register and logD");
	logf_register(&logf_test_write, stderr);

	DEBUG("Test logf_debug");
	logf_debug("debug test");

	DEBUG("Test logf_info");
	logf_info("info test");

	DEBUG("Test logf_warn");
	logf_warn("warn test");

	DEBUG("Test logf_error");
	logf_error("error test");

	DEBUG("Test logf_debug_errno");
	logf_debug_errno("debug errno test");
	errno = 1;

	DEBUG("Test logf_info_errno");
	logf_info_errno("info errno test");
	errno = 2;

	DEBUG("Test logf_warn_errno");
	logf_warn_errno("warn errno test");
	errno = 3;

	DEBUG("Test logf_error_errno");
	logf_error_errno("error errno test");

	return 0;
}
