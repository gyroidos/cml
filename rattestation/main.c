/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2019 Fraunhofer AISEC
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

#include "common/macro.h"
#include "common/mem.h"
#include "common/file.h"
#include "common/logf.h"
#include "common/event.h"

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>

#include "attestation.h"

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bio.h>
#include <openssl/x509_vfy.h>

#define LOGFILE_DIR "/data/logs"
#define LOGFILE_PATH LOGFILE_DIR "/rattestation"

static logf_handler_t *ipagent_logfile_handler = NULL;
static logf_handler_t *ipagent_logfile_handler_stdout = NULL;

char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	IF_TRUE_RETVAL(0 > length, NULL);

	size_t len = MUL_WITH_OVERFLOW_CHECK(length, (size_t)2);
	len = MUL_WITH_OVERFLOW_CHECK(len, sizeof(char));
	len = ADD_WITH_OVERFLOW_CHECK(len, 1);
	char *hex = mem_alloc0(len);

	for (int i = 0; i < length; ++i) {
		// remember snprintf additionally writs a '0' byte
		snprintf(hex + i * 2, 3, "%.2x", bin[i]);
	}

	return hex;
}

static void
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGINT...");
	exit(0);
}

static void
main_return_result_and_exit(bool validated)
{
	TRACE("Exit handler called...");
	exit(validated ? 0 : -1);
}

int
main(int argc, char **argv)
{
	ipagent_logfile_handler = logf_register(&logf_file_write, logf_file_new(LOGFILE_PATH));
	ipagent_logfile_handler_stdout = logf_register(&logf_file_write, stdout);

	logf_handler_set_prio(ipagent_logfile_handler, LOGF_PRIO_TRACE);
	logf_handler_set_prio(ipagent_logfile_handler_stdout, LOGF_PRIO_TRACE);

	char *rhost = (argc < 2) ? "127.0.0.1" : argv[1];
	char *config_file = (argc < 3) ? "rattestation.conf" : argv[2];

	event_init();

	/* register keyboard sigint */
	event_signal_t *sig = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig);

	/*
	 * do attestation and register the main_retrun_result_and_exit handler
	 * as callback when the response has been validated
	 */
	if (-1 == attestation_do_request(rhost, config_file, main_return_result_and_exit)) {
		ERROR("Connection to remote host %s failed!", rhost);
		main_return_result_and_exit(false);
	}

	event_loop();

	return 0;
}
