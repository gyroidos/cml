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

#include "tpm2d.h"

#include "control.h"
#include "device/fraunhofer/common/cml/tpm2d/device.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/sock.h"
#include "common/protobuf.h"

#include <signal.h>

#define TPM2D_SOCK_PATH TPM2D_BASE_DIR "/communication"
#define TPM2D_CONTROL_SOCKET TPM2D_SOCK_PATH "/control.sock"

static tpm2d_control_t *tpm2d_control_cmld = NULL;
static logf_handler_t *tpm2d_logfile_handler = NULL;

static uint32_t tpm2d_pps_key_handle = 0;
static uint32_t tpm2d_as_key_handle = 0;

static void
tpm2d_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	INFO("Logfile must be closed and a new file opened");
	logf_unregister(tpm2d_logfile_handler);
	tpm2d_logfile_handler = logf_register(&logf_file_write, logf_file_new("/data/logs/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);
}

static void
tpm2d_init(void)
{
	int ret = 0;
	char *token_dir = mem_printf("%s/%s", TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);

	if (!file_is_dir(TPM2D_BASE_DIR)) {
		if (mkdir(TPM2D_BASE_DIR, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm2d's working dir: %s", TPM2D_BASE_DIR);
		}
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_powerup()))
		FATAL("powerup failed with error code: %08x", ret);

	if (TPM_RC_SUCCESS != (ret = tpm2_startup(TPM_SU_CLEAR)))
		FATAL("startup failed with error code: %08x", ret);

	if (TPM_RC_SUCCESS != (ret = tpm2_selftest()))
		FATAL("selftest failed with error code: %08x", ret);

	if (!file_is_dir(token_dir)) {
		if (mkdir(token_dir, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm tokens dir: %s", token_dir);
		}
		// create platform key
		if (TPM_RC_SUCCESS != (ret = tpm2_createprimary_asym(TPM_RH_PLATFORM, TPM2D_KEY_TYPE_STORAGE,
				NULL, TPM2D_PLATFORM_STORAGE_KEY_PW, TPM2D_PPS_PUB_FILE, &tpm2d_pps_key_handle))) {
			FATAL("Failed to create platform key with error code: %08x", ret);
		}
		INFO("Created PPS key with handle %08x", tpm2d_pps_key_handle);

		if (TPM_RC_SUCCESS != (ret = tpm2_evictcontrol(TPM_RH_PLATFORM, NULL, tpm2d_pps_key_handle,
							TPM2D_PLATFORM_STORAGE_KEY_PERSIST_HANDLE))) {
			FATAL("Failed to persist platform key with error code: %08x", ret);
		}
		INFO("Persisted PPS key with handle %08x -> %08x", tpm2d_pps_key_handle,
								TPM2D_PLATFORM_STORAGE_KEY_PERSIST_HANDLE);

		if (TPM_RC_SUCCESS != (ret = tpm2_create_asym(tpm2d_pps_key_handle, TPM2D_KEY_TYPE_SIGNING_U,
					(TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT),
					TPM2D_PLATFORM_STORAGE_KEY_PW, TPM2D_ATTESTATION_KEY_PW,
					TPM2D_ATTESTATION_PRIV_FILE, TPM2D_ATTESTATION_PUB_FILE))) {
			dir_delete_folder(TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
			FATAL("Failed to create attestation key with error code: %08x", ret);
		}
		INFO("Created signing key for attestation.");
	}

	// load attestation key
	if (TPM_RC_SUCCESS != (ret = tpm2_load(TPM2D_PLATFORM_STORAGE_KEY_PERSIST_HANDLE,
					TPM2D_PLATFORM_STORAGE_KEY_PW, TPM2D_ATTESTATION_PRIV_FILE,
					TPM2D_ATTESTATION_PUB_FILE, &tpm2d_as_key_handle))) {
		FATAL("Failed to load attestation key with error code: %08x", ret);
	}
	INFO("Loaded signing key for attestation.");

	mem_free(token_dir);
	INFO("Sucessfully initialized TPM2.0");
}

static void
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	FATAL("Received SIGINT...");
}

int
main(UNUSED int argc, char **argv) {

	if (file_exists("/dev/log/main"))
		logf_register(&logf_android_write, logf_android_new(argv[0]));
	else
		logf_register(&logf_klog_write, logf_klog_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	tpm2d_logfile_handler = logf_register(&logf_file_write, logf_file_new("/data/logs/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);

	INFO("Starting tpm2d ...");

	event_init();

	event_signal_t *sig = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig);

	event_timer_t *logfile_timer = event_timer_new(HOURS_TO_MILLISECONDS(24), EVENT_TIMER_REPEAT_FOREVER, tpm2d_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	tpm2d_init();

	if (mkdir(TPM2D_SOCK_PATH, 0700) < 0 && errno != EEXIST)
                FATAL_ERRNO("Could not mkdir communictaions dir: %s", TPM2D_SOCK_PATH);

	tpm2d_control_cmld = tpm2d_control_new(TPM2D_CONTROL_SOCKET, tpm2d_as_key_handle);
	if (!tpm2d_control_cmld) {
		FATAL("Could not init tpm2d_control socket");
	}

	INFO("created control socket.");

	event_loop();

	return 0;
}
