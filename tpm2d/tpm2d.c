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
#include "nvmcrypt.h"

#include "control.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/sock.h"
#include "common/protobuf.h"

#include <signal.h>
#include <getopt.h>

#define TPM2D_SOCK_PATH TPM2D_BASE_DIR "/communication"
#define TPM2D_CONTROL_SOCKET TPM2D_SOCK_PATH "/control.sock"

static bool use_simulator = false;

static tpm2d_control_t *tpm2d_control_cmld = NULL;
static logf_handler_t *tpm2d_logfile_handler = NULL;

static uint32_t tpm2d_salt_key_handle = 0;

#ifndef TPM2D_NVMCRYPT_ONLY
static uint32_t tpm2d_as_key_handle = 0;
#if TPM2D_KEY_HIERARCHY != TPM_RH_ENDORSEMENT

static uint32_t tpm2d_ps_key_handle = 0;
static uint32_t persist_ps_handle = 0;
#endif
#endif

static void
tpm2d_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	INFO("Logfile must be closed and a new file opened");
	logf_unregister(tpm2d_logfile_handler);
	tpm2d_logfile_handler = logf_register(&logf_file_write, logf_file_new("/data/logs/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);
}

static void
tpm2d_setup_salt_key(void)
{
	// create primary key in NULL hierarchy wwhcih is used for session encryption
	int ret;
	if (TPM_RC_SUCCESS != (ret = tpm2_createprimary_asym(TPM_RH_NULL, TPM2D_KEY_TYPE_STORAGE_R,
			NULL, NULL, NULL, &tpm2d_salt_key_handle))) {
		FATAL("Failed to create primary key for session encryption with error code: %08x", ret);
	}
}

TPMI_DH_OBJECT
tpm2d_get_salt_key_handle(void)
{
	return tpm2d_salt_key_handle;
}

#ifndef TPM2D_NVMCRYPT_ONLY
TPMI_DH_OBJECT
tpm2d_get_as_key_handle(void)
{
	return tpm2d_as_key_handle;
}

#if TPM2D_KEY_HIERARCHY == TPM_RH_ENDORSEMENT
static void
tpm2d_setup_keys(void)
{
	int ret = 0;
	// create ek
	if (TPM_RC_SUCCESS != (ret = tpm2_createprimary_asym(TPM2D_KEY_HIERARCHY,
			TPM2D_KEY_TYPE_SIGNING_EK, NULL, TPM2D_ATTESTATION_KEY_PW, NULL,
			&tpm2d_as_key_handle))) {
		FATAL("Failed to create primary endorsement key with error code: %08x", ret);
	}
	INFO("Created EK with handle %08x", tpm2d_as_key_handle);
}
#else
static void
tpm2d_setup_keys(void)
{
	int ret = 0;
	char *token_dir = mem_printf("%s/%s", TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);

	if (TPM2D_KEY_HIERARCHY == TPM_RH_OWNER) {
		persist_ps_handle = TPM2D_OWNER_STORAGE_KEY_PERSIST_HANDLE;
	} else {
		persist_ps_handle = TPM2D_PLATFORM_STORAGE_KEY_PERSIST_HANDLE;
	}
	if (!file_is_dir(token_dir)) {
		if (mkdir(token_dir, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm tokens dir: %s", token_dir);
		}
		// create primary key
		if (TPM_RC_SUCCESS != (ret = tpm2_createprimary_asym(TPM2D_KEY_HIERARCHY, TPM2D_KEY_TYPE_STORAGE_R,
				NULL, TPM2D_PRIMARY_STORAGE_KEY_PW, TPM2D_PS_PUB_FILE, &tpm2d_ps_key_handle))) {
			FATAL("Failed to create primary storage key with error code: %08x", ret);
		}
		INFO("Created PS key with handle %08x", tpm2d_ps_key_handle);

		if (TPM_RC_SUCCESS != (ret = tpm2_evictcontrol(TPM2D_KEY_HIERARCHY, NULL,
							tpm2d_ps_key_handle, persist_ps_handle))) {
			FATAL("Failed to persist platform key with error code: %08x", ret);
		}
		INFO("Persisted PS key with handle %08x -> %08x", tpm2d_ps_key_handle, persist_ps_handle);
		if (TPM_RC_SUCCESS != (ret = tpm2_flushcontext(tpm2d_ps_key_handle))) {
			ERROR("flushing transient object handle of platform key storage key");
		}

	}
	if (!file_exists(TPM2D_ATTESTATION_PRIV_FILE)) {
		if (TPM_RC_SUCCESS != (ret = tpm2_create_asym(persist_ps_handle, TPM2D_KEY_TYPE_SIGNING_U,
					(TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT),
					TPM2D_PRIMARY_STORAGE_KEY_PW, TPM2D_ATTESTATION_KEY_PW,
					TPM2D_ATTESTATION_PRIV_FILE, TPM2D_ATTESTATION_PUB_FILE))) {
			dir_delete_folder(TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
			FATAL("Failed to create attestation key with error code: %08x", ret);
		}
		INFO("Created signing key for attestation.");
	}

	// load attestation key
	if (TPM_RC_SUCCESS != (ret = tpm2_load(persist_ps_handle,
					TPM2D_PRIMARY_STORAGE_KEY_PW, TPM2D_ATTESTATION_PRIV_FILE,
					TPM2D_ATTESTATION_PUB_FILE, &tpm2d_as_key_handle))) {
		FATAL("Failed to load attestation key with error code: %08x", ret);
	}
	INFO("Loaded signing key for attestation.");
	mem_free(token_dir);
}
#endif /* ndef TPM2D_NVMCRYPT_ONLY */
#endif /* TPM2D_KEY_HIERARCHY == TPM_RH_ENDORSEMENT */

static void
tpm2d_init(void)
{
	int ret = 0;
	char *session_dir = mem_printf("%s/%s", TPM2D_BASE_DIR, TPM2D_SESSION_DIR);

	if (!file_is_dir(TPM2D_BASE_DIR)) {
		if (mkdir(TPM2D_BASE_DIR, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm2d's working dir: %s", TPM2D_BASE_DIR);
		}
	}

	// setup directory for session artefacts, generated by tss2
	if (mkdir(session_dir, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir data dir: %s", TPM2D_BASE_DIR"/session");
	if (setenv("TPM_DATA_DIR", TPM2D_BASE_DIR"/session", 1) < 0)
		FATAL_ERRNO("Could not set environment!");

	// if real hw tpm exists, setup environment
	if (file_exists("/dev/tpm0") && !use_simulator) {
		if (setenv("TPM_INTERFACE_TYPE", "dev", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
		if (setenv("TPM_DEVICE", "/dev/tpm0", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
	}

	tss2_init();

	// if no real hw tpm exists, powerup the simulator
	if (!file_exists("/dev/tpm0") || use_simulator) {
		// startup not needed for ibm simulator
		//if (TPM_RC_SUCCESS != (ret = tpm2_powerup()))
		//	FATAL("powerup failed with error code: %08x", ret);

		//// startup should be made by uefi/bios, thus also only for simulator
		if (TPM_RC_SUCCESS != (ret = tpm2_startup(TPM_SU_CLEAR)))
			FATAL("startup failed with error code: %08x", ret);
	}

	if (TPM_RC_SUCCESS != (ret = tpm2_selftest()))
		FATAL("selftest failed with error code: %08x", ret);

	// create salt key for session encryption
	tpm2d_setup_salt_key();

#ifndef TPM2D_NVMCRYPT_ONLY
	// initialize nvm_crypt_submodule
	nvmcrypt_init(true);

	tpm2d_setup_keys();
#else
	// initialize nvm_crypt_submodule
	nvmcrypt_init(false);
#endif

	mem_free(session_dir);
	INFO("Sucessfully initialized TPM2.0");
}

void
tpm2d_exit(void)
{
	INFO("Cleaning up tss2 and exit");
	if (tpm2d_salt_key_handle)
		tpm2_flushcontext(tpm2d_salt_key_handle);
#ifndef TPM2D_NVMCRYPT_ONLY
	if (tpm2d_as_key_handle)
		tpm2_flushcontext(tpm2d_as_key_handle);
#endif

	tss2_destroy();
	exit(0);
}

static void
main_sigint_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGINT...");
	tpm2d_exit();
}

static void
main_sigterm_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGTERM...");
	tpm2d_exit();
}

static void
print_usage(const char *cmd)
{
	printf("\n");
	printf("Usage: %s [-s] \n", cmd);
	printf("\n");
	printf("\t use -s option to connect to simulator, otherwise /dev/tpm0 ist used");
	printf("\n");
	exit(-1);
}

static const struct option global_options[] = {
	{"sim",  no_argument, 0, 's'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

int
main(UNUSED int argc, char **argv) {

	if (file_exists("/dev/log/main"))
		logf_register(&logf_android_write, logf_android_new(argv[0]));
	else
		logf_register(&logf_klog_write, logf_klog_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	for (int c, option_index = 0; -1 != (c = getopt_long(argc, argv, ":sh",
					global_options, &option_index)); ) {
		switch (c) {
		case 's':
			use_simulator = true;
			break;
		default: // includes cases 'h' and '?'
			print_usage(argv[0]);
		}
	}

	tpm2d_logfile_handler = logf_register(&logf_file_write, logf_file_new("/data/logs/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);

	INFO("Starting tpm2d ...");

	event_init();

	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig_int);
	event_signal_t *sig_term = event_signal_new(SIGTERM, &main_sigterm_cb, NULL);
	event_add_signal(sig_term);

	event_timer_t *logfile_timer = event_timer_new(HOURS_TO_MILLISECONDS(24), EVENT_TIMER_REPEAT_FOREVER, tpm2d_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	tpm2d_init();

	if (mkdir(TPM2D_SOCK_PATH, 0700) < 0 && errno != EEXIST)
                FATAL_ERRNO("Could not mkdir communictaions dir: %s", TPM2D_SOCK_PATH);

	tpm2d_control_cmld = tpm2d_control_new(TPM2D_CONTROL_SOCKET);
	if (!tpm2d_control_cmld) {
		FATAL("Could not init tpm2d_control socket");
	}

	INFO("created control socket.");

	event_loop();

	tss2_destroy();

	return 0;
}
