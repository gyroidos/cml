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
#include "tpm2d_shared.h"
#include "nvmcrypt.h"

#include "control.h"
#include "rcontrol.h"

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

// clang-format off
#define TPM2D_CONTROL_SOCKET SOCK_PATH(tpm2d-control)
// clang-format on
#define TPM2D_RCONTROL_PORT 9505

static bool use_simulator = false;
static bool no_setup_keys = false;

static tpm2d_control_t *tpm2d_control_cmld = NULL;
static tpm2d_rcontrol_t *tpm2d_rcontrol_attest = NULL;
static logf_handler_t *tpm2d_logfile_handler = NULL;

static uint32_t tpm2d_salt_key_handle = TPM_RH_NULL;

#ifndef TPM2D_NVMCRYPT_ONLY
// transient (tr) attestation key (as) handle
static uint32_t tpm2d_as_key_handle_tr = TPM_RH_NULL;
// transient (tr) parent handle (pt) for attestation key (as)
static uint32_t tpm2d_as_key_handle_pt_tr = TPM_RH_NULL;
// persistent (ps) parent handle (pt) for attestation key (as)
static uint32_t tpm2d_as_key_handle_pt_ps = TPM2D_STORAGE_KEY_PERSIST_HANDLE;
// auth for attestation
static char *tpm2d_as_key_pwd_pt = TPM2D_PRIMARY_STORAGE_KEY_PW;
#endif

static void
tpm2d_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	INFO("Logfile must be closed and a new file opened");
	logf_unregister(tpm2d_logfile_handler);
	tpm2d_logfile_handler =
		logf_register(&logf_file_write, logf_file_new(LOGFILE_DIR "/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);
}

static void
tpm2d_setup_salt_key(void)
{
	// create primary key in NULL hierarchy wwhcih is used for session encryption
	int ret;
	if (TPM_RC_SUCCESS !=
	    (ret = tpm2_createprimary_asym(TPM_RH_NULL, TPM2D_KEY_TYPE_STORAGE_R, NULL, NULL, NULL,
					   &tpm2d_salt_key_handle))) {
		FATAL("Failed to create primary key for session encryption with error code: %08x",
		      ret);
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
	if (TPM_RH_NULL == tpm2d_as_key_handle_tr) {
		int ret;
		// load attestation key
		if (TPM_RC_SUCCESS !=
		    (ret = tpm2_load(tpm2d_as_key_handle_pt_ps, tpm2d_as_key_pwd_pt,
				     TPM2D_ATT_PRIV_FILE, TPM2D_ATT_PUB_FILE,
				     &tpm2d_as_key_handle_tr))) {
			ERROR("Failed to load attestation key with error code: %08x", ret);
			return TPM_RH_NULL;
		} else {
			INFO("Loaded signing key for attestation with handle %08x from parent handle %08x.",
			     tpm2d_as_key_handle_tr, tpm2d_as_key_handle_pt_ps);
		}
	}
	return tpm2d_as_key_handle_tr;
}

void
tpm2d_flush_as_key_handle(void)
{
	if (tpm2d_as_key_handle_tr != TPM_RH_NULL) {
		tpm2_flushcontext(tpm2d_as_key_handle_tr);
		tpm2d_as_key_handle_tr = TPM_RH_NULL;
	}
}

static void
tpm2d_setup_keys(void)
{
	int ret = 0;
	char *token_dir = mem_printf("%s/%s", TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
	bool handle_possibly_uninit = true;

	if (file_exists(TPM2D_ATT_PRIV_FILE)) {
		INFO("Signing key for attestation found in %s, nothing to be done.", token_dir);
		mem_free(token_dir);
		return;
	}

	if (!file_is_dir(token_dir)) {
		if (mkdir(token_dir, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm tokens dir: %s", token_dir);
		}
	}
retry:
	// create attestation key based on a persistent parent key
	if (TPM_RC_SUCCESS !=
	    (ret = tpm2_create_asym(tpm2d_as_key_handle_pt_ps, TPM2D_KEY_TYPE_STORAGE_U,
				    (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT),
				    tpm2d_as_key_pwd_pt, TPM2D_ATT_KEY_PW, TPM2D_ATT_PRIV_FILE,
				    TPM2D_ATT_PUB_FILE, TPM2D_ATT_TSS_FILE))) {
		if (handle_possibly_uninit) {
			INFO("Attestation parent possibly unitialized, trying to create and persist a primary key");
			// create primary key
			if (TPM_RC_SUCCESS !=
			    (ret = tpm2_createprimary_asym(
				     TPM2D_KEY_HIERARCHY, TPM2D_KEY_TYPE_STORAGE_R, NULL,
				     tpm2d_as_key_pwd_pt, TPM2D_ATT_PARENT_PUB_FILE,
				     &tpm2d_as_key_handle_pt_tr))) {
				dir_delete_folder(TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
				FATAL("Failed to create att primary key with error code: %08x",
				      ret);
			}
			INFO("Created att primary key with handle %08x", tpm2d_as_key_handle_pt_tr);

			if (TPM_RC_SUCCESS !=
			    (ret = tpm2_evictcontrol(TPM2D_KEY_HIERARCHY, NULL,
						     tpm2d_as_key_handle_pt_tr,
						     tpm2d_as_key_handle_pt_ps))) {
				dir_delete_folder(TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
				FATAL("Failed to persist att primary key with error code: %08x",
				      ret);
			}
			INFO("Persisted att primary key with handle %08x -> %08x",
			     tpm2d_as_key_handle_pt_tr, tpm2d_as_key_handle_pt_ps);
			handle_possibly_uninit = false;

			if (TPM_RC_SUCCESS !=
			    (ret = tpm2_flushcontext(tpm2d_as_key_handle_pt_tr))) {
				ERROR("Failed to flush transient object handle of att primary key");
			}
			goto retry;
		} else {
			dir_delete_folder(TPM2D_BASE_DIR, TPM2D_TOKEN_DIR);
			FATAL("Failed to create attestation key with error code: %08x", ret);
		}
	} else {
		INFO("Created signing key for attestation in %s, not loading need to wait for provsg ...",
		     token_dir);
	}
	mem_free(token_dir);
}
#endif /* ifndef TPM2D_NVMCRYPT_ONLY */

static void
tpm2d_init(void)
{
	int ret = 0;
	char *session_dir = mem_printf("%s/%s", TPM2D_BASE_DIR, TPM2D_SESSION_DIR);

	if (!file_is_dir(TPM2D_BASE_DIR)) {
		if (dir_mkdir_p(TPM2D_BASE_DIR, 0700) < 0) {
			FATAL_ERRNO("Could not mkdir tpm2d's working dir: %s", TPM2D_BASE_DIR);
		}
	}

	// setup directory for session artefacts, generated by tss2
	if (mkdir(session_dir, 0700) < 0 && errno != EEXIST)
		FATAL_ERRNO("Could not mkdir data dir: %s", TPM2D_BASE_DIR "/session");
	if (setenv("TPM_DATA_DIR", TPM2D_BASE_DIR "/session", 1) < 0)
		FATAL_ERRNO("Could not set environment!");

	// if real hw tpm exists, setup environment
	if (file_exists("/dev/tpm0") && !use_simulator) {
		if (setenv("TPM_INTERFACE_TYPE", "dev", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
		if (setenv("TPM_DEVICE", "/dev/tpm0", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
	} else {
		if (setenv("TPM_INTERFACE_TYPE", "socsim", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
		if (setenv("TPM_SERVER_TYPE", "raw", 1) < 0)
			FATAL_ERRNO("Could not set environment!");
	}

	tss2_init();

	if (TPM_RC_SUCCESS != (ret = tpm2_selftest()))
		FATAL("selftest failed with error code: %08x", ret);

	// create salt key for session encryption
	tpm2d_setup_salt_key();

#ifndef TPM2D_NVMCRYPT_ONLY
	// initialize nvm_crypt_submodule
	nvmcrypt_init(true);
	if (!no_setup_keys)
		tpm2d_setup_keys();
#else
	// initialize nvm_crypt_submodule
	nvmcrypt_init(false);
#endif

	mem_free(session_dir);
	INFO("Sucessfully initialized TPM2.0");
	tss2_destroy();
}

void
tpm2d_exit(void)
{
	INFO("Cleaning up tss2 and exit");
	// When called tss2 library context may not be
	tss2_init();
	if (tpm2d_salt_key_handle != TPM_RH_NULL)
		tpm2_flushcontext(tpm2d_salt_key_handle);
#ifndef TPM2D_NVMCRYPT_ONLY
	if (tpm2d_as_key_handle_tr != TPM_RH_NULL)
		tpm2_flushcontext(tpm2d_as_key_handle_tr);
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
	printf("\t use -n option to disable setup keys for attestation");
	printf("\n");
	exit(-1);
}

static const struct option global_options[] = { { "sim", no_argument, 0, 's' },
						{ "nokeys", no_argument, 0, 'n' },
						{ "help", no_argument, 0, 'h' },
						{ 0, 0, 0, 0 } };

int
main(UNUSED int argc, char **argv)
{
	if (file_exists("/dev/log/main"))
		logf_register(&logf_android_write, logf_android_new(argv[0]));
	else
		logf_register(&logf_klog_write, logf_klog_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	for (int c, option_index = 0;
	     - 1 != (c = getopt_long(argc, argv, ":snh", global_options, &option_index));) {
		switch (c) {
		case 's':
			use_simulator = true;
			break;
		case 'n':
			no_setup_keys = true;
			break;
		default: // includes cases 'h' and '?'
			print_usage(argv[0]);
		}
	}

	tpm2d_logfile_handler =
		logf_register(&logf_file_write, logf_file_new(LOGFILE_DIR "/cml-tpm2d"));
	logf_handler_set_prio(tpm2d_logfile_handler, LOGF_PRIO_WARN);

	INFO("Starting tpm2d ...");

	event_init();

	event_signal_t *sig_int = event_signal_new(SIGINT, &main_sigint_cb, NULL);
	event_add_signal(sig_int);
	event_signal_t *sig_term = event_signal_new(SIGTERM, &main_sigterm_cb, NULL);
	event_add_signal(sig_term);

	event_timer_t *logfile_timer =
		event_timer_new(HOURS_TO_MILLISECONDS(24), EVENT_TIMER_REPEAT_FOREVER,
				tpm2d_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	tpm2d_init();

	TRACE("Try to create directory for socket if not existing");
	if (dir_mkdir_p(CMLD_SOCKET_DIR, 0755) < 0) {
		FATAL("Could not create directory for tpm2d_control socket");
	}

	tpm2d_control_cmld = tpm2d_control_new(TPM2D_CONTROL_SOCKET);
	if (!tpm2d_control_cmld) {
		FATAL("Could not init tpm2d_control socket");
	}
	if (!no_setup_keys) {
		tpm2d_rcontrol_attest = tpm2d_rcontrol_new("0.0.0.0", TPM2D_RCONTROL_PORT);
		if (!tpm2d_rcontrol_attest) {
			FATAL("Could not init tpm2d_rcontrol socket");
		}
	}

	INFO("created control socket.");

	event_loop();

	tss2_destroy();

	return 0;
}
