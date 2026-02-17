/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include "scd.h"
#include "tpm2d_shared.h"

#include "control.h"
#include "device.pb-c.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/event.h"
#include "common/logf.h"
#include "common/sock.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/uuid.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"
#include "common/list.h"
#include "common/ssl_util.h"
#include "common/str.h"
#include "token.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

// clang-format off
#ifndef SCD_CONTROL_SOCKET
#define SCD_CONTROL_SOCKET SOCK_PATH(scd_control)
#endif // SCD_CONTROL_SOCKET
// clang-format on

// Do not edit! This path is also configured in cmld.c
#define DEVICE_ID_CONF SCD_TOKEN_DIR "/device_id.conf"

#define DMI_PRODUCT_SERIAL "/sys/devices/virtual/dmi/id/product_serial"
#define DMI_PRODUCT_NAME "/sys/devices/virtual/dmi/id/product_name"
#define DMI_PRODUCT_SERIAL_LEN 40
#define DMI_PRODUCT_NAME_LEN 20

#define TOKEN_DEFAULT_EXT ".p12"

#ifndef PKCS11_MODULE_DIR
#define PKCS11_MODULE_DIR DEFAULT_BASE_PATH "/pkcs11/"
#endif // PKCS11_MODULE_DIR

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

static list_t *scd_token_list = NULL;

static scd_control_t *scd_control_cmld = NULL;
static logf_handler_t *scd_logfile_handler = NULL;
static void *scd_logfile_p = NULL;

static void
scd_sigterm_cb(UNUSED int signum, UNUSED event_signal_t *sig, UNUSED void *data)
{
	INFO("Received SIGTERM..");
	if (scd_logfile_p) {
		logf_unregister(scd_logfile_handler);
		logf_file_close(scd_logfile_p);
	}
	exit(0);
}

bool
scd_in_provisioning_mode(void)
{
	return file_is_regular(PROVISIONING_MODE_FILE);
}

static void
provisioning_mode()
{
	INFO("Check for existence of device certificate");

	bool need_initialization = (!file_exists(DEVICE_CERT_FILE));
	bool use_tpm = false;
	char *dev_key_file = DEVICE_KEY_FILE;

	// if available, use tpm to create and store device key
	if (file_exists("/dev/tpm0") || file_exists("/dev/tpmrm0")) {
		// assumption: tpm2d is launched prior to scd, and creates a keypair on first boot
		if (!file_exists(TPM2D_ATT_TSS_FILE)) {
			WARN("TPM keypair not found, missing %s, TPM support disabled!",
			     TPM2D_ATT_TSS_FILE);
			use_tpm = false;
		} else {
			use_tpm = true;
			dev_key_file = TPM2D_ATT_TSS_FILE;
		}
	}

	if (need_initialization) {
		sleep(5);
	}

	// if no certificate exists, create a csr
	if (!file_exists(DEVICE_CERT_FILE)) {
		INFO("Device certificate not available. Switch to device provisioning mode");
		file_printf(PROVISIONING_MODE_FILE, "provisioning mode");

		if (ssl_init(use_tpm, TPM2D_PRIMARY_STORAGE_KEY_PW) == -1) {
			FATAL("Failed to initialize OpenSSL stack for device cert");
		}

		if (!file_exists(DEVICE_CSR_FILE) || (!use_tpm && !file_exists(DEVICE_KEY_FILE))) {
			DEBUG("Create CSR (recreate if corresponding private key misses)");

			if (file_exists(SCD_TOKEN_DIR) && file_is_dir(SCD_TOKEN_DIR)) {
				DEBUG("CSR folder already exists");
			} else if (dir_mkdir_p(SCD_TOKEN_DIR, 00755) != 0) {
				FATAL("Failed to create CSR directory");
			}

			char *hw_serial = NULL;
			char *hw_name = NULL;

			// file_read_new of max length of SERIAL and NAME is limited due to the character limit of RFC5280
			if (file_exists(DMI_PRODUCT_SERIAL))
				hw_serial =
					file_read_new(DMI_PRODUCT_SERIAL, DMI_PRODUCT_SERIAL_LEN);
			if (!hw_serial)
				hw_serial = mem_strdup("0000");

			if (file_exists(DMI_PRODUCT_NAME))
				hw_name = file_read_new(DMI_PRODUCT_NAME, DMI_PRODUCT_NAME_LEN);
			if (!hw_name)
				hw_name = mem_strdup("generic");

			char *common_name = mem_printf("%s %s", hw_name, hw_serial);
			DEBUG("Using common name %s", common_name);

			// create device uuid and write to csr
			uuid_t *dev_uuid = uuid_new(NULL);
			const char *uid;
			if (!dev_uuid || (uid = uuid_string(dev_uuid)) == NULL) {
				FATAL("Could not create device uuid");
			}

			if (ssl_create_csr(DEVICE_CSR_FILE, dev_key_file, NULL, common_name, uid,
					   use_tpm, RSA_SSA_PADDING) != 0) {
				FATAL("Unable to create CSR");
			}

			mem_free0(hw_serial);
			mem_free0(hw_name);
			mem_free0(common_name);
			uuid_free(dev_uuid);
			DEBUG("CSR with privkey created and stored");
		} else {
			DEBUG("CSR with privkey already exists");
		}

		// self-sign device csr to bring the device up
		// corresponding cert is overwritten during provisioning
		DEBUG("Create self-signed certificate from CSR");

		if (ssl_self_sign_csr(DEVICE_CSR_FILE, DEVICE_CERT_FILE, dev_key_file, use_tpm) !=
		    0) {
			FATAL("Unable to self sign existing device.csr");
		}

		ssl_free();
	} else {
		INFO("Device certificate found");
		if (file_exists(DEVICE_CSR_FILE)) {
			// this is the case when a non-provisioned gyroidos device
			// created its own device.cert and user.p12
			WARN("Device CSR still exists. Device was not correctly provisioned!");
		}
	}

	// we now have anything for a clean startup so just die and let us be restarted by init
	if (need_initialization) {
		logf_unregister(scd_logfile_handler);
		logf_file_close(scd_logfile_p);
		exit(0);
	}

	// remark: no certificate validation checks are carried out
	if ((!use_tpm && !file_exists(DEVICE_KEY_FILE)) || !file_exists(SSIG_ROOT_CERT)) {
		FATAL("Missing certificate chains, or private key for device certificate");
	}
}

static void
scd_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	INFO("Logfile must be closed and a new file opened");
	logf_unregister(scd_logfile_handler);
	logf_file_close(scd_logfile_p);

	scd_logfile_p = logf_file_new(LOGFILE_DIR "/cml-scd");
	scd_logfile_handler = logf_register(&logf_file_write, scd_logfile_p);
	logf_handler_set_prio(scd_logfile_handler, LOGF_PRIO_TRACE);
}

static void INIT
main_init(void)
{
	logf_register(&logf_file_write, stdout);

	scd_logfile_p = logf_file_new(LOGFILE_DIR "/cml-scd");
	scd_logfile_handler = logf_register(&logf_file_write, scd_logfile_p);
	logf_handler_set_prio(scd_logfile_handler, LOGF_PRIO_TRACE);
}

static void
main_sync_fs()
{
	SYNC_INFO();
}

int
main(UNUSED int argc, UNUSED char **argv)
{
	event_timer_t *logfile_timer = event_timer_new(
		HOURS_TO_MILLISECONDS(24), EVENT_TIMER_REPEAT_FOREVER, scd_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	event_signal_t *sig_term = event_signal_new(SIGTERM, &scd_sigterm_cb, NULL);
	event_add_signal(sig_term);

	if (atexit(&main_sync_fs))
		WARN("could not register on exit cleanup method 'cmld_cleanup()'");

	provisioning_mode();

	INFO("Starting scd ...");

	// for now, the scd is using the tpm engine only for provisioning
	if (ssl_init(false, NULL) == -1) {
		FATAL("Failed to initialize OpenSSL stack for scd runtime");
	}

	if (!file_exists(DEVICE_ID_CONF)) {
		INFO("Generating device identity from %s!", DEVICE_CERT_FILE);

		DeviceId *dev_id = mem_new0(DeviceId, 1);
		device_id__init(dev_id);

		// set device uuid
		dev_id->uuid = ssl_get_uid_from_cert_new(DEVICE_CERT_FILE);

		// write the uuid to device_id config file
		if (protobuf_message_write_to_file(DEVICE_ID_CONF, (ProtobufCMessage *)dev_id) <
		    0) {
			FATAL("Could not write device id to \"%s\"!", DEVICE_ID_CONF);
		}

		// this call also frees dev_id->uuid
		protobuf_free_message((ProtobufCMessage *)dev_id);
	}

	DEBUG("Try to create directory for socket if not existing");
	if (dir_mkdir_p(CMLD_SOCKET_DIR, 0755) < 0) {
		FATAL("Could not create directory for scd_control socket");
	}

	scd_control_cmld = scd_control_new(SCD_CONTROL_SOCKET);
	if (!scd_control_cmld) {
		FATAL("Could not init scd_control socket");
	}

	INFO("created control socket.");

	DEBUG("Try to create directory for tokencontrl sockets if not existing");
	if (dir_mkdir_p(SCD_TOKENCONTROL_SOCKET, 0755) < 0) {
		FATAL("Could not create directory for scd_control socket");
	}

	event_loop();
	ssl_free();

	return 0;
}

const char *
scd_get_softtoken_dir(void)
{
	return SCD_TOKEN_DIR;
}

/*softtoken_t *
scd_load_softtoken(const char *path, const char *name)
{
	ASSERT(path);
	ASSERT(name);

	softtoken_t *ntoken;

	TRACE("scd_load_softtoken path: %s", path);
	TRACE("scd_load_softtoken name: %s", name);

	if (strlen(name) >= strlen(TOKEN_DEFAULT_EXT) &&
	    !strcmp(name + strlen(name) - strlen(TOKEN_DEFAULT_EXT), TOKEN_DEFAULT_EXT)) {
		char *token_file = mem_printf("%s/%s", path, name);
		TRACE("Softtoken filename: %s", token_file);

		ntoken = softtoken_new_from_p12(token_file);
		mem_free0(token_file);
		return ntoken;
	}

	ERROR("SCD: scd_load_softtoken failed");
	return NULL;
}*/

/**
 * Gets an existing scd token.
 */
token_t *
scd_get_token(tokentype_t type, const char *tuuid)
{
	for (list_t *l = scd_token_list; l; l = l->next) {
		token_t *t = (token_t *)l->data;
		ASSERT(t);

		if (type != token_get_type(t)) {
			continue;
		}

		if (strcmp(tuuid, uuid_string(token_get_uuid(t))) == 0) {
			TRACE("Token %s found in scd_token_list", uuid_string(token_get_uuid(t)));
			return t;
		}
	}
	return NULL;
}

/**
 * Creates a new scd token structure and appends it to the global list.
 */
int
scd_token_new(tokentype_t type, const char *uuid, const char *token_info)
{
	TRACE("SCD: scd_token_new. proto_tokentype: %d", type);

	token_t *ntoken;

	if (NULL != (ntoken = scd_get_token(type, uuid))) {
		WARN("SCD: Token %s already exists. Aborting creation...", uuid);
		return -1; // TODO: is this the correct behaviour?
	}

	switch (type) {
	case TOKEN_TYPE_NONE:
		ntoken = token_new(TOKEN_TYPE_NONE, NULL, uuid);
		break;
	case TOKEN_TYPE_SOFT:
		ntoken = token_new(TOKEN_TYPE_SOFT, SCD_TOKEN_DIR, uuid);
		break;
	case TOKEN_TYPE_USB:
		ntoken = token_new(TOKEN_TYPE_USB, token_info, uuid);
		break;
	case TOKEN_TYPE_PKCS11:
		ASSERT(token_info);
		str_t *module_path = str_new(PKCS11_MODULE_DIR);
		str_append(module_path, token_info);
		char *pkcs11_module = str_free(module_path, false);
		ntoken = token_new(TOKEN_TYPE_PKCS11, pkcs11_module, uuid);
		mem_free0(pkcs11_module);
		break;
	default:
		ERROR("Type of token not recognized");
		return -1;
	}

	if (!ntoken) {
		ERROR("Could not create new scd_token");
		return -1;
	}
	scd_token_list = list_append(scd_token_list, ntoken);

	return 0;
}

/**
 * free a scd token and remove it from the global list of initialized tokens.
 */
void
scd_token_free(token_t *token)
{
	IF_NULL_RETURN(token);
	token_t *t = token;
	scd_token_list = list_remove(scd_token_list, token);
	token_free(t);
}
