/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2018 Fraunhofer AISEC
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

#include "tss.h"

#include "tpm2d.pb-c.h"
#include "tpm2d_shared.h"
#include "cmld.h"
#include "unit.h"

#include "common/event.h"
#include "common/dir.h"
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/proc.h"
#include "common/fd.h"
#include "common/file.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>

// clang-format off
#define TPM2D_CONTROL_SOCKET "tpm2d-control"
// clang-format on

#ifndef TPM2D_BINARY_NAME
#define TPM2D_BINARY_NAME "tpm2d"
#endif

#define TPM2D_UUID "00000000-0000-0000-0000-000000000002"

static int tss_sock = -1;

static unit_t *tpm2d_unit;

/**
 * Returns the HashAlgLen (proto) for the given tss_hash_algo_t algo.
 */
static HashAlgLen
tss_hash_algo_get_len_proto(tss_hash_algo_t algo)
{
	switch (algo) {
	case TSS_SHA1:
		return HASH_ALG_LEN__SHA1;
	case TSS_SHA256:
		return HASH_ALG_LEN__SHA256;
	case TSS_SHA384:
		return HASH_ALG_LEN__SHA384;
	default:
		ERROR("Unsupported value for tss_hash_algo_t: %d", algo);
		return 0;
	}
}

bool
tss_is_tpm2d_installed(void)
{
	bool found = false;
	const char *path[] = { "/bin",	    "/sbin",	      "/usr/bin",
			       "/usr/sbin", "/usr/local/bin", "/usr/local/bin" };

	for (size_t i = 0; i < 6; ++i) {
		char *binary = mem_printf("%s/%s", path[i], TPM2D_BINARY_NAME);
		found = file_exists(binary);
		mem_free0(binary);
		if (found)
			return true;
	}
	return false;
}

static void
tss_event_cb_recv_message(int fd, unsigned events, event_io_t *io, UNUSED void *data)
{
	if (events & EVENT_IO_EXCEPT) {
		INFO("tpm2d closed event connection; reconnect.");
		event_remove_io(io);
		event_io_free(io);
		if (close(fd) < 0)
			WARN_ERRNO("Failed to close connected tpm2d socket");
	}
}

static void
tss_tpm2d_on_connect_cb(int sock, const char *sock_path)
{
	ASSERT(sock_path);

	tss_sock = sock;

	/* register socket for receiving data */
	fd_make_non_blocking(sock);

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, &tss_event_cb_recv_message, NULL);
	event_add_io(event);

	cmld_init_stage_unit_notify(tpm2d_unit);
}

int
tss_init(void)
{
	// Check if the platform has a TPM module attached
	if (!file_exists("/dev/tpmrm0") || !tss_is_tpm2d_installed()) {
		WARN("Platform does not support TSS / TPM 2.0");
		return 0;
	}

	// create data dir if not existing
	if (!file_is_dir(TPM2D_BASE_DIR)) {
		if (dir_mkdir_p(TPM2D_BASE_DIR, 0755) < 0) {
			FATAL_ERRNO("Could not mkdir tpm2d's data dir: %s", TPM2D_BASE_DIR);
		}
	} else {
		// ensure scd can access the file which stores the TPM-wrapped device key
		if (chmod(TPM2D_BASE_DIR, 00755) < 0) {
			FATAL_ERRNO("Could not chmod '%s' to 755!", TPM2D_BASE_DIR);
		}
		const char *token_dir = TPM2D_BASE_DIR "/" TPM2D_TOKEN_DIR;
		if (file_is_dir(token_dir) && chmod(token_dir, 00755) < 0) {
			FATAL_ERRNO("Could not chmod '%s' to 755!", token_dir);
		}
	}

	// Start the tpm2d
	tpm2d_unit = unit_new(uuid_new(TPM2D_UUID), "TPM2D", TPM2D_BINARY_NAME, NULL, NULL, 0,
			      false, TPM2D_BASE_DIR, TPM2D_CONTROL_SOCKET, SOCK_STREAM,
			      &tss_tpm2d_on_connect_cb, true);

	// grant access to the TPM
	list_t *dev_nodes = list_append(NULL, "/dev/tpmrm0");
	unit_device_set_initial_allow(tpm2d_unit, dev_nodes);
	list_delete(dev_nodes);

	// ensure read access to ima measurements for attestation
	list_t *ima_files = NULL;
	ima_files = list_append(ima_files, "/sys/kernel/security/ima/binary_runtime_measurements");
	ima_files =
		list_append(ima_files, "/sys/kernel/security/ima/binary_runtime_measurements_sha1");
	ima_files = list_append(ima_files,
				"/sys/kernel/security/ima/binary_runtime_measurements_sha256");

	for (list_t *l = ima_files; l; l = l->next) {
		const char *file = l->data;
		if (chmod(file, 00444) < 0)
			WARN("Could not chmod '%s' to read-only!", file);
	}

	list_delete(ima_files);

	if (unit_start(tpm2d_unit)) {
		unit_free(tpm2d_unit);
		ERROR("Could nor start unit for tpm2d!");
		return -1;
	}

	cmld_init_stage_unit_notify(tpm2d_unit);

	return 0;
}

void
tss_cleanup(void)
{
	IF_NULL_RETURN(tpm2d_unit);

	unit_kill(tpm2d_unit);
	unit_free(tpm2d_unit);
}

void
tss_ml_append(char *filename, uint8_t *filehash, int filehash_len, tss_hash_algo_t hashalgo)
{
	/*
	 * check if tpm2d socket is connected otherwise silently return,
	 * since platform may not support tss/tpm2 functionality
	 */
	IF_TRUE_RETURN(tss_sock < 0);

	ControllerToTpm msg = CONTROLLER_TO_TPM__INIT;

	msg.code = CONTROLLER_TO_TPM__CODE__ML_APPEND;
	msg.ml_filename = filename;
	msg.has_ml_datahash = true;
	msg.ml_datahash.len = filehash_len;
	msg.ml_datahash.data = filehash;
	msg.has_ml_hashalg = true;

	HashAlgLen hash_len = tss_hash_algo_get_len_proto(hashalgo);
	IF_TRUE_RETURN(hash_len == 0);
	msg.ml_hashalg = hash_len;

	if (protobuf_send_message(tss_sock, (ProtobufCMessage *)&msg) < 0) {
		WARN("Failed to send measurement to tpm2d");
	}

	TpmToController *resp =
		(TpmToController *)protobuf_recv_message(tss_sock, &tpm_to_controller__descriptor);
	if (!resp) {
		WARN("Failed to receive and decode TpmToController protobuf message!");
		return;
	}

	if (resp->code != TPM_TO_CONTROLLER__CODE__GENERIC_RESPONSE ||
	    resp->response != TPM_TO_CONTROLLER__GENERIC_RESPONSE__CMD_OK) {
		ERROR("tpmd failed to append measurement to ML");
	} else {
		INFO("Sucessfully appended measurement to ML: file %s", filename);
	}

	protobuf_free_message((ProtobufCMessage *)resp);
}
