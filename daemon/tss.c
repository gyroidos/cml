/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#include "tss.h"

#include "tpm2d.pb-c.h"
#include "tpm2d_shared.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/proc.h"
#include "common/file.h"

#include <google/protobuf-c/protobuf-c-text.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TPM2D_BINARY_NAME
#define TPM2D_BINARY_NAME "tpm2d"
#endif

static int tss_sock = -1;
static pid_t tss_tpm2d_pid = -1;

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

static bool
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

static pid_t
fork_and_exec_tpm2d(void)
{
	TRACE("Starting tpm2d..");

	int status;
	pid_t pid = fork();
	char *const param_list[] = { TPM2D_BINARY_NAME, NULL };

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", TPM2D_BINARY_NAME);
		return -1;
	case 0:
		execvp((const char *)param_list[0], param_list);
		FATAL_ERRNO("Could not execvp %s", TPM2D_BINARY_NAME);
		return -1;
	default:
		// Just check if the child is alive but do not wait
		if (waitpid(pid, &status, WNOHANG) != 0) {
			ERROR("Failed to start %s", TPM2D_BINARY_NAME);
			return -1;
		}
		return pid;
	}
	return -1;
}

int
tss_init(bool start_daemon)
{
	// Check if the platform has a TPM module attached
	if (!file_exists("/dev/tpm0") || !tss_is_tpm2d_installed()) {
		WARN("Platform does not support TSS / TPM 2.0");
		return 0;
	}

	// Start the tpm2d
	// In hosted mode this should be handled by the respective init scripts
	if (start_daemon) {
		tss_tpm2d_pid = fork_and_exec_tpm2d();
		IF_TRUE_RETVAL_TRACE(tss_tpm2d_pid == -1, -1);
	} else {
		DEBUG("Skipping tpm2d launch as requested");
	}

	// Connect to tpm2d
	size_t retries = 0;
	do {
		NANOSLEEP(0, 500000000)
		tss_sock = sock_unix_create_and_connect(SOCK_STREAM, TPM2D_SOCKET);
		retries++;
		TRACE("Retry %zu connecting to tpm2d", retries);
		printf(".");
		fflush(stdout);
	} while (tss_sock < 0);

	return (tss_sock < 0) ? -1 : 0;
}

static void
tss_tpm2d_stop(void)
{
	IF_TRUE_RETURN_TRACE(tss_tpm2d_pid == -1);
	DEBUG("Stopping %s process with pid=%d!", TPM2D_BINARY_NAME, tss_tpm2d_pid);
	kill(tss_tpm2d_pid, SIGTERM);
}

void
tss_cleanup(void)
{
	tss_tpm2d_stop();
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
