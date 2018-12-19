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

#ifdef ANDROID
#include "device/fraunhofer/common/cml/tpm2_control/tpm2d.pb-c.h"
#else
#include "tpm2d.pb-c.h"
#endif

#include "common/macro.h"
#include "common/sock.h"
#include "common/mem.h"
#include "common/protobuf.h"

#include <protobuf-c-text/protobuf-c-text.h>
#include <stdbool.h>

#define TPM2D_SOCK_PATH "/data/cml/tpm2d/communication"
#define TPM2D_SOCKET TPM2D_SOCK_PATH "/control.sock"

static int tss_sock = -1;

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
		return -1;
	}
}

int
tss_init(void)
{
	tss_sock = sock_unix_create_and_connect(SOCK_STREAM, TPM2D_SOCKET);
	return (tss_sock < 0) ? -1 : 0;
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
	msg.ml_hashalg = tss_hash_algo_get_len_proto(hashalgo);

	if (protobuf_send_message(tss_sock, (ProtobufCMessage *) &msg) < 0) {
		WARN("Failed to send measurement to tpm2d");
	}

	TpmToController *resp = (TpmToController *)protobuf_recv_message(tss_sock, &tpm_to_controller__descriptor);
	if (!resp) {
		WARN("Failed to receive and decode TpmToController protobuf message!");
		return;
	}

	if (resp->code != TPM_TO_CONTROLLER__CODE__GENERIC_RESPONSE ||
			resp->response != TPM_TO_CONTROLLER__GENERIC_RESPONSE__CMD_OK) {
		ERROR("tpmd failed to append measurement to ML");
	} else {
		INFO("Sucessfully appended measurement to ML: file %s" , filename);
	}

	protobuf_free_message((ProtobufCMessage *)resp);
}
