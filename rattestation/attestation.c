/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2021 Fraunhofer AISEC
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

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/random.h>
#include "ibmtss/Unmarshal_fp.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/event.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/ssl_util.h"
#include "common/hex.h"

#include "attestation.pb-c.h"
#include "config.pb-c.h"
#include "attestation.h"
#include "config.h"
#include "modsig.h"
#include "hash.h"
#include "ima_verify.h"
#include "container_verify.h"

#define TPM2D_SERVICE_PORT "9505"

struct attestation_resp_cb_data {
	void (*resp_verified_cb)(bool);
	size_t nonce_len;
	uint8_t *nonce;
	RAttestationConfig *config;
};

static bool
attestation_verify_resp(Tpm2dToRemote *resp, RAttestationConfig *config, uint8_t *nonce,
			size_t nonce_len)
{
	ASSERT(config);
	ASSERT(nonce);
	ASSERT(resp);
	ASSERT(resp->n_pcr_values < 24);
	ASSERT((config->halg == SHA256_DIGEST_LENGTH) || (config->halg == SHA_DIGEST_LENGTH));

	bool ret = false;
	uint8_t quote[resp->quoted.len];
	uint8_t sig[resp->signature.len];
	uint8_t *q = quote; // Required as TSS functions manipulate pointer
	uint8_t *s = sig;   // Required as TSS functions manipulate pointer
	uint32_t quote_len = resp->quoted.len;
	uint32_t sig_len = resp->signature.len;
	uint8_t pcr[resp->n_pcr_values][config->halg];

	if (resp->has_quoted) {
		INFO("Response contains quote (Length %zu)", resp->quoted.len);
		DEBUG_HEXDUMP(resp->quoted.data, resp->quoted.len, "Quote");
	} else {
		ERROR("Response does not contain quote to be verified");
		ret = false;
		goto err;
	}

	if (resp->has_signature) {
		DEBUG("Response contains signature (Length %zu)", resp->signature.len);
		DEBUG_HEXDUMP(resp->signature.data, resp->signature.len, "Signature");
	} else {
		ERROR("Response does not contain signature");
		goto err;
	}

	// The TSS library manipulates the quote and signature buffers. Copy the buffers
	// in order to enable a clean freeing of the protobuf response
	memcpy(quote, resp->quoted.data, resp->quoted.len);
	memcpy(sig, resp->signature.data, resp->signature.len);

	DEBUG("Verifying Response...");
	DEBUG("Hash Algorithm: SHA%d", config->halg * 8);

	if (resp->n_pcr_values != config->n_pcr_values) {
		ERROR("Number of configured PCR values (%lu) does not match responded PCR values (%lu)",
		      config->n_pcr_values, resp->n_pcr_values);
		ret = false;
		goto err;
	}

	bool ret_pcr = true;
	for (size_t i = 0; i < config->n_pcr_values; i++) {
		if (convert_hex_to_bin(config->pcr_values[i]->value,
				       strlen(config->pcr_values[i]->value), pcr[i],
				       config->halg)) {
			ERROR("Failed to convert configured PCR value %s: Invalid hex string",
			      config->pcr_values[i]->value);
			ret_pcr = false;
			continue;
		}
		if (resp->pcr_values[i]->value.len != config->halg) {
			ERROR("Length of configured PCR value %zu invalid (%zu,	must be %u)", i,
			      resp->pcr_values[i]->value.len, config->halg);
			ret_pcr = false;
			continue;
		}
		if (!config->pcr_values[i]->has_number || !resp->pcr_values[i]->has_number) {
			ERROR("PCR number not specified");
			ret_pcr = false;
			continue;
		}
		if (config->pcr_values[i]->number != resp->pcr_values[i]->number) {
			ERROR("Configured PCR number (%d) does not match responded PCR number (%d)",
			      config->pcr_values[i]->number, resp->pcr_values[i]->number);
			ret_pcr = false;
			continue;
		}
		if (memcmp(pcr[i], resp->pcr_values[i]->value.data, config->halg)) {
			ERROR_HEXDUMP(resp->pcr_values[i]->value.data,
				      resp->pcr_values[i]->value.len, "PCR_%d VERIFICATION FAILED",
				      resp->pcr_values[i]->number);
			ret_pcr = false;
			continue;
		}

		DEBUG_HEXDUMP(resp->pcr_values[i]->value.data, resp->pcr_values[i]->value.len,
			      "PCR_%d VERIFICATION SUCCESSFUL", resp->pcr_values[i]->number);
	}

	if (!ret_pcr) {
		ERROR("PCR VERIFICATION FAILED");
		ret = false;
		goto err;
	}

	// The quote is sent as a TPMS_ATTEST and has to be unmarshalled
	TPMS_ATTEST tpms_attest;
	TPM_RC rc = TSS_TPMS_ATTEST_Unmarshalu(&tpms_attest, &q, &quote_len);
	if (rc != TPM_RC_SUCCESS) {
		ERROR("TSS_TPMS_ATTEST_Unmarshalu returned error code %u\n", rc);
		ret = false;
		goto err;
	}

	// Nonce verification
	int ret_nonce = memcmp(tpms_attest.extraData.t.buffer, nonce, nonce_len);
	DEBUG_HEXDUMP(nonce, nonce_len, "Nonce sent");
	DEBUG_HEXDUMP(tpms_attest.extraData.t.buffer, tpms_attest.extraData.t.size, "Nonce rcvd");
	if (ret_nonce) {
		ERROR("Nonce VERIFICATION FAILED");
		ret = false;
		goto err;
	}
	DEBUG("Nonce VERIFICATION SUCCESSFUL");

	// The signature is sent as a TPMT_SIGNATURE and has to be unmarshalled
	TPMT_SIGNATURE tpmt_signature;
	rc = TSS_TPMT_SIGNATURE_Unmarshalu(&tpmt_signature, &s, &sig_len, false);
	if (rc != TPM_RC_SUCCESS) {
		ERROR("TSS_TPMT_SIGNATURE_Unmarshalu returned error code %u", rc);
		ret = false;
		goto err;
	}

	// Verify signature
	ssl_init(false, NULL);

	int retssl = ssl_verify_signature_from_buf(resp->certificate.data, resp->certificate.len,
						   tpmt_signature.signature.rsapss.sig.t.buffer,
						   tpmt_signature.signature.rsapss.sig.t.size,
						   resp->quoted.data, resp->quoted.len, "SHA256");
	if (retssl != 0) {
		ERROR("VERIFY QUOTE SIGNATURE FAILED");
		ret = false;
		goto err;
	} else {
		INFO("VERIFY QUOTE SIGNATURE SUCCESSFUL");
	}

	// Verify aggregated PCR value
	DEBUG_HEXDUMP(tpms_attest.attested.quote.pcrDigest.t.buffer,
		      tpms_attest.attested.quote.pcrDigest.t.size, "Quote PCR Digest");
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	uint8_t pcr_calc[SHA256_DIGEST_LENGTH] = { 0 };
	for (size_t i = 0; i < resp->n_pcr_values; i++) {
		SHA256_Update(&ctx, resp->pcr_values[i]->value.data, SHA256_DIGEST_LENGTH);
	}
	SHA256_Final(pcr_calc, &ctx);
	if (memcmp(tpms_attest.attested.quote.pcrDigest.t.buffer, pcr_calc, SHA256_DIGEST_LENGTH)) {
		ERROR("VERIFY AGGREGATED PCR FAILED");
		ret = false;
		goto err;
	}
	INFO("VERIFY AGGREGATED PCR SUCCESSFUL");

	// PCR10 kernel module verification (from /sys/kernel/security/ima/binary_runtime_measuremts)
	hash_algo_t hash_algo = size_to_hash_algo((int)resp->halg);

	if (config->verify_ima) {
		// Check if response has IMA entries
		if (!resp->has_ml_ima_entry) {
			ERROR("Response does not contain IMA entries");
			ret = false;
			goto err;
		}

		// Find the PCR containing the IMA measurements
		int ima_index = -1;
		for (int i = 0; i < (int)resp->n_pcr_values; i++) {
			if (resp->pcr_values[i]->number == config->ima_pcr) {
				ima_index = i;
				break;
			}
		}

		if (ima_index < 0) {
			ERROR("Configured IMA PCR %d not present", config->ima_pcr);
			ret = false;
			goto err;
		}

		int ret_ima = ima_verify_binary_runtime_measurements(
			resp->ml_ima_entry.data, resp->ml_ima_entry.len, config->kmod_sign_cert,
			hash_algo, resp->pcr_values[ima_index]->value.data);
		if (ret_ima != 0) {
			ERROR("Failed to verify measurement list");
			ret = false;
			goto err;
		}
	}

	// PCR11 container verification
	if (config->verify_containers) {
		// Check if response has container entries
		if (resp->n_ml_container_entry == 0) {
			ERROR("Response does not contain container entries");
			ret = false;
			goto err;
		}

		// Find the PCR containing the container measurements
		int container_index = -1;
		for (int i = 0; i < (int)resp->n_pcr_values; i++) {
			if (resp->pcr_values[i]->number == config->container_pcr) {
				container_index = i;
				break;
			}
		}

		if (container_index < 0) {
			ERROR("Configured IMA PCR %d not present", config->ima_pcr);
			ret = false;
			goto err;
		}
		int ret_container = container_verify_runtime_measurements(
			resp->ml_container_entry, resp->n_ml_container_entry, hash_algo,
			resp->pcr_values[container_index]->value.data);
		if (ret_container != 0) {
			ERROR("Failed to verify container measurement list");
			ret = false;
			goto err;
		}
	}

	ret = true;

err:
	DEBUG("---------------------------");
	DEBUG("REMOTE ATTESTATION: %s", ret ? "SUCCESSFUL" : "FAILED");
	DEBUG("---------------------------");

	// Free resources
	ssl_free();

	return ret;
}

static void
attestation_response_recv_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	bool verified = false;
	struct attestation_resp_cb_data *resp_cb_data = data;

	if (events & EVENT_IO_EXCEPT) {
		WARN("Exception on connected socket to control client; closing socket");
		goto cleanup;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	Tpm2dToRemote *resp =
		(Tpm2dToRemote *)protobuf_recv_message(fd, &tpm2d_to_remote__descriptor);
	IF_NULL_GOTO_ERROR(resp, cleanup);

	verified = attestation_verify_resp(resp, resp_cb_data->config, resp_cb_data->nonce,
					   resp_cb_data->nonce_len);

	protobuf_free_message((ProtobufCMessage *)resp);
	INFO("Handled response on connection %d", fd);

cleanup:
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected tpm2d socket");
	// call registerd handler with verification result
	if (resp_cb_data->resp_verified_cb)
		(resp_cb_data->resp_verified_cb)(verified);
	if (resp_cb_data->nonce)
		mem_free0(resp_cb_data->nonce);
	protobuf_free_message((ProtobufCMessage *)resp_cb_data->config);
	mem_free0(resp_cb_data);
}

int
attestation_do_request(const char *host, char *config_file, void (*resp_verified_cb)(bool))
{
	// Set nonce
	size_t nonce_len = 8;
	uint8_t nonce[nonce_len];
	if (getrandom(nonce, nonce_len, (unsigned int)0) != (ssize_t)nonce_len) {
		ERROR("Failed to create attestation request: Failed to retrieve random nonce from /dev/urandom");
		return -1;
	}

	// Read the configuration which contains information about the remote attestation request
	// as well as the expected values for the PCRs
	RAttestationConfig *config = rattestation_read_config_new(config_file);
	if (!config) {
		ERROR("Failed to read config file %s. The file has to be provided as a command line argument",
		      config_file);
		return -1;
	}

	// build RemoteToTpm2d message
	RemoteToTpm2d msg = REMOTE_TO_TPM2D__INIT;

	msg.code = REMOTE_TO_TPM2D__CODE__ATTESTATION_REQ;
	msg.has_qualifyingdata = true;
	msg.qualifyingdata.data = nonce;
	msg.qualifyingdata.len = nonce_len;
	msg.has_atype = true;
	msg.atype = config->atype;
	if (config->atype == IDS_ATTESTATION_TYPE__ADVANCED) {
		if (!config->has_pcrs) {
			ERROR("Missing PCR bitmap configuration for attestation type advanced");
			return -1;
		}
		msg.has_pcrs = true;
		msg.pcrs = config->pcrs;
	}
	msg.attest_ima = config->verify_ima;
	msg.attest_containers = config->verify_containers;

	int sock = sock_inet_create_and_connect(SOCK_STREAM, host, TPM2D_SERVICE_PORT);
	IF_TRUE_RETVAL(sock < 0, -1);

	DEBUG("Sending attestation request to TPM2D on %s:%s", host, TPM2D_SERVICE_PORT);

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)&msg);
	IF_TRUE_RETVAL(msg_size < 0, -1);

	INFO("Send message with size %zd", msg_size);
	DEBUG_HEXDUMP(nonce, nonce_len, "Request with Nonce");

	struct attestation_resp_cb_data *resp_cb_data =
		mem_new0(struct attestation_resp_cb_data, 1);
	resp_cb_data->resp_verified_cb = resp_verified_cb;
	resp_cb_data->nonce = mem_new0(uint8_t, nonce_len);
	memcpy(resp_cb_data->nonce, nonce, nonce_len);
	resp_cb_data->nonce_len = nonce_len;
	resp_cb_data->config = config;

	DEBUG("Register Response handler on sockfd=%d", sock);
	fd_make_non_blocking(sock);
	event_io_t *event =
		event_io_new(sock, EVENT_IO_READ, attestation_response_recv_cb, resp_cb_data);
	event_add_io(event);

	return 0;
}
