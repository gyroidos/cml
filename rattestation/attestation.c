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
	char *config_file;
};

static char *
convert_bin_to_hex_new(const uint8_t *bin, int length)
{
	size_t len = MUL_WITH_OVERFLOW_CHECK(length, (size_t)2);
	len = MUL_WITH_OVERFLOW_CHECK(len, sizeof(char));
	len = ADD_WITH_OVERFLOW_CHECK(len, 1);
	char *hex = mem_alloc0(len);

	for (int i = 0; i < length; ++i) {
		// remember snprintf additionally writes a '0' byte
		snprintf(hex + i * 2, 3, "%.2x", bin[i]);
	}

	return hex;
}

static bool
attestation_verify_resp(Tpm2dToRemote *resp, const char *config_file, uint8_t *nonce,
			size_t nonce_len)
{
	ASSERT(config_file);
	ASSERT(nonce);
	ASSERT(resp);

	bool ret = false;
	uint8_t quote[resp->quoted.len];
	uint8_t sig[resp->signature.len];
	uint8_t *q = quote; // Required as TSS functions manipulate pointer
	uint8_t *s = sig;   // Required as TSS functions manipulate pointer
	uint32_t quote_len = resp->quoted.len;
	uint32_t sig_len = resp->signature.len;
	char *pcr_strings[resp->n_pcr_values];

	// TODO Right now, the "good" values are read from the configuration file.
	// Later, different methods could be implemented
	RAttestationConfig *config = rattestation_read_config_new(config_file);
	if (!config) {
		ERROR("Failed to read config file %s. The file has to be provided as a command line argument",
		      config_file);
		return false;
	}

	if (resp->has_quoted) {
		char *quote_str = convert_bin_to_hex_new(resp->quoted.data, resp->quoted.len);
		DEBUG("Quote (Length %ld): %s", resp->quoted.len, quote_str);
		mem_free(quote_str);
	} else {
		ERROR("Response does not contain quote to be verified");
		ret = false;
		goto err;
	}

	if (resp->has_signature) {
		char *sig_str = convert_bin_to_hex_new(resp->signature.data, resp->signature.len);
		DEBUG("Signature (Length %ld): %s\n", resp->signature.len, sig_str);
		mem_free(sig_str);
	} else {
		ERROR("Response does not contain signature");
		goto err;
	}

	// The TSS library manipulates the quote and signature buffers. Copy the buffers
	// in order to enable a clean freeing of the protobuf response
	memcpy(quote, resp->quoted.data, resp->quoted.len);
	memcpy(sig, resp->signature.data, resp->signature.len);

	// Convert to hex string representation to directly compare with specified values
	// in the configuration file
	for (size_t i = 0; i < resp->n_pcr_values; i++) {
		pcr_strings[i] = convert_bin_to_hex_new(resp->pcr_values[i]->value.data,
							resp->pcr_values[i]->value.len);
	}

	DEBUG("Verifying Response...");

	DEBUG("Hash Algorithm: SHA%d", config->halg * 8);

	// The pcrs are configured as hex strings
	size_t pcr_string_len = config->halg * 2;

	for (size_t i = 0; i < config->n_pcr_values; i++) {
		if (strlen(pcr_strings[i]) != pcr_string_len) {
			ERROR("Length of configured PCR value %ld invalid (%ld, must be %ld)", i,
			      strlen(pcr_strings[i]), pcr_string_len);
			ret = false;
			goto err;
		}
		if (strlen(config->pcr_values[i]->value) != pcr_string_len) {
			ERROR("Length of received PCR value %ld invalid (%ld, must be %ld)", i,
			      strlen(config->pcr_values[i]->value), pcr_string_len);
			ret = false;
			goto err;
		}
		if (strncmp(pcr_strings[i], config->pcr_values[i]->value, pcr_string_len)) {
			DEBUG("PCR_%ld: %s - VERIFICATION FAILED", i, pcr_strings[i]);
			ret = false;
			goto err;
		}
		DEBUG("PCR_%ld: %s - VERIFICATION SUCCESSFUL", i, pcr_strings[i]);
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

	char *nonce_str = convert_bin_to_hex_new(nonce, nonce_len);
	char *rcv_nonce_str = convert_bin_to_hex_new(tpms_attest.extraData.t.buffer,
						     tpms_attest.extraData.t.size);
	DEBUG("Nonce (sent %s, received %s) - %s", nonce_str, rcv_nonce_str,
	      ret_nonce ? "VERIFICATION FAILED" : "VERIFICATION SUCCESSFUL");
	mem_free(nonce_str);
	mem_free(rcv_nonce_str);

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
						   resp->quoted.data, resp->quoted.len);
	if (retssl != 0) {
		ERROR("VERIFY QUOTE SIGNATURE FAILED");
		ret = false;
		goto err;
	} else {
		INFO("VERIFY QUOTE SIGNATURE SUCCESSFUL");
	}

	// PCR10 kernel module verification (from /sys/kernel/security/ima/binary_runtime_measuremts)
	hash_algo_t hash_algo = size_to_hash_algo((int)resp->halg);
	int ret_ima = ima_verify_binary_runtime_measurements(resp->ml_ima_entry.data,
							     resp->ml_ima_entry.len,
							     config->kmod_sign_cert, hash_algo,
							     resp->pcr_values[10]->value.data);
	if (ret_ima != 0) {
		ERROR("Failed to verify measurement list");
		goto err;
	}

	// PCR11 container verification
	int ret_container =
		container_verify_runtime_measurements(resp->ml_container_entry,
						      resp->n_ml_container_entry, hash_algo,
						      resp->pcr_values[11]->value.data);
	if (ret_container != 0) {
		ERROR("Failed to verify container measurement list");
		goto err;
	}

	ret = true;

err:
	DEBUG("---------------------------");
	DEBUG("REMOTE ATTESTATION: %s", ret ? "SUCCESSFUL" : "FAILED");
	DEBUG("---------------------------");

	// Free resources
	for (size_t i = 0; i < resp->n_pcr_values; i++) {
		mem_free(pcr_strings[i]);
	}
	protobuf_free_message((ProtobufCMessage *)config);
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

	verified = attestation_verify_resp(resp, resp_cb_data->config_file, resp_cb_data->nonce,
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
		mem_free(resp_cb_data->nonce);
	mem_free(resp_cb_data);
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

	// build RemoteToTpm2d message
	RemoteToTpm2d msg = REMOTE_TO_TPM2D__INIT;

	msg.code = REMOTE_TO_TPM2D__CODE__ATTESTATION_REQ;
	msg.has_qualifyingdata = true;
	msg.qualifyingdata.data = nonce;
	msg.qualifyingdata.len = nonce_len;

	int sock = sock_inet_create_and_connect(SOCK_STREAM, host, TPM2D_SERVICE_PORT);
	IF_TRUE_RETVAL(sock < 0, -1);

	DEBUG("Sending attestation request to TPM2D on %s:%s", host, TPM2D_SERVICE_PORT);

	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)&msg);
	IF_TRUE_RETVAL(msg_size < 0, -1);

	INFO("Send message with size %ld", msg_size);

	char *nonce_str = convert_bin_to_hex_new(nonce, nonce_len);
	INFO("Request with Nonce %s, Request size=%zd", nonce_str, msg_size);
	mem_free(nonce_str);

	struct attestation_resp_cb_data *resp_cb_data =
		mem_new0(struct attestation_resp_cb_data, 1);
	resp_cb_data->resp_verified_cb = resp_verified_cb;
	resp_cb_data->nonce = mem_new0(uint8_t, nonce_len);
	memcpy(resp_cb_data->nonce, nonce, nonce_len);
	resp_cb_data->nonce_len = nonce_len;
	resp_cb_data->config_file = config_file;

	DEBUG("Register Response handler on sockfd=%d", sock);
	fd_make_non_blocking(sock);
	event_io_t *event =
		event_io_new(sock, EVENT_IO_READ, attestation_response_recv_cb, resp_cb_data);
	event_add_io(event);

	return 0;
}