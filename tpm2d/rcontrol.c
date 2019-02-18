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

#include "rcontrol.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/tpm2d/attestation.pb-c.h"
#else
#include "attestation.pb-c.h"
#endif

#include "tpm2d.h"
#include "ml.h"
#include "ek.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/protobuf.h"

#include "protobuf-c-text/protobuf-c-text.h"

struct tpm2d_rcontrol {
	int sock;		// listen ip socket fd
};

/**
 * Returns the HashAlgLen (proto) for the given TPM_ALG_ID alg_id.
 */
static HashAlgLen
tpm2d_rcontrol_hash_algo_get_len_proto(TPM_ALG_ID alg_id)
{
	switch (alg_id) {
	case TPM_ALG_SHA1:
		return HASH_ALG_LEN__SHA1;
	case TPM_ALG_SHA256:
		return HASH_ALG_LEN__SHA256;
	case TPM_ALG_SHA384:
		return HASH_ALG_LEN__SHA384;
	default:
		ERROR("Unsupported value for TPM_ALG_ID: %d", alg_id);
		return -1;
	}
}

static void
tpm2d_rcontrol_handle_message(const RemoteToTpm2d *msg, int fd, tpm2d_rcontrol_t *rcontrol)
{
	ASSERT(rcontrol);

	TRACE("Handle message from client fd=%d", fd);

	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text = protobuf_c_text_to_string((ProtobufCMessage *)msg, NULL);
		TRACE("Handling RemoteToTpmd message:\n%s", msg_text ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	switch(msg->code) {
	case REMOTE_TO_TPM2D__CODE__ATTESTATION_REQ: {
		Pcr **out_pcrs = NULL;
		int pcr_regs = 0;
		int pcr_indices = 0;
		tpm2d_pcr_t** pcr_array = NULL;
		tpm2d_quote_t *quote = NULL;
		uint8_t *attestation_cert = NULL;

		Tpm2dToRemote out = TPM2D_TO_REMOTE__INIT;
		out.code = TPM2D_TO_REMOTE__CODE__ATTESTATION_RES;

		switch (msg->atype) {
			case IDS_ATTESTATION_TYPE__BASIC:
				TRACE("atype BASIC");
				pcr_regs = 12;
				break;
			case IDS_ATTESTATION_TYPE__ALL:
				TRACE("atype ALL");
				pcr_regs = 24;
				break;
			case IDS_ATTESTATION_TYPE__ADVANCED:
				TRACE("atype ADVACE");
				pcr_regs = (msg->has_pcrs) ? msg->pcrs : 0;
				break;
			default:
				goto err_att_req;
				break;
		}
		pcr_indices = pcr_regs - 1;

		pcr_array = mem_alloc0(sizeof(tpm2d_pcr_t*) * pcr_regs);
		for (int i=0; i < pcr_regs; ++i) {
			pcr_array[i] = tpm2_pcrread_new(i, TPM2D_HASH_ALGORITHM);

			IF_NULL_GOTO_ERROR(pcr_array[i], err_att_req);
			INFO("PCR%d: size %zu", i, pcr_array[i]->pcr_size);
		}

		quote = tpm2_quote_new(pcr_indices, tpm2d_get_as_key_handle(),
				TPM2D_ATTESTATION_KEY_PW, msg->qualifyingdata.data,
				msg->qualifyingdata.len);
		IF_NULL_GOTO_ERROR(quote, err_att_req);

		size_t att_cert_len;
		attestation_cert = ek_get_certificate_new(TPM2D_ASYM_ALGORITHM, &att_cert_len);
		IF_NULL_GOTO_ERROR(attestation_cert, err_att_req);
		INFO("cert ek done: size=%zu", att_cert_len);

		Pcr out_pcr = PCR__INIT;
		out_pcrs = mem_new(Pcr *, pcr_regs);
		for (int i=0; i < pcr_regs; ++i) {
			out_pcr.has_value = true;
			out_pcr.value.data = pcr_array[i]->pcr_value;
			out_pcr.value.len = pcr_array[i]->pcr_size;
			INFO("pcr: %zu", out_pcr.value.len);
			out_pcr.has_number = true;
			out_pcr.number = i;
			out_pcrs[i] = mem_alloc(sizeof(Pcr));
			memcpy(out_pcrs[i], &out_pcr, sizeof(Pcr));
		}

		out.has_atype = true;
		out.atype = msg->atype;
		out.halg = tpm2d_rcontrol_hash_algo_get_len_proto(quote->halg_id);
		out.has_quoted = true;
		out.quoted.data = quote->quoted_value;
		out.quoted.len = quote->quoted_size;
		out.has_signature = true;
		out.signature.data = quote->signature_value;
		out.signature.len = quote->signature_size;

		out.n_pcr_values = pcr_regs;
		out.pcr_values = out_pcrs;

		out.has_certificate = true;
		out.certificate.data = attestation_cert;
		out.certificate.len = att_cert_len;

		out.ml_entry = ml_get_measurement_list_strings_new(&out.n_ml_entry);

		DEBUG("Received INTERNAL_ATTESTATION_RES, now sending reply");
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
err_att_req:
		for (size_t i=0; i< out.n_ml_entry; ++i) {
			mem_free(out.ml_entry[i]);
		}

		if (pcr_array)
			for (int i=0; i < pcr_regs; ++i) {
				if (pcr_array[i])
					tpm2_pcrread_free(pcr_array[i]);
				if (out_pcrs && out_pcrs[i])
					mem_free(out_pcrs[i]);
			}
		if (out_pcrs)
			mem_free(out_pcrs);
		if (pcr_array)
			mem_free(pcr_array);
		if (quote)
			tpm2_quote_free(quote);
		if (attestation_cert)
			mem_free(attestation_cert);
	} break;
	default:
		WARN("RemoteToTpm2d command %d unknown or not implemented yet", msg->code);
		break;
	}
}

/**
 * Event callback for incoming data that a ControllerToTpm message.
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd	    file descriptor of the client connection
 *		    from which the incoming message is read
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this tpm2d_rcontrol_t struct
 */
static void
tpm2d_rcontrol_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_rcontrol_t *rcontrol = data;
	ASSERT(rcontrol);

	if (events & EVENT_IO_READ) {
		RemoteToTpm2d *msg = (RemoteToTpm2d *)protobuf_recv_message(fd, &remote_to_tpm2d__descriptor);
		if (NULL == msg) {
			WARN("Failed to receive and decode RemoteToTpm2d protobuf message on sock %d!", fd);
		} else {
			tpm2d_rcontrol_handle_message(msg, fd, rcontrol);
			protobuf_free_message((ProtobufCMessage *)msg);
			DEBUG("Handled remote control connection %d", fd);
			return;
		}
	}
	if (events & EVENT_IO_EXCEPT) {
		event_remove_io(io);
		event_io_free(io);
		close(fd);
		return;
	}
}
/**
 * Event callback for accepting incoming connections on the listening socket.
 *
 * @param fd	    file descriptor of the listening socket
 *		    from which incoming connectionis should be accepted
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this tpm2d_rcontrol_t struct
  */
static void
tpm2d_rcontrol_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_rcontrol_t *rcontrol = data;
	ASSERT(rcontrol);
	ASSERT(rcontrol->sock == fd);

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept remote control connection");
		return;
	}
	DEBUG("Accepted remote control connection %d", cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, tpm2d_rcontrol_cb_recv_message, rcontrol);
	event_add_io(event);
}

tpm2d_rcontrol_t *
tpm2d_rcontrol_new(const char *ip, int port)
{
	int sock = sock_inet_create_and_bind(SOCK_STREAM, ip, port);
	IF_TRUE_RETVAL(sock < 0, NULL);
	IF_TRUE_RETVAL(listen(sock, SOMAXCONN) < 0, NULL);

	DEBUG("Listening on remote control socket (%s:%d)", ip, port);

	tpm2d_rcontrol_t *tpm2d_rcontrol = mem_new0(tpm2d_rcontrol_t, 1);
	tpm2d_rcontrol->sock = sock;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, tpm2d_rcontrol_cb_accept, tpm2d_rcontrol);
	event_add_io(event);

	return tpm2d_rcontrol;
}

