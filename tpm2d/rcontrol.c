/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */
// #define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#include <sys/stat.h>

#include "rcontrol.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/tpm2d/attestation.pb-c.h"
#else
#include "attestation.pb-c.h"
#endif

#include "tpm2d.h"
#include "tpm2d_shared.h"
#include "ml.h"
#include "ek.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/file.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"

#include <google/protobuf-c/protobuf-c-text.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x)[0])

struct tpm2d_rcontrol {
	int sock; // listen ip socket fd
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
		char *msg_text;
		size_t msg_len =
			protobuf_string_from_message(&msg_text, (ProtobufCMessage *)msg, NULL);
		TRACE("Handling RemoteToTpmd message:\n%s", msg_len > 0 ? msg_text : "NULL");
		if (msg_text)
			mem_free0(msg_text);
	}

	tss2_init();

	switch (msg->code) {
	case REMOTE_TO_TPM2D__CODE__ATTESTATION_REQ: {
		Pcr **out_pcrs = NULL;
		tpm2d_pcr_t **pcr_array = NULL;
		tpm2d_quote_t *quote = NULL;
		uint8_t *attestation_cert = NULL;
		size_t att_cert_len = 0;
		uint8_t pcr_bitmap[3];
		int pcr_regs = 0;
		int index = 0;

		TPMI_DH_OBJECT att_key_handle = tpm2d_get_as_key_handle();
		if (att_key_handle == TPM_RH_NULL)
			goto err_att_req;

		Tpm2dToRemote out = TPM2D_TO_REMOTE__INIT;
		out.code = TPM2D_TO_REMOTE__CODE__ATTESTATION_RES;

		switch (msg->atype) {
		case IDS_ATTESTATION_TYPE__BASIC:
			TRACE("atype BASIC");
			pcr_regs = 12;
			for (int i = 0; i < pcr_regs; ++i) {
				pcr_bitmap[i / 8] |= 1 << (i % 8);
			}
			break;
		case IDS_ATTESTATION_TYPE__ALL:
			TRACE("atype ALL");
			pcr_regs = 24;
			for (int i = 0; i < pcr_regs; ++i) {
				pcr_bitmap[i / 8] |= 1 << (i % 8);
			}
			break;
		case IDS_ATTESTATION_TYPE__ADVANCED:
			TRACE("atype ADVANCED");
			memcpy(pcr_bitmap, &msg->pcrs, sizeof(pcr_bitmap));
			for (size_t i = 0; i < ARRAY_SIZE(pcr_bitmap); i++) {
				for (size_t j = 0; j < 8; j++) {
					if (pcr_bitmap[i] & (1 << j)) {
						pcr_regs++;
					}
				}
			}
			break;
		default:
			goto err_att_req;
			break;
		}

		pcr_array = mem_alloc0(
			MUL_WITH_OVERFLOW_CHECK((size_t)sizeof(tpm2d_pcr_t *), pcr_regs));
		index = 0;
		for (int i = 0; i < (int)ARRAY_SIZE(pcr_bitmap); ++i) {
			for (int j = 0; j < 8; j++) {
				if (pcr_bitmap[i] & (1 << j)) {
					int pcr_num = i * 8 + j;
					pcr_array[index] =
						tpm2_pcrread_new(pcr_num, TPM2D_HASH_ALGORITHM);
					IF_NULL_GOTO_ERROR(pcr_array[index], err_att_req);
					INFO("PCR%d: size %zu", pcr_num,
					     pcr_array[index]->pcr_size);
					index++;
				}
			}
		}

		quote = tpm2_quote_new(pcr_bitmap, sizeof(pcr_bitmap), att_key_handle,
				       TPM2D_ATT_KEY_PW, msg->qualifyingdata.data,
				       msg->qualifyingdata.len);
		IF_NULL_GOTO_ERROR(quote, err_att_req);

		// add device certificate to quote
		FILE *fp;
		struct stat stat_buf;
		if (!(fp = fopen(TPM2D_ATT_CERT_FILE, "rb"))) {
			ERROR("Error opening device cert file");
			goto err_att_req;
		}
		if (fstat(fileno(fp), &stat_buf) == -1) {
			ERROR("Error accessing device cert file");
			fclose(fp);
			goto err_att_req;
		}
		att_cert_len = stat_buf.st_size;
		attestation_cert = mem_new(uint8_t, att_cert_len);

		if ((fread(attestation_cert, sizeof(uint8_t), att_cert_len, fp)) != att_cert_len) {
			ERROR("Error reading out device cert file");
			fclose(fp);
			goto err_att_req;
		}
		fclose(fp);

		IF_NULL_GOTO_ERROR(attestation_cert, err_att_req);
		INFO("att cert done: size=%zu", att_cert_len);

		Pcr out_pcr = PCR__INIT;
		out_pcrs = mem_new(Pcr *, pcr_regs);
		index = 0;
		for (int i = 0; i < (int)ARRAY_SIZE(pcr_bitmap); ++i) {
			for (int j = 0; j < 8; j++) {
				if (pcr_bitmap[i] & (1 << j)) {
					out_pcr.has_value = true;
					out_pcr.value.data = pcr_array[index]->pcr_value;
					out_pcr.value.len = pcr_array[index]->pcr_size;
					out_pcr.has_number = true;
					out_pcr.number = (i * 8) + j;
					INFO("PCR_%d: %zu", index, out_pcr.value.len);
					out_pcrs[index] = mem_alloc(sizeof(Pcr));
					memcpy(out_pcrs[index], &out_pcr, sizeof(Pcr));
					index++;
				}
			}
		}

		out.has_atype = true;
		out.atype = msg->atype;
		out.has_halg = true;
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

		if (msg->attest_ima) {
			out.has_ml_ima_entry = true;
			out.ml_ima_entry.data = ml_get_ima_list_new(&out.ml_ima_entry.len);
			if (!out.ml_ima_entry.data) {
				WARN("Failed to retrieve IMA measurement list");
				goto err_att_req;
			}
		} else {
			out.has_ml_ima_entry = false;
		}

		if (msg->attest_containers) {
			out.ml_container_entry =
				ml_get_container_list_new(&out.n_ml_container_entry);
			if (!out.ml_container_entry) {
				WARN("Failed to retrieve container measurement list");
				goto err_att_req;
			}
		} else {
			out.n_ml_container_entry = 0;
		}

		DEBUG("Received INTERNAL_ATTESTATION_RES, now sending reply");
		protobuf_send_message(fd, (ProtobufCMessage *)&out);

		mem_free0(out.ml_ima_entry.data);
		ml_container_list_free(out.ml_container_entry, out.n_ml_container_entry);

	err_att_req:
		tpm2d_flush_as_key_handle();

		if (pcr_array)
			for (int i = 0; i < pcr_regs; ++i) {
				if (pcr_array[i])
					tpm2_pcrread_free(pcr_array[i]);
				if (out_pcrs && out_pcrs[i])
					mem_free0(out_pcrs[i]);
			}
		if (out_pcrs)
			mem_free0(out_pcrs);
		if (pcr_array)
			mem_free0(pcr_array);
		if (quote)
			tpm2_quote_free(quote);
		if (attestation_cert)
			mem_free0(attestation_cert);
	} break;
	default:
		WARN("RemoteToTpm2d command %d unknown or not implemented yet", msg->code);
		break;
	}
	tss2_destroy();
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
		RemoteToTpm2d *msg =
			(RemoteToTpm2d *)protobuf_recv_message(fd, &remote_to_tpm2d__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);

		tpm2d_rcontrol_handle_message(msg, fd, rcontrol);
		protobuf_free_message((ProtobufCMessage *)msg);
		DEBUG("Handled remote control connection %d", fd);
	}
	if (events & EVENT_IO_EXCEPT) {
		INFO("Remote client closed connection; disconnecting rcontrol socket.");
		goto connection_err;
	}
	return;

connection_err:
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected rcontrol socket");
	return;
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

	event_io_t *event =
		event_io_new(cfd, EVENT_IO_READ, tpm2d_rcontrol_cb_recv_message, rcontrol);
	event_add_io(event);
}

static event_io_t *event;

tpm2d_rcontrol_t *
tpm2d_rcontrol_new(const char *ip, int port)
{
	int sock = sock_inet_create_and_bind(SOCK_STREAM, ip, port);
	IF_TRUE_RETVAL(sock < 0, NULL);
	IF_TRUE_RETVAL(listen(sock, SOMAXCONN) < 0, NULL);

	DEBUG("Listening on remote control socket (%s:%d)", ip, port);

	tpm2d_rcontrol_t *tpm2d_rcontrol = mem_new0(tpm2d_rcontrol_t, 1);
	tpm2d_rcontrol->sock = sock;

	event = event_io_new(sock, EVENT_IO_READ, tpm2d_rcontrol_cb_accept, tpm2d_rcontrol);
	event_add_io(event);

	return tpm2d_rcontrol;
}

void
tpm2d_rcontrol_free(tpm2d_rcontrol_t *rcontrol)
{
	event_remove_io(event);
	event_io_free(event);
	mem_free0(rcontrol);
}
