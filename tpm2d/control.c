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

#include "control.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/tpm2d/tpm2d.pb-c.h"
#else
#include "tpm2d.pb-c.h"
#endif

#include "tpm2d.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/sock.h"
#include "common/fd.h"
#include "common/event.h"
#include "common/list.h"
#include "common/file.h"
#include "common/protobuf.h"

#include "protobuf-c-text/protobuf-c-text.h"

// maximum no. of connections waiting to be accepted on the listening socket
#define TPM2D_CONTROL_SOCK_LISTEN_BACKLOG 8

struct tpm2d_control {
	int sock;		// listen socket fd
	TPMI_DH_OBJECT attestation_key_handle;
};

UNUSED static list_t *control_list = NULL;

static void
tpm2d_control_handle_message(const ControllerToTpm *msg, int fd, tpm2d_control_t *control)
{
	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text = protobuf_c_text_to_string((ProtobufCMessage *)msg, NULL);
		TRACE("Handling ControllerToTpm message:\n%s", msg_text ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	switch(msg->code) {
	case CONTROLLER_TO_TPM__CODE__INTERNAL_ATTESTATION_REQ: {
		Pcr **out_pcrs = NULL;
		int pcr_regs = 0;
		int pcr_indices = 0;
		tpm2d_pcr_strings_t** pcr_strings_array = NULL;
		tpm2d_quote_strings_t *quote_strings = NULL;
		char *attestation_pub_key = NULL;

		TpmToController out = TPM_TO_CONTROLLER__INIT;
		out.code = TPM_TO_CONTROLLER__CODE__INTERNAL_ATTESTATION_RES;

		switch (msg->atype) {
			case IDS_ATTESTATION_TYPE__BASIC:
				TRACE("atype BASIC");
				pcr_regs = 11;
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

		pcr_strings_array = mem_alloc0(sizeof(tpm2d_pcr_strings_t*) * pcr_regs);
		for (int i=0; i < pcr_regs; ++i) {
			pcr_strings_array[i] = tpm2_pcrread_new(i, TPM2D_HASH_ALGORITHM);

			IF_NULL_GOTO_ERROR(pcr_strings_array[i], err_att_req);
			TRACE("PCR%d: %s", i, pcr_strings_array[i]->pcr_str);
		}

		quote_strings = tpm2_quote_new(pcr_indices,
				control->attestation_key_handle, TPM2D_ATTESTATION_KEY_PW, msg->qualifyingdata);
		IF_NULL_GOTO_ERROR(quote_strings, err_att_req);

		attestation_pub_key = tpm2_read_file_to_hex_string_new(TPM2D_ATTESTATION_PUB_FILE);
		IF_NULL_GOTO_ERROR(attestation_pub_key, err_att_req);

		Pcr out_pcr = PCR__INIT;
		out_pcrs = mem_new(Pcr *, pcr_regs);
		for (int i=0; i < pcr_regs; ++i) {
			out_pcr.value = pcr_strings_array[i]->pcr_str;
			out_pcr.has_number = true;
			out_pcr.number = i;
			out_pcrs[i] = mem_alloc(sizeof(Pcr));
			memcpy(out_pcrs[i], &out_pcr, sizeof(Pcr));
		}

		out.has_atype = true;
		out.atype = msg->atype;
		out.halg = quote_strings->halg_str;
		out.quoted = quote_strings->quoted_str;
		out.signature = quote_strings->signature_str;
		out.n_pcr_values = pcr_regs;
		out.pcr_values = out_pcrs;

		out.certificate_uri = attestation_pub_key;

		DEBUG("Received INTERNAL_ATTESTATION_RES, now sending reply");
		protobuf_send_message(fd, (ProtobufCMessage *)&out);
err_att_req:
		if (pcr_strings_array)
			for (int i=0; i < pcr_regs; ++i) {
				if (pcr_strings_array[i])
					tpm2_pcrread_free(pcr_strings_array[i]);
				if (out_pcrs && out_pcrs[i])
					mem_free(out_pcrs[i]);
			}
		if (out_pcrs)
			mem_free(out_pcrs);
		if (pcr_strings_array)
			mem_free(pcr_strings_array);
		if (quote_strings)
			tpm2_quote_free(quote_strings);
		if (attestation_pub_key)
			mem_free(attestation_pub_key);
	} break;
	default:
		WARN("ControllerToTpm command %d unknown or not implemented yet", msg->code);
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
 * @param data	    pointer to this tpm2d_control_t struct
 */
static void
tpm2d_control_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_control_t *control = data;
	ASSERT(control);

	if (events & EVENT_IO_READ) {
		ControllerToTpm *msg = (ControllerToTpm *)protobuf_recv_message(fd, &controller_to_tpm__descriptor);
		if (NULL == msg) {
			WARN("Failed to receive and decode ControllerToTpm protobuf message on sock %d!", fd);
		} else {
			tpm2d_control_handle_message(msg, fd, control);
			protobuf_free_message((ProtobufCMessage *)msg);
			DEBUG("Handled control connection %d", fd);
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
 * @param data	    pointer to this tpm2d_control_t struct
  */
static void
tpm2d_control_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	tpm2d_control_t *control = data;
	ASSERT(control);
	ASSERT(control->sock == fd);

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept control connection");
		return;
	}
	DEBUG("Accepted control connection %d", cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, tpm2d_control_cb_recv_message, control);
	event_add_io(event);
}

tpm2d_control_t *
tpm2d_control_new(const char *path, uint32_t as_key_handle)
{
	int sock = sock_unix_create_and_bind(SOCK_STREAM | SOCK_NONBLOCK, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	if (listen(sock, TPM2D_CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	tpm2d_control_t *tpm2d_control = mem_new0(tpm2d_control_t, 1);
	tpm2d_control->sock = sock;
	tpm2d_control->attestation_key_handle = as_key_handle;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, tpm2d_control_cb_accept, tpm2d_control);
	event_add_io(event);

	return tpm2d_control;
}

