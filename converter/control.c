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

#ifdef ANDROID
#include "device/fraunhofer/common/cml/control/control.pb-c.h"
#else
#include "control.pb-c.h"
#endif

#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/file.h"

#include <stdbool.h>
#include <unistd.h>

#define CONTROL_SOCKET SOCK_PATH(control)

static int
send_message(ControllerToDaemon *msg)
{
	int sock = sock_unix_create_and_connect(SOCK_STREAM, CONTROL_SOCKET);
	IF_TRUE_RETVAL(sock < 0, -1);
	ssize_t msg_size = protobuf_send_message(sock, (ProtobufCMessage *)msg);
	if (msg_size < 0)
		ERROR("error sending message");

	close(sock);
	return (msg_size < 0) ? -1 : 0;
}

bool
control_is_enabled(void)
{
	return file_is_socket(CONTROL_SOCKET);
}

int
control_push_guestos(char *cfgfile, char *certfile, char *sigfile)
{
	int ret = -1;
	uint8_t *cfg = NULL;
	uint8_t *sig = NULL;
	uint8_t *cert = NULL;
	off_t cfglen = file_size(cfgfile);
	if (cfglen < 0) {
		ERROR("Error accessing config file %s.", cfgfile);
		return ret;
	}

	off_t siglen = file_size(sigfile);
	if (siglen < 0) {
		ERROR("Error accessing signature file %s.", sigfile);
		return ret;
	}

	off_t certlen = file_size(certfile);
	if (certlen < 0) {
		ERROR("Error accessing certificate file %s.", certfile);
		return ret;
	}

	cfg = mem_alloc(cfglen);
	if (file_read(cfgfile, (char *)cfg, cfglen) < 0) {
		ERROR("Error reading %s.", cfgfile);
		goto out;
	}
	sig = mem_alloc(siglen);
	if (file_read(sigfile, (char *)sig, siglen) < 0) {
		ERROR("Error reading %s.", sigfile);
		goto out;
	}
	cert = mem_alloc(certlen);
	if (file_read(certfile, (char *)cert, certlen) < 0) {
		ERROR("Error reading %s.", certfile);
		goto out;
	}
	INFO("Pushing cfg %s (len %zu), sig %s (len %zu), and cert %s (len %zu).", cfgfile, (size_t)cfglen, sigfile,
	     (size_t)siglen, certfile, (size_t)certlen);

	// build ControllerToDaemon message
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;

	msg.command = CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG;
	msg.has_guestos_config_file = true;
	msg.guestos_config_file.len = cfglen;
	msg.guestos_config_file.data = cfg;
	msg.has_guestos_config_signature = true;
	msg.guestos_config_signature.len = siglen;
	msg.guestos_config_signature.data = sig;
	msg.has_guestos_config_certificate = true;
	msg.guestos_config_certificate.len = certlen;
	msg.guestos_config_certificate.data = cert;

	ret = send_message(&msg);
out:
	if (cfg)
		mem_free(cfg);
	if (sig)
		mem_free(sig);
	if (cert)
		mem_free(cert);
	return ret;
}

int
control_register_localca(char *ca_cert_file)
{
	int ret = -1;
	off_t ca_cert_len = file_size(ca_cert_file);
	if (ca_cert_len < 0) {
		ERROR("Error accessing certificate file %s.", ca_cert_file);
		return ret;
	}
	uint8_t *ca_cert = mem_alloc(ca_cert_len);
	if (file_read(ca_cert_file, (char *)ca_cert, ca_cert_len) < 0) {
		ERROR("Error reading %s.", ca_cert_file);
		goto out;
	}
	INFO("Registering Local CA by cert %s (len %zu).", ca_cert_file, (size_t)ca_cert_len);

	// build ControllerToDaemon message
	ControllerToDaemon msg = CONTROLLER_TO_DAEMON__INIT;
	msg.command = CONTROLLER_TO_DAEMON__COMMAND__REGISTER_LOCALCA;
	msg.has_guestos_rootcert = true;
	msg.guestos_rootcert.len = ca_cert_len;
	msg.guestos_rootcert.data = ca_cert;

	ret = send_message(&msg);
out:
	if (ca_cert)
		mem_free(ca_cert);
	return ret;
}
