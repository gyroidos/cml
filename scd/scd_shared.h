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

#ifndef SCD_SHARED_H
#define SCD_SHARED_H

#define PROVISIONING_MODE_FILE "/tmp/_provisioning_"

#ifndef DEFAULT_BASE_PATH
#define DEFAULT_BASE_PATH "/data/cml"
#endif
#ifndef DEFAULT_CONF_BASE_PATH
#define DEFAULT_CONF_BASE_PATH "/data/cml"
#endif
#ifndef LOGFILE_DIR
#define LOGFILE_DIR "/data/logs"
#endif

// Do not edit! The provisioning script requires this path (also trustme-main.mk and its dummy provsg folder)
#define SCD_TOKEN_DIR DEFAULT_BASE_PATH "/tokens"
#define SSIG_ROOT_CERT SCD_TOKEN_DIR "/ssig_rootca.cert"
#define LOCALCA_ROOT_CERT SCD_TOKEN_DIR "/localca_rootca.cert"
#define TRUSTED_CA_STORE SCD_TOKEN_DIR "/ca"

#define DEVICE_CERT_FILE SCD_TOKEN_DIR "/device.cert"
#define DEVICE_CSR_FILE SCD_TOKEN_DIR "/device.csr"
// Only used on platforms without TPM, otherwise TPM-bound key is used
#define DEVICE_KEY_FILE SCD_TOKEN_DIR "/device.key"

#endif // SCD_SHARED_H