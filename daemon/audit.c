/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "audit.h"

#include "cmld.h"
#include "smartcard.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/str.h"
#include "common/macro.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/protobuf.h"

#include <string.h>
#include <time.h>
#include <google/protobuf-c/protobuf-c-text.h>

//TODO implement ACK mechanism fpr all service messages inside c-service.c?
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/c_service.pb-c.h"
#else
#include "c_service.pb-c.h"
#endif

#define AUDIT_HASH_ALGO SHA512
#define AUDIT_HASH_ALGO_LEN 64

#define AUDIT_DEFAULT_CONTAINER "00000000-0000-0000-0000-000000000000"

#define AUDIT_DELIMITER "-----\n"

#undef LOGF_LOG_MIN_PRIO
#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define AUDIT_LOGDIR "/data/audit"

uint64_t AUDIT_STORAGE = 0;

const char *evcategory[] = { "SUA", "FUA", "SSA", "FSA", "RLE" };
const char *evclass[] = { "GUESTOS_MGMT", "TOKEN_MGMT", "CONTAINER_MGMT", "CONTAINER_ISOLATION",
			  "TPM_COMM" };
const char *severity[] = { "INFO", "WARN", "ERROR", "FATAL" };
const char *component[] = { "CMLD", "SCD", "TPM2D" };
const char *result[] = { "SUCCESS", "FAIL" };

static AUDIT_MODE LOGMODE = CONTAINER;

typedef struct {
	char *key;
	char *value;
} audit_meta_t;

static container_t *
audit_get_log_container(const uuid_t *uuid)
{
	container_t *c = NULL;

	if (uuid && LOGMODE == CONTAINER) {
		c = cmld_container_get_by_uuid(uuid);
	}

	if (!c) {
		c = cmld_containers_get_a0();
	}

	return c;
}

char *
audit_log_file_new(const char *uuid)
{
	if (C0 == LOGMODE)
		return mem_printf("%s/%s.log", AUDIT_LOGDIR, AUDIT_DEFAULT_CONTAINER);
	else
		return mem_printf("%s/%s.log", AUDIT_LOGDIR, uuid);
}

static uint64_t
audit_remaining_storage(const char *uuid)
{
	char *file = audit_log_file_new(uuid);
	off_t size = file_size(file);

	mem_free(file);

	if (!file_exists(file)) {
		return AUDIT_STORAGE;
	}

	if (0 > size) {
		ERROR_ERRNO("Failed to retrieve size of audit log file");
		return 0;
	}

	if ((uint64_t)size > AUDIT_STORAGE) {
		ERROR("Detected audit log overflow");
		return 0;
	}

	return AUDIT_STORAGE - size;
}

const char *
audit_result_to_string(AUDIT_RESULT c)
{
	return result[c];
}

const char *
audit_category_to_string(AUDIT_CATEGORY c)
{
	return evcategory[c];
}

const char *
audit_evclass_to_string(AUDIT_EVENTCLASS c)
{
	return evclass[c];
}

const char *
audit_severity_to_string(AUDIT_SEVERITY s)
{
	return severity[s];
}

const char *
audit_component_to_string(AUDIT_COMPONENT c)
{
	return component[c];
}

static void
audit_send_record_cb(const char *hash_string, const char *hash_file,
		     UNUSED smartcard_crypto_hashalgo_t hash_algo, void *data)
{
	if (!hash_string) {
		ERROR("audit_send_record_cb: hash_string was empty");
		return;
	}

	if (!hash_file) {
		ERROR("audit_send_record_cb: hash_file was empty");
		return;
	}

	if (!data) {
		ERROR("audit_send_record_cb: No container given");
		return;
	}

	const container_t *c = (const container_t *)data;
	ASSERT(c);

	uint32_t buf_len = file_size(hash_file);
	uint8_t *buf = mem_alloc0(buf_len);

	int read = file_read(hash_file, (char *)buf, buf_len);

	if (read < 0 || buf_len != (unsigned int)read) {
		ERROR("Processing SCD response: read %u bytes, expected %u", read, buf_len);
		goto out;
	}

	TRACE("Got hash from SCD for file %s: %s", hash_file, hash_string);

	container_audit_set_processing_ack(c, false);

	if (unlink(hash_file)) {
		ERROR_ERRNO("Failed to unlink %s", hash_file);
	}

	if (0 > container_audit_record_send(c, buf, buf_len)) {
		ERROR("Failed to send audit record to container");
		goto out;
	}

	container_audit_set_last_ack(c, mem_strdup(hash_string));
	TRACE("Sent audit record with ID %s to container %s", container_audit_get_last_ack(c),
	      uuid_string(container_get_uuid(c)));
	//sleep(30);

out:
	mem_free(buf);
}

void
audit_record_free(AuditRecord *record)
{
	ASSERT(record);

	if (record->type)
		mem_free(record->type);

	if (record->subject_id)
		mem_free(record->subject_id);

	if (record->meta)
		mem_free(record->meta);

	mem_free(record);
}

static AuditRecord *
audit_record_new(AUDIT_CATEGORY category, AUDIT_COMPONENT component, AUDIT_EVENTCLASS evclass,
		 const char *evtype, const char *subject_id, int meta_length,
		 AuditRecord__Meta **metas)
{
	AuditRecord *s = mem_new0(AuditRecord, 1);

	audit_record__init(s);

	char *type = mem_printf("%s.%s.%s.%s", audit_category_to_string(category),
				audit_component_to_string(component),
				audit_evclass_to_string(evclass), evtype);
	s->timestamp = time(NULL);

	if (EFAULT == errno) {
		ERROR_ERRNO("Failed to get current time");
		return NULL;
	}

	s->type = type;

	if (subject_id)
		s->subject_id = mem_strdup(subject_id);

	s->n_meta = meta_length;
	s->meta = metas;

	return s;
}

static AuditRecord *
audit_record_from_textfile_new(const char *filename, const ProtobufCMessageDescriptor *descriptor,
			       bool purge)
{
	ASSERT(filename);
	ASSERT(descriptor);

	FILE *file = fopen(filename, "r");
	if (!file) {
		WARN_ERRNO("Could not open file \"%s\" for reading.", filename);
		return NULL;
	}

	ssize_t size = file_size(filename);

	if (0 > size) {
		ERROR("Failed to retrieve size of audit record log");
		return NULL;
	}

	// read file up to delimiter
	char *buf = mem_alloc0(size + 1);
	size_t read = 0;
	bool delim_found = false;

	while (!delim_found && read < (size_t)size) {
		ssize_t current = 0;
		size_t n = 0;
		char *line = NULL;

		if (0 > (current = getline(&line, &n, file))) {
			ERROR_ERRNO("Failed to read line from file");
			fclose(file);
			goto out;
		}

		if (read + current > (size_t)size) {
			ERROR("File was changed while reading");
			fclose(file);
			goto out;
		}

		// if delimiter line was read, stop further processing
		if (!strcmp(AUDIT_DELIMITER, line)) {
			delim_found = true;
			continue;
		}

		memcpy(buf + read, line, current);
		read += current;
	}
	fclose(file);

	// parse record from file
	AuditRecord *record;
	if (0 == size) {
		INFO("Read audit record with default values");
		record = (AuditRecord *)mem_new0(AuditRecord, 1);
		audit_record__init(record);
		goto out;
	} else {
		record = (AuditRecord *)protobuf_message_new_from_buf((uint8_t *)buf, read,
								      descriptor);
	}

	if (!record) {
		ERROR("Failed to parse text protobuf message (%s) from file \"%s\".",
		      descriptor->name ? descriptor->name : "UNKNOWN", filename);
		goto out;
	}

	if (purge) {
		// delete record from file
		if (read + strlen(AUDIT_DELIMITER) == (size_t)size) {
			DEBUG("Audit log empty, removing file");
			if (-1 == unlink(filename)) {
				ERROR_ERRNO("Failed to remove audit log file");
			}
			goto out;
		}

		char *filebuf = file_read_new(filename, AUDIT_STORAGE);

		if (!filebuf) {
			ERROR("Failed to read audit log file");
			goto out;
		}

		size_t offset = read + strlen(AUDIT_DELIMITER);
		if (-1 == file_write(filename, filebuf + offset, strlen(filebuf + offset))) {
			ERROR_ERRNO("Failed to remove message from file: %s", filename);
		}
		mem_free(filebuf);
	}

out:
	if (buf)
		mem_free(buf);

	return (AuditRecord *)record;
}

static int
audit_write_file(const uuid_t *uuid, const AuditRecord *msg)
{
	int ret = -1;

	char *dir = mem_printf("%s/audit", AUDIT_LOGDIR);

	if (!file_is_dir(dir) && dir_mkdir_p(dir, 0600)) {
		ERROR("Failed to create logdir");
		mem_free(dir);
		return -1;
	}
	mem_free(dir);

	char *file = audit_log_file_new(uuid_string(uuid));

	char *msg_text = protobuf_c_text_to_string((ProtobufCMessage *)msg, NULL);

	//TODO send error message
	if (audit_remaining_storage(uuid_string(uuid)) <
	    (strlen(msg_text) + strlen(AUDIT_DELIMITER))) {
		container_t *c = cmld_container_get_by_uuid(uuid);

		TRACE("Trying to notify container %s about stored audit events, remaining storage: %ld",
		      (uuid_string(uuid)), audit_remaining_storage(uuid_string(uuid)));
		if ((!c) || (-1 == container_audit_record_notify(
					   c, audit_remaining_storage(uuid_string(uuid))))) {
			ERROR("Failed to notify container about audit log overflow");
		}
		ERROR("Failed to store audit record: max. log size exceeded");
		goto out;
	}

	TRACE("Logging audit record to file: %s", file);
	if (0 > file_write_append(file, msg_text, strlen(msg_text))) {
		ERROR("Failed to log audit message to file: %s", file);
		goto out;
	}

	if (0 > file_write_append(file, "-----\n", strlen("-----\n"))) {
		ERROR("Failed to log audit message to file: %s", msg_text);
		goto out;
	}

	ret = 0;

out:
	mem_free(file);

	return ret;
}

static AuditRecord *
audit_next_record_new(const container_t *c, bool purge)
{
	AuditRecord *r = NULL;

	char *file = audit_log_file_new(uuid_string(container_get_uuid(c)));

	if (file_exists(file)) {
		r = (AuditRecord *)audit_record_from_textfile_new(file, &audit_record__descriptor,
								  purge);

		if (!r) {
			ERROR("Failed to read audit record");
			goto out;
		}

		TRACE("Read audit record %s from file",
		      protobuf_c_text_to_string((ProtobufCMessage *)r, NULL) ?
			      protobuf_c_text_to_string((ProtobufCMessage *)r, NULL) :
			      "<broken>");
	}

out:
	mem_free(file);

	return r;
}

static int
audit_do_send_record(const container_t *c, AuditRecord *record)
{
	int ret = -1;

	char tmpfile[strlen(AUDIT_LOGDIR) + 14];
	if (0 >= sprintf(tmpfile, "%s/%s", AUDIT_LOGDIR, "audit_XXXXXX")) {
		ERROR_ERRNO("Failed to prepare temporary filename");
		return -1;
	}

	if (!strcmp("", mktemp(tmpfile))) {
		ERROR_ERRNO("Failed to generate temporary filename");
		return -1;
	}

	CmldToServiceMessage *message_proto = mem_new0(CmldToServiceMessage, 1);
	cmld_to_service_message__init(message_proto);
	message_proto->code = CMLD_TO_SERVICE_MESSAGE__CODE__AUDIT_RECORD;

	message_proto->audit_record = record;

	uint8_t *packed;
	uint32_t packed_len = protobuf_pack_message_new((ProtobufCMessage *)message_proto, &packed);

	//	audit_record_free(record);
	//	mem_free(message_proto);

	protobuf_free_message((ProtobufCMessage *)message_proto);

	if (!packed) {
		ERROR("Failed to pack protobuf message");
		goto out;
	}

	if (-1 == file_write(tmpfile, (char *)packed, packed_len)) {
		ERROR("Failed to write packed message to file.");
		mem_free(packed);
		goto out;
	}
	mem_free(packed);

	TRACE("Requesting scd to hash serialized protobuf message at %s", tmpfile);

	// this state is needed s.t. additional ACKs from container arriving while scd is hashing the file
	// do not lead to multiple transmissions of the same record
	container_audit_set_processing_ack(c, true);

	if (smartcard_crypto_hash_file(tmpfile, AUDIT_HASH_ALGO, audit_send_record_cb, (void *)c)) {
		container_audit_set_processing_ack(c, false);
		str_t *dump = str_hexdump_new((unsigned char *)packed, (int)packed_len);
		ERROR("Failed to request hashing of record to be sent with length %u: %s.",
		      packed_len, str_buffer(dump));
		mem_free(dump);
	}

	ret = 0;
out:

	return ret;
}

static int
audit_send_next_stored(const container_t *c)
{
	if (!c)
		return -1;

	char *file = audit_log_file_new(uuid_string(container_get_uuid(c)));

	if (!file_exists(file)) {
		DEBUG("Sent all stored audit messages");
		mem_free(file);

		if (0 > container_audit_notify_complete(c)) {
			ERROR("Failed to notify container that all records were sent");
			return -1;
		}

		container_audit_set_last_ack(c, NULL);
		container_audit_set_processing_ack(c, false);

		return 0;
	}
	mem_free(file);

	AuditRecord *record;
	if (!(record = audit_next_record_new(c, false))) {
		ERROR("Could not read next audit record");
		return -1;
	}

	if (audit_do_send_record(c, record)) {
		ERROR("Failed to send next stored audit record");
		mem_free(record);
		return -1;
	}
	mem_free(record);

	return 0;
}

int
audit_process_ack(const container_t *c, const char *ack)
{
	ASSERT(c);

	if (!AUDIT_STORAGE) {
		DEBUG("Got ACK from container but AUDIT_STORAGE is zero, ignoring...");
		return 0;
	}

	if (C0 == LOGMODE && strcmp(AUDIT_DEFAULT_CONTAINER, uuid_string(container_get_uuid(c)))) {
		DEBUG("Got ACK from container %s, but LOGMODE is C0, ignoring...",
		      uuid_string(container_get_uuid(c)));
		return -1;
	}

	if (!ack) {
		ERROR("Got audit ACK missing hash from container %s",
		      uuid_string(container_get_uuid(c)));
	}

	if (container_audit_get_processing_ack(c)) {
		TRACE("Already processing ACK for container %s, ignoring additional ACK",
		      uuid_string(container_get_uuid(c)));
		return 0;
	}

	TRACE("Got audit record ACK from container %s: %s", uuid_string(container_get_uuid(c)),
	      ack);

	if (match_hash(AUDIT_HASH_ALGO_LEN, container_audit_get_last_ack(c), ack)) {
		TRACE("ACK hash matched last sent record %s", container_audit_get_last_ack(c));

		AuditRecord *record = audit_next_record_new(c, true);

		if (!record) {
			ERROR("Failed to delete audit record %s", ack);
			return -1;
		}

		mem_free(record);
		TRACE("Cleaned up ack'ed record");

		container_audit_set_last_ack(c, mem_strdup(""));
	} else {
		WARN("ACK from container %s did not match last sent audit record, try to send last stored record again",
		     uuid_string(container_get_uuid(c)));
	}

	return audit_send_next_stored(c);
}

int
audit_log_event(const uuid_t *uuid, AUDIT_CATEGORY category, AUDIT_COMPONENT component,
		AUDIT_EVENTCLASS evclass, const char *evtype, const char *subject_id,
		int meta_count, ...)
{
	container_t *c = NULL;
	AuditRecord *record = NULL;
	AuditRecord__Meta **metas = NULL;
	int ret = 0;

	if (!AUDIT_STORAGE) {
		TRACE("Attempt to log audit message but AUDIT_STORAGE is zero, skipping...");
		return 0;
	}

	if (0 < meta_count) {
		if (0 != (meta_count % 2)) {
			ERROR("Odd number of variadic arguments, aborting...");
			return -1;
		}

		va_list ap;

		va_start(ap, meta_count);

		metas = mem_alloc0((meta_count / 2) * sizeof(AuditRecord__Meta *));
		for (int i = 0; i < meta_count / 2; i++) {
			metas[i] = mem_alloc0(sizeof(AuditRecord__Meta));

			audit_record__meta__init(metas[i]);

			metas[i]->key = mem_strdup(va_arg(ap, const char *));
			metas[i]->value = mem_strdup(va_arg(ap, const char *));
		}

		va_end(ap);
		meta_count /= 2;
	}

	record = audit_record_new(category, component, evclass, evtype, subject_id, meta_count,
				  metas);

	if (!record) {
		ERROR("Failed to create audit record");
		mem_free(metas);
		goto out;
	}

	DEBUG("Logging audit message %s",
	      protobuf_c_text_to_string((ProtobufCMessage *)record, NULL) ?
		      protobuf_c_text_to_string((ProtobufCMessage *)record, NULL) :
		      "");

	c = audit_get_log_container(uuid);

	if (c) {
		if (0 != (ret = audit_write_file(container_get_uuid(c), record))) {
			ERROR("Failed to store audit log for container %s to file",
			      uuid_string(container_get_uuid(c)));
			goto out;
		}
	} else {
		ERROR("No audit logging container available, will log to file %s",
		      AUDIT_DEFAULT_CONTAINER);
		uuid_t *default_uuid = uuid_new(AUDIT_DEFAULT_CONTAINER);
		if (0 != (ret = audit_write_file(default_uuid, record))) {
			ERROR("Failed to store audit log to file");
			uuid_free(default_uuid);
			goto out;
		}
		uuid_free(default_uuid);
	}

	if (c && (container_audit_get_processing_ack(c))) {
		TRACE("Already processing ACK, do not notify container again");
		goto out;
	}

	if (c && (CONTAINER_STATE_RUNNING == container_get_state(c))) {
		bool processing_ack = container_audit_get_processing_ack(c);
		if (!processing_ack &&
		    (-1 == container_audit_record_notify(c, audit_remaining_storage(uuid_string(
								    container_get_uuid(c)))))) {
			ERROR("Failed to notify container about new audit record");
		}
	}

out:
	//if (record)
	//	audit_record_free(record);
	protobuf_free_message((ProtobufCMessage *)record);

	return ret;
}

int
audit_set_size(uint32_t size)
{
	AUDIT_STORAGE = size * 1024 * 1024;

	return 0;
}
