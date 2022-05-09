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
#include "crypto.h"

#include "common/audit.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/str.h"
#include "common/macro.h"
#include "common/dir.h"
#include "common/file.h"
#include "common/protobuf.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/nl.h"

#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <linux/audit.h>
#include <inttypes.h>
#include <google/protobuf-c/protobuf-c-text.h>

//TODO implement ACK mechanism fpr all service messages inside c-service.c?
#include "c_service.pb-c.h"

#ifndef AUDIT_DM_CTRL
#define AUDIT_DM_CTRL 1338
#endif
#ifndef AUDIT_DM_EVENT
#define AUDIT_DM_EVENT 1339
#endif

#define AUDIT_HASH_ALGO SHA512
#define AUDIT_HASH_ALGO_LEN 64

#define AUDIT_DEFAULT_CONTAINER "00000000-0000-0000-0000-000000000000"

#define AUDIT_DELIMITER "-----\n"

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#define AUDIT_LOGDIR "/data/audit"

uint64_t AUDIT_STORAGE = 0;

static AUDIT_MODE LOGMODE = CONTAINER;

typedef struct {
	char *key;
	char *value;
} audit_meta_t;

const char *evcategory[] = { "SUA", "FUA", "SSA", "FSA", "RLE" };
const char *evclass[] = { "GENERIC",	    "GUESTOS_MGMT",	   "TOKEN_MGMT",
			  "CONTAINER_MGMT", "CONTAINER_ISOLATION", "TPM_COMM",
			  "KAUDIT" };
const char *component[] = { "CMLD", "SCD", "TPM2D" };
const char *result[] = { "SUCCESS", "FAIL" };

static const char *
audit_category_to_string(AUDIT_CATEGORY c)
{
	return evcategory[c];
}

static const char *
audit_evclass_to_string(AUDIT_EVENTCLASS c)
{
	return evclass[c];
}

static const char *
audit_component_to_string(AUDIT_COMPONENT c)
{
	return component[c];
}

static container_t *
audit_get_log_container(const uuid_t *uuid)
{
	container_t *c = NULL;

	if (uuid && LOGMODE == CONTAINER) {
		c = cmld_container_get_by_uuid(uuid);
	}

	if (!c) {
		c = cmld_containers_get_c0();
	}

	return c;
}

static char *
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

	if (!file_exists(file)) {
		mem_free0(file);
		return AUDIT_STORAGE;
	}
	mem_free0(file);

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

static void
audit_send_record_cb(const char *hash_string, const char *hash_file,
		     UNUSED crypto_hashalgo_t hash_algo, void *data)
{
	uint8_t *buf = NULL;
	const container_t *c = (const container_t *)data;
	ASSERT(c);

	// callback is triggert twice for cleanup
	IF_NULL_RETURN_TRACE(hash_string);

	if (!hash_file) {
		ERROR("audit_send_record_cb: hash_file was empty");
		return;
	}

	if (!data) {
		ERROR("audit_send_record_cb: No container given");
		return;
	}

	uint32_t buf_len = file_size(hash_file);
	buf = mem_alloc0(buf_len);

	int read = file_read(hash_file, (char *)buf, buf_len);

	if (read < 0 || buf_len != (unsigned int)read) {
		ERROR("Processing SCD response: read %u bytes, expected %u", read, buf_len);
		goto out;
	}

	TRACE("Got hash from SCD for file %s: %s", hash_file, hash_string);

	if (unlink(hash_file)) {
		ERROR_ERRNO("Failed to unlink %s", hash_file);
	}

	char *old_acked = mem_strdup(container_audit_get_last_ack(c));
	container_audit_set_last_ack(c, hash_string);

	if (0 > container_audit_record_send(c, buf, buf_len)) {
		ERROR("Failed to send audit record to container");
		// rollback
		container_audit_set_last_ack(c, old_acked);
		mem_free0(old_acked);
		goto out;
	}
	mem_free0(old_acked);

	TRACE("Sent audit record with ID %s to container %s", container_audit_get_last_ack(c),
	      uuid_string(container_get_uuid(c)));

out:
	container_audit_set_processing_ack(c, false);
	mem_free0(buf);
}

static AuditRecord *
audit_record_from_textfile_new(const char *filename, bool purge)
{
	ASSERT(filename);

	TRACE("audit record from textfile using log '%s'", filename);

	FILE *file = fopen(filename, "r");
	if (!file) {
		WARN_ERRNO("Could not open file \"%s\" for reading.", filename);
		return NULL;
	}

	ssize_t size = file_size(filename);

	if (0 > size) {
		ERROR("Failed to retrieve size of audit record log '%s'", filename);
		fclose(file);
		return NULL;
	}

	AuditRecord *record = NULL;

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
			mem_free0(line);
			goto out;
		}

		if (read + current > (size_t)size) {
			ERROR("File was changed while reading");
			fclose(file);
			mem_free0(line);
			goto out;
		}

		// if delimiter line was read, stop further processing
		if (!strcmp(AUDIT_DELIMITER, line)) {
			delim_found = true;
			mem_free0(line);
			continue;
		}

		memcpy(buf + read, line, current);
		read += current;
		mem_free0(line);
	}
	fclose(file);

	// parse record from file
	if (0 == size) {
		INFO("Read audit record with default values");
		record = (AuditRecord *)mem_new0(AuditRecord, 1);
		audit_record__init(record);
		goto out;
	} else {
		record = (AuditRecord *)protobuf_message_new_from_buf((uint8_t *)buf, read,
								      &audit_record__descriptor);
	}

	if (!record) {
		WARN("Failed to parse text protobuf message (%s) from file \"%s\"."
		     "Generating new record with corrupted data as raw_text",
		     audit_record__descriptor.name ? audit_record__descriptor.name : "UNKNOWN",
		     filename);

		AuditRecord__Meta **meta = mem_new0(AuditRecord__Meta *, 1);
		meta[0] = mem_new0(AuditRecord__Meta, 1);
		audit_record__meta__init(meta[0]);

		// store corrput message as meta
		meta[0]->key = mem_strdup("raw_text");
		meta[0]->value = mem_strndup(buf, read);

		char *type = mem_printf("%s.%s.%s.%s", audit_category_to_string(FSA),
					audit_component_to_string(CMLD),
					audit_evclass_to_string(GENERIC), "corrupt-record");

		record = audit_record_new(type, NULL, 1, meta);
		mem_free0(type);
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
		mem_free0(filebuf);
	}

out:
	if (buf)
		mem_free0(buf);

	return (AuditRecord *)record;
}

static bool
audit_log_check_delimiter(const char *log_file)
{
	int fd = -1;
	char buf[sizeof(AUDIT_DELIMITER)];
	size_t log_file_size = 0;
	bool ret = false;

	IF_TRUE_RETVAL_TRACE(0 >= (log_file_size = file_size(log_file)), true);
	if (0 > (fd = open(log_file, O_RDONLY))) {
		TRACE_ERRNO("open failed by returning fd=%d", fd);
		return true;
	}

	IF_TRUE_GOTO_WARN(-1 == lseek(fd, -strlen(AUDIT_DELIMITER), SEEK_END), out);
	IF_TRUE_GOTO_WARN(-1 == fd_read(fd, buf, strlen(AUDIT_DELIMITER)), out);

	buf[sizeof(AUDIT_DELIMITER) - 1] = '\0';

	// if delimiter line was read, all is fine
	if (!strcmp(AUDIT_DELIMITER, buf))
		ret = true;

out:
	close(fd);
	return ret;
}

static int
audit_write_file(const uuid_t *uuid, const AuditRecord *msg)
{
	int ret = -1;

	char *dir = mem_printf("%s/audit", AUDIT_LOGDIR);

	if (!file_is_dir(dir) && dir_mkdir_p(dir, 0600)) {
		ERROR("Failed to create logdir");
		mem_free0(dir);
		return -1;
	}
	mem_free0(dir);

	char *file = audit_log_file_new(uuid_string(uuid));

	char *msg_text;
	size_t msg_len = protobuf_string_from_message(&msg_text, (ProtobufCMessage *)msg, NULL);

	//TODO send error message
	if (audit_remaining_storage(uuid_string(uuid)) < (msg_len + strlen(AUDIT_DELIMITER))) {
		container_t *c = cmld_container_get_by_uuid(uuid);

		TRACE("Trying to notify container %s about stored audit events,"
		      " remaining storage: %" PRIu64,
		      uuid_string(uuid), audit_remaining_storage(uuid_string(uuid)));
		if ((!c) || (-1 == container_audit_record_notify(
					   c, audit_remaining_storage(uuid_string(uuid))))) {
			ERROR("Failed to notify container about audit log overflow");
		}
		ERROR("Failed to store audit record: max. log size exceeded");
		goto out;
	}

	TRACE("Logging audit record to file: %s", file);
	if (!audit_log_check_delimiter(file)) {
		TRACE("Fixup audit delimiter to %s", file);
		if (0 > file_write_append(file, AUDIT_DELIMITER, strlen(AUDIT_DELIMITER))) {
			ERROR("Failed to fixup audit log file: %s", file);
			goto out;
		}
	}

	if (0 > file_write_append(file, msg_text, msg_len)) {
		ERROR("Failed to log audit message to file: %s", file);
		goto out;
	}

	if (0 > file_write_append(file, AUDIT_DELIMITER, strlen(AUDIT_DELIMITER))) {
		ERROR("Failed to log audit message to file: %s", msg_text);
		goto out;
	}

	ret = 0;

out:
	mem_free0(file);
	mem_free0(msg_text);

	return ret;
}

static AuditRecord *
audit_next_record_new(const container_t *container, bool purge)
{
	AuditRecord *r;

	char *file = audit_log_file_new(uuid_string(container_get_uuid(container)));
	TRACE("next record in log file '%s'", file);

	if (!file_exists(file)) {
		ERROR("Failed to read audit record: no file");
		mem_free0(file);
		return NULL;
	}

	r = (AuditRecord *)audit_record_from_textfile_new(file, purge);

	mem_free0(file);

	return r;
}

static int
audit_do_send_record(const container_t *c)
{
	uint8_t *packed = NULL;
	uint32_t packed_len = 0;
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

	if (!(message_proto->audit_record = audit_next_record_new(c, false))) {
		ERROR("Could not read next audit record");
		goto out;
	}
	TRACE("read next audit record sucessfully");

	packed_len = protobuf_pack_message_new((ProtobufCMessage *)message_proto, &packed);

	if (!packed) {
		ERROR("Failed to pack protobuf message");
		goto out;
	}

	if (-1 == file_write(tmpfile, (char *)packed, packed_len)) {
		ERROR("Failed to write packed message to file.");
		goto out;
	}

	TRACE("Requesting scd to hash serialized protobuf message at %s", tmpfile);

	// this state is needed s.t. additional ACKs from container arriving while scd is hashing the file
	// do not lead to multiple transmissions of the same record
	container_audit_set_processing_ack(c, true);

	if (crypto_hash_file(tmpfile, AUDIT_HASH_ALGO, audit_send_record_cb, (void *)c)) {
		container_audit_set_processing_ack(c, false);
		str_t *dump = str_hexdump_new((unsigned char *)packed, (int)packed_len);
		ERROR("Failed to request hashing of record to be sent with length %u: %s.",
		      packed_len, str_buffer(dump));
		mem_free0(dump);
	}

	TRACE("sent next stored audit record sucessfully");
	ret = 0;
out:
	if (ret < 0)
		ERROR("Failed to send next stored audit record");

	mem_free0(packed);
	protobuf_free_message((ProtobufCMessage *)message_proto);
	return ret;
}

static int
audit_send_next_stored(const container_t *c)
{
	if (!c)
		return -1;

	TRACE("send_next_stored");
	char *file = audit_log_file_new(uuid_string(container_get_uuid(c)));

	TRACE("send_next_stored log file: %s", file);

	if (!file_exists(file)) {
		DEBUG("Sent all stored audit messages");
		mem_free0(file);

		if (0 > container_audit_notify_complete(c)) {
			ERROR("Failed to notify container that all records were sent");
			return -1;
		}

		container_audit_set_last_ack(c, "");
		container_audit_set_processing_ack(c, false);

		return 0;
	}
	mem_free0(file);

	return audit_do_send_record(c);
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

	TRACE("Last ack for container %s: %s", uuid_string(container_get_uuid(c)),
	      container_audit_get_last_ack(c));

	if (crypto_match_hash(AUDIT_HASH_ALGO_LEN, container_audit_get_last_ack(c), ack)) {
		TRACE("ACK hash matched last sent record %s", container_audit_get_last_ack(c));

		AuditRecord *record = audit_next_record_new(c, true);

		if (!record) {
			ERROR("Failed to delete audit record %s", ack);
			return -1;
		}

		protobuf_free_message((ProtobufCMessage *)record);
		TRACE("Cleaned up ack'ed record");

		container_audit_set_last_ack(c, "");
	} else {
		WARN("ACK from container %s did not match last sent audit record, try to send last stored record again",
		     uuid_string(container_get_uuid(c)));
	}

	return audit_send_next_stored(c);
}

static int
audit_record_log(container_t *c, AuditRecord *record)
{
	int ret = 0;

	IF_NULL_RETVAL(record, -1);

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
	return ret;
}

int
audit_log_event(const uuid_t *uuid, AUDIT_CATEGORY category, AUDIT_COMPONENT component,
		AUDIT_EVENTCLASS evclass, const char *evtype, const char *subject_id,
		int meta_count, ...)
{
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

	char *type = mem_printf("%s.%s.%s.%s", audit_category_to_string(category),
				audit_component_to_string(component),
				audit_evclass_to_string(evclass), evtype);

	record = audit_record_new(type, subject_id, meta_count, metas);
	mem_free0(type);

	if (!record) {
		ERROR("Failed to create audit record");
		mem_free0(metas);
		goto out;
	}

	char *record_text;
	size_t msg_len =
		protobuf_string_from_message(&record_text, (ProtobufCMessage *)record, NULL);

	if (msg_len < 1) {
		ERROR("Could not cast protobuf message to string");
		mem_free0(record_text);
		goto out;
	}
	DEBUG("Logging audit message %s", record_text ? record_text : "");
	mem_free0(record_text);

	ret = audit_record_log(audit_get_log_container(uuid), record);

out:
	//if (record)
	//	audit_record_free(record);
	protobuf_free_message((ProtobufCMessage *)record);

	return ret;
}

static void
audit_cb_kernel_handle_log(int fd, unsigned events, UNUSED event_io_t *io, void *data)
{

	nl_sock_t *audit_sock = data;
	ASSERT(audit_sock);
	ASSERT(fd == nl_sock_get_fd(audit_sock));

	char *buf = mem_new0(char, MAX_AUDIT_MESSAGE_LENGTH);
	char *log_record = NULL;

	if (events & EVENT_IO_EXCEPT) {
		goto out;
	}

	int msg_len;
	if ((msg_len = nl_msg_receive_kernel(audit_sock, buf, MAX_AUDIT_MESSAGE_LENGTH, false)) <=
	    0) {
		WARN("could not read audit meassge.");
		goto out;
	}

	struct nlmsghdr *nlmsg = (struct nlmsghdr *)buf;
	uint16_t type = nlmsg->nlmsg_type;

	if (type == AUDIT_TRUSTED_APP) {
		log_record = NLMSG_DATA(nlmsg);
		int uid = -1;
		int pid = -1;
		sscanf(log_record, "%*s pid=%d uid=%d %*8970c", &pid, &uid);
		TRACE("scanned pid=%d, uid=%d", pid, uid);
		char *record_text = strstr(log_record, "msg='");
		IF_NULL_GOTO(record_text, out);
		record_text += 5;
		// remove closing ' char from msg string
		int record_text_len = strlen(record_text) - 1;
		AuditRecord *record = (AuditRecord *)protobuf_message_new_from_buf(
			(uint8_t *)record_text, record_text_len, &audit_record__descriptor);
		audit_record_log(cmld_container_get_by_uid(uid), record);
		protobuf_free_message((ProtobufCMessage *)record);
		TRACE("audit: type=%d %s", type, log_record);
	} else if (type == AUDIT_USER || type == AUDIT_LOGIN || type == AUDIT_DM_CTRL ||
		   (type >= AUDIT_FIRST_USER_MSG && type <= AUDIT_LAST_USER_MSG) ||
		   (type >= AUDIT_FIRST_USER_MSG2 && type <= AUDIT_LAST_USER_MSG2)) {
		log_record = NLMSG_DATA(nlmsg);
		int uid = -1;
		int pid = -1;
		sscanf(log_record, "%*s pid=%d uid=%d %*8970c", &pid, &uid);
		char *res = strstr(log_record, "res=");
		res = res ? res + 4 : "failed";
		container_t *c = cmld_container_get_by_uid(uid);
		c = c ? c : cmld_containers_get_c0();

		const uuid_t *uuid = NULL;
		const char *uuid_str = NULL;
		if (c) {
			uuid = container_get_uuid(c);
			uuid_str = uuid_string(uuid);
		}

		char *record_type = mem_printf("type=%hu", type);
		audit_log_event(uuid,
				(strstr(res, "success") || res[0] == '1') ? SSA : FSA, CMLD, KAUDIT,
				record_type, uuid_str, 2, "msg",
				log_record);
		mem_free0(record_type);
		TRACE("audit: type=%d %s", type, log_record);
	} else if (type == AUDIT_DM_EVENT) {
		log_record = NLMSG_DATA(nlmsg);
		uuid_t *uuid = NULL;
		char *dev_file = NULL;
		char *op_buf = mem_new0(char, MAX_AUDIT_MESSAGE_LENGTH);
		int dev_major, dev_minor, res;
		unsigned long long sector;
		int sscanf_ret =
			sscanf(log_record, "%*s module=%*s dev=%d:%d op=%s sector=%llu res=%d",
			       &dev_major, &dev_minor, op_buf, &sector, &res);
		TRACE("audit: sscanf_ret=%d", sscanf_ret);
		if (sscanf_ret == 5) {
			char *dev_name = NULL;
			char *sector_str = NULL;
			dev_file = mem_printf("/sys/dev/block/%d:%d/dm/name", dev_major, dev_minor);
			dev_name = file_read_new(dev_file, MAX_AUDIT_MESSAGE_LENGTH);
			if (dev_name) {
				char *dev_name_p;
				if ((dev_name_p = strchr(dev_name, '\n')) != NULL)
					*dev_name_p = '\0';
				char *uuid_str = mem_strndup(dev_name, 36);
				uuid = uuid_new(uuid_str);
				TRACE("uuid %s from dev '%s'", uuid_str, dev_file);
				mem_free0(uuid_str);
			}

			container_t *c = uuid ? cmld_container_get_by_uuid(uuid) : NULL;
			c = c ? c : cmld_containers_get_c0();

			const uuid_t *uuid = NULL;
			const char *uuid_str = NULL;
			if (c) {
				uuid = container_get_uuid(c);
				uuid_str = uuid_string(uuid);
			}

			sector_str = mem_printf("%llu", sector);
			audit_log_event(uuid, (res == 1) ? SSA : FSA, CMLD,
					CONTAINER_MGMT, "dm-integrity",
					uuid_str, 6, "op", op_buf,
					"label", dev_name, "sector", sector_str);

			mem_free0(sector_str);
			mem_free0(dev_name);
		}
		mem_free0(op_buf);
		mem_free0(dev_file);
		if (uuid)
			uuid_free(uuid);
		TRACE("audit: type=%d %s", type, log_record);
	} else if (type == AUDIT_KERNEL ||
		   (type >= AUDIT_FIRST_EVENT && type <= AUDIT_INTEGRITY_LAST_MSG)) {
		log_record = NLMSG_DATA(nlmsg);
		TRACE("audit: type=%d %s", type, log_record);
	}
out:
	mem_free0(buf);
}

int
audit_init(uint32_t size)
{
	AUDIT_STORAGE = size * 1024 * 1024;

	TRACE("Initializing audit subsystem");

	/* Open audit netlink socket */
	nl_sock_t *audit_sock;
	if (!(audit_sock = nl_sock_default_new(NETLINK_AUDIT))) {
		ERROR("Failed to allocate audit netlink socket");
		return -1;
	}
	/* Register cmld as auditd in kernel framwork */
	struct audit_status s_pid = { .mask = AUDIT_STATUS_PID, .pid = getpid() };
	if (-1 == audit_kernel_send(audit_sock, AUDIT_SET, &s_pid, sizeof(struct audit_status))) {
		ERROR("Failed to set cmld as auditd in kernel!");
		nl_sock_free(audit_sock);
		return -1;
	}

	event_io_t *audit_io_event = event_io_new(nl_sock_get_fd(audit_sock), EVENT_IO_READ,
						  &audit_cb_kernel_handle_log, audit_sock);
	event_add_io(audit_io_event);

	/* Register message handler for audit logs */
	if (fd_make_non_blocking(nl_sock_get_fd(audit_sock))) {
		ERROR("Could not set fd of audit netlink socket to non blocking!");
		nl_sock_free(audit_sock);
		return -1;
	}

	return 0;
}
