/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2023 Fraunhofer AISEC
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

#include "protobuf.h"
#include "protobuf-text.h"
#include <errno.h>
#include <stdio.h> // for protobuf-c-text.h
#include <google/protobuf-c/protobuf-c-text.h>

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "macro.h"
#include "mem.h"
#include "fd.h"
#include "file.h"

#include <unistd.h>
#include <arpa/inet.h>

// TODO update naming scheme

ssize_t
protobuf_dump_message(int fd, const ProtobufCMessage *message)
{
	ASSERT(message);

	char *string;
	size_t msg_len = protobuf_string_from_message(&string, message, NULL);
	if (NULL == string) {
		WARN("Failed to serialize text protobuf message to string.");
		return -1;
	}
	ssize_t bytes_written = write(fd, string, msg_len);
	mem_free0(string);
	if (-1 == bytes_written)
		WARN_ERRNO("Failed to write text protobuf message to fd %d.", fd);
	return bytes_written;
}

ProtobufCMessage *
protobuf_message_new_from_textfile(const char *filename,
				   const ProtobufCMessageDescriptor *descriptor)
{
	ASSERT(filename);
	ASSERT(descriptor);
	TRACE("Reading text protobuf message (%s) from file \"%s\".",
	      descriptor->name ? descriptor->name : "UNKNOWN", filename);

	ProtobufCTextError res;
	mem_memset(&res, 0, sizeof(res));
	FILE *file = fopen(filename, "r");
	if (!file) {
		WARN_ERRNO("Could not open file \"%s\" for reading.", filename);
		return NULL;
	}
	ProtobufCMessage *msg = protobuf_c_text_from_file(descriptor, file, &res, NULL);
	fclose(file);
	if (!msg) {
		ERROR("Failed to parse text protobuf message (%s) from file \"%s\". Reason: %s.",
		      descriptor->name ? descriptor->name : "UNKNOWN", filename,
		      res.error_txt ? res.error_txt : "UNKNOWN");
		return NULL;
	}
	if (!res.complete) {
		ERROR("Incomplete text protobuf message (%s) in file \"%s\".",
		      descriptor->name ? descriptor->name : "UNKNOWN", filename);
		protobuf_free_message(msg);
		return NULL;
	}
	if (res.complete < 0) // TODO investigate why this seems to be the case...
		WARN("Required field check wasn't performed -- libprotobuf-c is too old.");
	return msg;
}

ProtobufCMessage *
protobuf_message_new_from_string(char *string, const ProtobufCMessageDescriptor *descriptor)
{
	ASSERT(string);
	ASSERT(descriptor);
	TRACE("Parsing text protobuf message (%s) from string.",
	      descriptor->name ? descriptor->name : "UNKNOWN");

	ProtobufCTextError res;
	mem_memset(&res, 0, sizeof(res));
	ProtobufCMessage *msg = protobuf_c_text_from_string(descriptor, string, &res, NULL);
	if (!msg) {
		ERROR("Failed to parse text protobuf message (%s) from string. Reason: %s.",
		      descriptor->name ? descriptor->name : "UNKNOWN",
		      res.error_txt ? res.error_txt : "UNKNOWN");
		protobuf_c_text_free_ProtobufCTextError_data(&res);
		return NULL;
	}
	if (!res.complete) {
		ERROR("Incomplete text protobuf message (%s).",
		      descriptor->name ? descriptor->name : "UNKNOWN");
		protobuf_free_message(msg);
		protobuf_c_text_free_ProtobufCTextError_data(&res);
		return NULL;
	}
	if (res.complete < 0) {
		WARN("Required field check wasn't performed -- libprotobuf-c is too old.");
		protobuf_c_text_free_ProtobufCTextError_data(&res);
	}
	return msg;
}

ProtobufCMessage *
protobuf_message_new_from_buf(const uint8_t *buf, size_t buflen,
			      const ProtobufCMessageDescriptor *descriptor)
{
	ASSERT(buf);
	ASSERT(descriptor);
	TRACE("Parsing text protobuf message (%s) from buffer %p (length=%zu).",
	      descriptor->name ? descriptor->name : "UNKNOWN", buf, buflen);

	char *string = mem_alloc(buflen + 1);
	memcpy(string, buf, buflen);
	string[buflen] = '\0';

	ProtobufCMessage *msg = protobuf_message_new_from_string(string, descriptor);

	mem_free0(string);
	return msg;
}

ssize_t
protobuf_message_write_to_file(const char *filename, const ProtobufCMessage *message)
{
	ASSERT(filename);
	ASSERT(message);

	char *string;
	size_t msg_len = protobuf_string_from_message(&string, message, NULL);
	if (!string) {
		ERROR("Failed to serialize text protobuf message to string.");
		return -1;
	}

	int res = file_write(filename, string, msg_len);
	free(string);
	if (res < 0) {
		ERROR("Failed to write serialized text protobuf message to file \"%s\".", filename);
		return -1;
	}
	return msg_len;
}

size_t
protobuf_string_from_message(char **buffer_proto_string, const ProtobufCMessage *message,
			     ProtobufCAllocator *allocator)
{
	ASSERT(message);
	size_t proto_len = -1;

	char *tmp_string = protobuf_c_text_to_string(message, allocator);
	if (!tmp_string) {
		ERROR("Failed to serialize text protobuf message to string.");
		goto error;
	}
	proto_len = strlen(tmp_string);

	// if length less than 1,
	// something was wrong with the protobuf message
	if (proto_len < 1) {
		ERROR("Failed to read length of serialized protobuf message.");
		goto error;
	}

	// set message buffer from caller to new message buffer
	*buffer_proto_string = tmp_string;
	goto success;

error:
	free(tmp_string);
success:
	return proto_len;
}
