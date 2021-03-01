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

#include "protobuf.h"
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

#define PROTOBUF_MAX_MESSAGE_SIZE 1024 * 1024

// TODO update naming scheme

uint32_t
protobuf_pack_message_new(const ProtobufCMessage *message, uint8_t **ptr)
{
	ASSERT(message);
	ASSERT(ptr);

	uint32_t packed_len = protobuf_c_message_get_packed_size(message);
	uint8_t *packed = mem_alloc(packed_len);

	TRACE("Packed size: %d", packed_len);

	uint32_t actual_len = protobuf_c_message_pack(message, packed);
	ASSERT(actual_len == packed_len);

	*ptr = packed;

	return actual_len;
}

ssize_t
protobuf_send_message_packed(int fd, const uint8_t *buf, uint32_t buflen)
{
	ASSERT(buf);

	IF_FALSE_RETVAL(buflen < PROTOBUF_MAX_MESSAGE_SIZE, -1);

	ssize_t bytes_sent = fd_write(fd, (char *)&(uint32_t){ htonl(buflen) }, sizeof(uint32_t));
	if (-1 == bytes_sent)
		goto error_write;
	TRACE("sent protobuf message length (%zd bytes sent, %zu bytes expected, len=%d)",
	      bytes_sent, sizeof(uint32_t), buflen);
	ASSERT((size_t)bytes_sent == sizeof(uint32_t));

	// serialized form of message with all default values has zero length
	// => transmit its (zero) length prefix only
	if (buflen == 0)
		return 0;

	// TODO sending large messages: might have to send multiple chunks
	// need good (generic?!) solution that interacts nicely with event handling!
	bytes_sent = fd_write(fd, (char *)buf, buflen);
	if (-1 == bytes_sent)
		goto error_write;
	fsync(fd); // make sure all data is written so that receiving client unblocks
	TRACE("sent protobuf message data (%zd bytes sent, %u bytes expected)", bytes_sent, buflen);

	ASSERT((size_t)bytes_sent == buflen);
	return bytes_sent;

error_write:
	DEBUG_ERRNO("Failed to write binary protobuf message to fd %d.", fd);
	return -1;
}

ssize_t
protobuf_send_message(int fd, const ProtobufCMessage *message)
{
	ASSERT(message);

	uint8_t *buf = NULL;
	uint32_t buflen = protobuf_pack_message_new(message, &buf);

	if (!(buflen < PROTOBUF_MAX_MESSAGE_SIZE)) {
		ERROR("Packed message exceeds PROTOBUF_MAX_MESSAGE_SIZE");
		if (buf)
			mem_free(buf);

		return -1;
	}

	if (-1 == protobuf_send_message_packed(fd, buf, buflen)) {
		ERROR_ERRNO("Failed to write packed protobuf message to fd %d.", fd);
		return -1;
	}

	return buflen;
}

uint8_t *
protobuf_recv_message_packed_new(int fd, ssize_t *ret_len)
{
	ASSERT(ret_len);
	uint32_t buflen = 0;
	ssize_t bytes_read;
	do {
		bytes_read = fd_read(fd, (char *)&buflen, sizeof(uint32_t));
	} while (-1 == bytes_read && errno == EINTR);
	if (-1 == bytes_read)
		goto error_read;
	if (0 == bytes_read) { // EOF / remote end closed the connection
		DEBUG("client on fd %d closed connection.", fd);
		*ret_len = -1;
		return NULL;
	}
	buflen = ntohl(buflen);
	TRACE("read protobuf message length (%zd bytes read, %zu bytes expected, len=%d)",
	      bytes_read, sizeof(buflen), buflen);
	if (((size_t)bytes_read != sizeof(buflen))) {
		ERROR("Protocol violation!");
		*ret_len = -1;
		return NULL;
	}
	IF_FALSE_RETVAL(buflen < PROTOBUF_MAX_MESSAGE_SIZE, NULL);

	if (0 == buflen) {
		*ret_len = 0;
		return NULL;
	}

	uint8_t *buf = mem_alloc(buflen);
	do {
		bytes_read = fd_read(fd, (char *)buf, buflen);
	} while (-1 == bytes_read && errno == EINTR);
	if (-1 == bytes_read) {
		mem_free(buf);
		goto error_read;
	}
	TRACE("read protobuf message data (%zd bytes read, %u bytes expected)", bytes_read, buflen);

	if ((size_t)bytes_read != buflen) {
		ERROR("Dropped protobuf message (expected length : %zd bytes read != %u bytes expected)",
		      bytes_read, buflen);
		mem_free(buf);
		goto error_read;
	}
	// TODO: what if only part of a message could be read?
	// need good (generic?!) solution that interacts nicely with event handling!

	*ret_len = bytes_read;

	return buf;

error_read:
	DEBUG_ERRNO("Failed to read binary protobuf message from fd %d.", fd);
	*ret_len = -1;
	return NULL;
}

ProtobufCMessage *
protobuf_recv_message(int fd, const ProtobufCMessageDescriptor *descriptor)
{
	ASSERT(descriptor);

	ssize_t buflen = 0;
	uint8_t *buf = protobuf_recv_message_packed_new(fd, &buflen);

	// zero length data represents a message with all default values
	// => use unpack to construct it (and initialize it with these defaults)
	if (0 == buflen)
		return protobuf_c_message_unpack(descriptor, NULL, 0, NULL);

	if (!buf) {
		ERROR("Failed to receive packed protobuf message");
		return NULL;
	}

	ProtobufCMessage *msg = protobuf_c_message_unpack(descriptor, NULL, buflen, buf);
	mem_free(buf);
	return msg;
}

ProtobufCMessage *
protobuf_unpack_message(const ProtobufCMessageDescriptor *descriptor, uint8_t *buf,
			uint32_t buf_len)
{
	ASSERT(descriptor);

	ProtobufCMessage *msg = protobuf_c_message_unpack(descriptor, NULL, buf_len, buf);

	return msg;
}

void
protobuf_free_message(ProtobufCMessage *message)
{
	if (!message) {
		WARN("Trying to free NULL protobuf message!");
		return;
	}
	protobuf_c_message_free_unpacked(message, NULL);
}

ssize_t
protobuf_dump_message(int fd, const ProtobufCMessage *message)
{
	ASSERT(message);

	char *string = protobuf_c_text_to_string((ProtobufCMessage *)message, NULL);
	if (NULL == string) {
		WARN("Failed to serialize text protobuf message to string.");
		return -1;
	}
	ssize_t bytes_written = write(fd, string, strlen(string));
	mem_free(string);
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
	memset(&res, 0, sizeof(res));
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
	memset(&res, 0, sizeof(res));
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

	mem_free(string);
	return msg;
}

ssize_t
protobuf_message_write_to_file(const char *filename, ProtobufCMessage *message)
{
	ASSERT(filename);
	ASSERT(message);

	char *string = protobuf_c_text_to_string(message, NULL);
	if (!string) {
		ERROR("Failed to serialize text protobuf message to string.");
		return -1;
	}
	size_t len = strlen(string);
	int res = file_write(filename, string, len);
	free(string);
	if (res < 0) {
		ERROR("Failed to write serialized text protobuf message to file \"%s\".", filename);
		return -1;
	}
	return len;
}
