/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

/**
 * @file protobuf.h
 *
 * Provides utility functions to handle Protocol Buffers messages,
 * including serialization and deserialization of protobuf messages
 * to and from binary or text format representations.
 */

#ifndef PROTOBUF_H
#define PROTOBUF_H

#include <protobuf-c/protobuf-c.h>

#include <sys/types.h>
#include <stdbool.h>

#define PROTOBUF_MAX_MESSAGE_SIZE 1024 * 1024
#define PROTOBUF_MAX_OVERHEAD 1024

/**
 * Packs the given protobuf message struct
 * and returns it's binary serialized form.
 *
 * The serialized message is prefixed with the length of the actual data.
 *
 * @param message   the protobuf message struct to serialize and write
 * @param ptr       the location to store a pointer to the serialized representation
 * @return          the length of the serialized message (without length prefix) or -1 on error
 */
uint32_t
protobuf_pack_message_new(const ProtobufCMessage *message, uint8_t **ptr);

/**
 * Writes the given, serialized protobuf message struct to the given file descriptor
 * (e.g. a file or socket).
 *
 * The serialized message is prefixed with the length of the actual data.
 *
 * @param fd        the file descriptor that the serialized message is written to
 * @param buf       the serialized protobuf message to write
 * @return          the length of the given message (without length prefix)
 */
ssize_t
protobuf_send_message_packed(int fd, const uint8_t *buf, uint32_t buflen);

/**
 * Writes the given protobuf message struct to the given file descriptor
 * (e.g. a file or socket) in binary serialized form.
 *
 * The serialized message is prefixed with the length of the actual data.
 *
 * @param fd        the file descriptor that the serialized message is written to
 * @param message   the protobuf message struct to serialize and write
 * @return          the length of the serialized message (without length prefix)
 */
ssize_t
protobuf_send_message(int fd, const ProtobufCMessage *message);

/**
 * Reads a serialized protobuf message from the given file descriptor
 * (e.g. a file or socket) and deserializes it into a new message struct
 * as defined by the given message descriptor.
 *
 * The serialized message must be prefixed with the length of the actual data.
 *
 * @param fd        the file descriptor that the serialized message is read from
 * @param descriptor    the protobuf message descriptor that defines the message structure
 * @return          a pointer to a new protobuf message struct;
 *                  must be released with protobuf_free_message()
 */
ProtobufCMessage *
protobuf_recv_message(int fd, const ProtobufCMessageDescriptor *descriptor);

/**
 * Reads a serialized protobuf message from the given file descriptor
 * and returns it's packed representation
 *
 * The serialized message must be prefixed with the length of the actual data.
 *
 * @param fd        the file descriptor that the serialized message is read from
 * @param msg_len   a pointer where the length of the returned buffer should be stored, -1 on error
 * @return          a pointer to the received, packed  protobuf message
 */
uint8_t *
protobuf_recv_message_packed_new(int fd, ssize_t *msg_len);

/**
 * Unpacks the given, packed protobuf message
 *
 * @param descriptor    the protobuf message descriptor that defines the message structure
 * @param buf Buffer containing the packed protobuf message
 * @param buf_len length of the packed protobuf message
 * @return the unpacked protobuf message message message to free
 */
ProtobufCMessage *
protobuf_unpack_message(const ProtobufCMessageDescriptor *descriptor, uint8_t *buf,
			uint32_t buf_len);

/**
 * Frees an unpacked protobuf message struct (e.g. created by protobuf_recv_message()).
 *
 * @param message message to free
 */
void
protobuf_free_message(ProtobufCMessage *message);

/**
 * Writes (dumps) the given protobuf message struct to the given file descriptor
 * (e.g. a file or socket) in text form (human-readable).
 *
 * @param fd        the file descriptor that the message is written to
 * @param message   the protobuf message struct to be dumped
 * @return  the length of the dumped message string
 */
ssize_t
protobuf_dump_message(int fd, const ProtobufCMessage *message);

/**
 * Parses a protobuf message as defined by the given descriptor
 * from the given text file.
 *
 * @param filename      name of the text file containing the protobuf message
 * @param descriptor    the protobuf message descriptor that defines the message structure
 * @return  a pointer to the parsed protobuf message struct;
 *          must be released with protobuf_free_message()
 */
ProtobufCMessage *
protobuf_message_new_from_textfile(const char *filename,
				   const ProtobufCMessageDescriptor *descriptor);

/**
 * Parses a protobuf message as defined by the given descriptor
 * from the given string.
 *
 * @param filename      name of the text file containing the protobuf message
 * @param descriptor    the protobuf message descriptor that defines the message structure
 * @return  a pointer to the parsed protobuf message struct;
 *          must be released with protobuf_free_message()
 */
ProtobufCMessage *
protobuf_message_new_from_string(char *string, const ProtobufCMessageDescriptor *descriptor);

ProtobufCMessage *
protobuf_message_new_from_buf(const uint8_t *buf, size_t buflen,
			      const ProtobufCMessageDescriptor *descriptor);

/**
 * Writes a textual representation of the given protobuf message to the given file.
 *
 * @param filename  name of the text file where to store the serialized protobuf message
 * @param message   the protobuf message to be serialized
 * @return          the length of the serialized message
 */
ssize_t
protobuf_message_write_to_file(const char *filename, const ProtobufCMessage *message);

/**
 * Wrapper function for the protobug_c_text_to_string function
 * @param buffer_proto_string target buffer for serialized protobuf message
 * @param message protofbuf message
 * @param allocator protobuf C allocator
*/
size_t
protobuf_string_from_message(char **buffer_proto_string, const ProtobufCMessage *message,
			     ProtobufCAllocator *allocator);

#endif // PROTOBUF_H
