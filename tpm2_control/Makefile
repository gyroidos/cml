#
# This file is part of trust|me
# Copyright(c) 2013 - 2018 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2 (GPL 2), as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
#


LOCAL_CFLAGS := -pedantic -Wall -Wextra -Werror -std=gnu99 \
	-I.. -I../include -Icommon -DDEBUG_BUILD

SRC_FILES := \
	common/protobuf.c \
	common/sock.c \
	common/file.c \
	common/fd.c \
	tpm2d.pb-c.c \
	common/logf.pb-c.c \
	tpm2d_control.c

.PHONY: all
all: tpm2_control

protobuf: tpm2d.proto common/logf.proto
	protoc-c --c_out=. tpm2d.proto
	$(MAKE) -C common protobuf

libcommon: 
	$(MAKE) -C common libcommon

${SRC_FILES}: protobuf

tpm2_control: libcommon ${SRC_FILES}
	${CC} ${LOCAL_CFLAGS} ${SRC_FILES} -lc -lprotobuf-c -lprotobuf-c-text -Lcommon -lcommon -o tpm2_control

.PHONY: clean
clean:
	rm -f tpm2_control *.o *.pb-c.*
