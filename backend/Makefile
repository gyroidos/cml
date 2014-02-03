#
# This file is part of trust|me
# Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

test_basic: control_pb2.py
	./backend.py 127.0.0.1 8000 127.0.0.1 8888 basic

test_log: control_pb2.py
	./backend.py 127.0.0.1 8000 127.0.0.1 8888 log

test_wipe: control_pb2.py
	./backend.py 127.0.0.1 8000 127.0.0.1 8888 wipe

setup_stunnel:
	cd ../../../../.. ;	stunnel4 trustme/build/config_overlay/stunnel-server.conf

control_pb2.py:
	protoc -I=../daemon --python_out=. ../daemon/control.proto
	protoc -I=../daemon --python_out=. ../daemon/common/logf.proto
	protoc -I=../daemon --python_out=. ../daemon/container.proto
	protoc -I=../daemon --python_out=. ../daemon/guestos.proto

clean:
	rm -f guestos_pb2.py*
	rm -f control_pb2.py*
	rm -f container_pb2.py*
	rm -f common/logf_pb2.py*
	rm -f common/__init__.pyc
	rm -fr __pycache__
