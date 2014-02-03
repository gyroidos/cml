#!/usr/bin/python
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

from thread import *
from struct import *
import argparse
import atexit
import ctypes
import control_pb2
import SimpleHTTPServer
import socket
import SocketServer
import sys
import time

def sendProtobuf(request, conn):
    request_packed = request.SerializeToString()
    len_in_bytes = len(request_packed)
    #Length of buffer in bytes has to be sent first; use network byte order
    ret = conn.send(ctypes.c_uint32(socket.htonl(len_in_bytes)))
    ret = conn.send(request_packed)
    if ret < len(request_packed):
        print_in_red("Could not send the whole buffer")

def receivePackages(conn):
    while 1:
        len = conn.recv(4)
        if not len:
            continue;
        try:
            data = conn.recv(unpack('!I', len)[0])
        except Exception as e:
            print_in_red(str(e))
            continue;
        if not data:
            continue;
        reply = control_pb2.DaemonToController()
        try:
            reply.Clear()
            len_data = reply.MergeFromString(data)
            print_in_green(str(reply))
        except Exception as e:
            print_in_red(str(e))

def sleepWithInfo(seconds):
    print_in_yellow("Sleeping for " + str(seconds) + " seconds.")
    time.sleep(seconds)

def print_in_green(string_to_print):
    green = "\033[92m"
    print green + string_to_print

def print_in_yellow(string_to_print):
    yellow = "\033[93m"
    print yellow + string_to_print

def print_in_red(string_to_print):
    red = "\033[91m"
    print red + string_to_print

def sendSimpleCommand(command, command_string, conn, uuids=None):
    request = control_pb2.ControllerToDaemon()
    request.command = command
    if uuids:
        for uuid in uuids:
            request.container_uuids.append(uuid)
    sendProtobuf(request, conn)
    print_in_yellow("Sent " + command_string)
    sleepWithInfo(sleep_time)

def sendPUSH_GUESTOS_CONFIG(config_file_name, signature_file_name,
        certificate_file_name, conn):
    request = control_pb2.ControllerToDaemon()
    with open (config_file_name, "r") as config_file:
        config_string = config_file.read()
    with open (signature_file_name, "r") as signature_file:
        signature_string = signature_file.read()
    with open (certificate_file_name, "r") as certificate_file:
        certificate_string = certificate_file.read()
    request.command = control_pb2.ControllerToDaemon.PUSH_GUESTOS_CONFIG
    request.guestos_config_file = config_string
    request.guestos_config_signature = signature_string
    request.guestos_config_certificate = certificate_string
    sendProtobuf(request, conn)
    print_in_yellow("Sent PUSH_GUESTOS_CONFIG")
    sleepWithInfo(sleep_time)

def basicTestsuite(conn, addr):
    sendSimpleCommand(control_pb2.ControllerToDaemon.GET_CONTAINER_STATUS,
            "GET_CONTAINER_STATUS", conn)
    sendSimpleCommand(control_pb2.ControllerToDaemon.LIST_CONTAINERS,
            "LIST_CONTAINERS", conn)
    sendSimpleCommand(control_pb2.ControllerToDaemon.GET_CONTAINER_CONFIG,
            "GET_CONTAINER_CONFIG", conn)
    sendSimpleCommand(control_pb2.ControllerToDaemon.LIST_GUESTOS_CONFIGS,
            "LIST_GUESTOS_CONFIGS", conn)

def logTestsuite(conn, addr):
    sendSimpleCommand(control_pb2.ControllerToDaemon.GET_LAST_LOG, "GET_LAST_LOG", conn)
    sendSimpleCommand(control_pb2.ControllerToDaemon.OBSERVE_LOG_START,
            "OBSERVE_LOG_START", conn)
    sendSimpleCommand(control_pb2.ControllerToDaemon.OBSERVE_LOG_STOP,
            "OBSERVE_LOG_STOP", conn)

def wipeTestsuite(conn, addr):
    sendSimpleCommand(control_pb2.ControllerToDaemon.WIPE_DEVICE, "WIPE_DEVICE", conn)

def updateTestsuite(conn, addr, config_file_name, signature_file_name,
        certificate_file_name):
    sendPUSH_GUESTOS_CONFIG(config_file_name, signature_file_name,
            certificate_file_name, conn)

def runTestsuite(name, conn, addr, config_file_name=None,
        signature_file_name=None, certificate_file_name=None):
    #Wait for LOGON message
    sleepWithInfo(sleep_time)
    if name == "basic":
        basicTestsuite(conn, addr)
    elif name == "log":
        logTestsuite(conn, addr)
    elif name == "wipe":
        wipeTestsuite(conn, addr)
    elif name == "update":
        if config_file_name and signature_file_name and certificate_file_name:
            updateTestsuite(conn, addr, config_file_name, signature_file_name,
                    certificate_file_name)
        else:
            print_in_red("Need signature, certificate and config for update")
    else:
        print_in_red("Testsuite " + name + " not recognized. Use basic, log, wipe, update")
    conn.close()
    print_in_yellow("Finished sending test commands from testsuite " + name  + " - terminate with ctrl-c")
    if name == "update":
        print_in_red("Please wait until the device has downloaded all image files before pressing ctrl-c")

def connectionSetupFileserver(fileserver_ip, fileserver_port):
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer((fileserver_ip, fileserver_port), Handler)
    print_in_yellow("Serving files at port " + str(fileserver_port))
    start_new_thread(httpd.serve_forever,())
    return httpd

def connectionSetupBackend(backend_ip, backend_port):
    backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        backend_socket.bind((backend_ip, backend_port))
    except socket.error as msg:
        print_in_red("Bind failed with error " + msg[1] + " (" + str(msg[0]) + ")")
        return None
    maximum_number_of_queued_connections = 5
    backend_socket.listen(maximum_number_of_queued_connections)
    print_in_yellow("Serving trustme-backend at port " + str(backend_port))
    return backend_socket

def handleConnections(backend_socket, number_of_connections, testsuite,
        config_file_name=None, signature_file_name=None, certificate_file_name=None):
    for connection in range(number_of_connections):
        try:
            conn, addr = backend_socket.accept()
            print_in_yellow("Connection from " + str(addr[0]) + ":" + str(addr[1]))
            start_new_thread(receivePackages, (conn, ))
            start_new_thread(runTestsuite, (testsuite, conn, addr, config_file_name,
                signature_file_name, certificate_file_name))
        except KeyboardInterrupt:
            print_in_yellow("Caught keyboard interrupt - shutting down")
            sys.exit()

def closeConnection(backend_socket, httpd):
    print_in_yellow("Closing connection")
    if backend_socket:
        backend_socket.close()
    httpd.shutdown()

def setupArgParser():
    parser = argparse.ArgumentParser(description='Trustme Backend Simulator')
    parser.add_argument('fileserver_ip', metavar='fip', help='IP of fileserver')
    parser.add_argument('fileserver_port', metavar='fport', type=int, help='Port of fileserver')
    parser.add_argument('backend_ip', metavar='bip', help='IP of backend')
    parser.add_argument('backend_port', metavar='bport', type=int, help='Port of backend')
    parser.add_argument('testsuite', metavar='ts',
            choices=['basic', 'wipe', 'log', 'update'],
            help='The testsuite to run, currently possible: basic, wipe, log, update')
    parser.add_argument('--sleep_time', metavar='st', type=int, default=10,
            help='Time to sleep between commands (Default: 10)')
    parser.add_argument('--max_number_of_connections', metavar='mc', type=int,
            default=10, help='Maximum number of connections in one test (Default: 10)')
    parser.add_argument('--config_file_name', metavar='conf', default=None,
            help='Name of the config file used for update (Default: None)')
    parser.add_argument('--signature_file_name', metavar='sig', default=None,
            help='Name of the signature file used for update (Default: None)')
    parser.add_argument('--certificate_file_name', metavar='cert', default=None,
            help='Name of the certificate file used for update (Default: None)')
    return parser.parse_args()

args = setupArgParser()
fileserver_ip = args.fileserver_ip
fileserver_port = args.fileserver_port
backend_ip = args.backend_ip
backend_port = args.backend_port
testsuite = args.testsuite
sleep_time = args.sleep_time
max_number_of_connections = args.max_number_of_connections
config_file_name = args.config_file_name
signature_file_name = args.signature_file_name
certificate_file_name = args.certificate_file_name

httpd = connectionSetupFileserver(fileserver_ip, fileserver_port)
backend_socket = connectionSetupBackend(backend_ip, backend_port)
atexit.register(closeConnection, backend_socket, httpd)
if backend_socket:
    print_in_yellow("Running testsuite " + testsuite + " with sleep time " +
            str(sleep_time) + " seconds and maximum number of connections = " +
            str(max_number_of_connections))
    if testsuite == "update":
        if config_file_name and signature_file_name and certificate_file_name:
            print_in_yellow("The files provided for update are: " + config_file_name
                    + " " + signature_file_name + " " + certificate_file_name)
        else:
            print_in_red("Need signature, certificate and config for update")
            sys.exit()
    handleConnections(backend_socket, max_number_of_connections, testsuite,
            config_file_name, signature_file_name, certificate_file_name)
else:
    print_in_red("Could not bind socket - exiting")
    sys.exit()

