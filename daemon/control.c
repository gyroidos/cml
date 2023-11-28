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

#include "control.h"

#include "control.pb-c.h"
#include "container.pb-c.h"

#include "container.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "cmld.h"
#include "hardware.h"
#include "crypto.h"
#include "audit.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/protobuf-text.h"
#include "common/sock.h"
#include "common/uuid.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/logf.h"
#include "common/list.h"
#include "common/network.h"
#include "common/reboot.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/str.h"
#include "common/proc.h"

#include <unistd.h>
#include <inttypes.h>

#include <google/protobuf-c/protobuf-c-text.h>

// maximum no. of connections waiting to be accepted on the listening socket
#define CONTROL_SOCK_LISTEN_BACKLOG 8

// time between reconnection attempts of a remote client socket
#define CONTROL_REMOTE_RECONNECT_INTERVAL 10000

#define LOGGER_ENTRY_MAX_LEN (5 * 1024)

struct control {
	int sock; // listen socket fd
	bool privileged;
	list_t *event_io_sock_connected_list; // list of clients
};

static list_t *control_list = NULL;

/**
 * @brief callback for the dir_foreach function sending a file as LogMessage to the Controller
 * @path: Expects path string without trailing "/" at the end
 * @return 1 on error, 0 else
 */
static int
control_send_file_as_log_message_cb(const char *path, const char *file, void UNUSED *data)
{
	IF_NULL_RETVAL(path, 1);
	IF_NULL_RETVAL(file, 1);

	int *fd = (int *)data;
	int ret = 0;
	str_t *path_str = str_new(path);
	str_append(path_str, "/");
	str_append(path_str, file);

	LogMessage message = LOG_MESSAGE__INIT;

	message.name = mem_strdup(file);
	DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
	if (cmld_get_device_uuid()) {
		TRACE("Setting uuid: %s", cmld_get_device_uuid());
		out.device_uuid = mem_strdup(cmld_get_device_uuid());
	}

	DEBUG("Opening and sending %s", str_buffer(path_str));

	char *file_buf =
		file_read_new(str_buffer(path_str), (size_t)file_size(str_buffer(path_str)));

	if (file_buf) {
		int max_fragment_size = PROTOBUF_MAX_MESSAGE_SIZE - PROTOBUF_MAX_OVERHEAD;
		int sent = 0;
		int size = strlen(file_buf);

		while (0 < size - sent) {
			fflush(stdout);
			fflush(stderr);

			// send fragments if size exceeds fragment_size
			int tosend = size - sent;
			if (tosend > max_fragment_size) {
				out.code = DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE_FRAGMENT;
				message.msg =
					(char *)mem_strndup(file_buf + sent, max_fragment_size);

				DEBUG("Sending fragment of logfile %s, sent: %d, remaining: %d",
				      str_buffer(path_str), sent, size - sent);

				out.log_message = &message;
				if (protobuf_send_message(*fd, (ProtobufCMessage *)&out) < 0) {
					ERROR_ERRNO("Could not finish sending %s",
						    str_buffer(path_str));
					ret = 1;
					break;
				}

				sent += max_fragment_size;
				mem_free0(message.msg);
			} else {
				DEBUG("Sending final fragment of logfile %s, sent: %d, remaining: %d",
				      str_buffer(path_str), sent, size - sent);
				out.code = DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE_FINAL;
				message.msg = (char *)mem_strndup(file_buf + sent, size - sent);

				out.log_message = &message;
				if (protobuf_send_message(*fd, (ProtobufCMessage *)&out) < 0) {
					ERROR_ERRNO("Could not finish sending %s",
						    str_buffer(path_str));
					ret = 1;
					break;
				}

				sent += strlen(message.msg);
				mem_free0(message.msg);
			}
		}
		mem_free0(file_buf);
	} else {
		DEBUG("File %s could not be read to buffer.", str_buffer(path_str));
		ret = 1;
	}

	if (out.device_uuid != NULL) {
		mem_free0(out.device_uuid);
	}

	str_free(path_str, true);

	return ret;
}

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
ContainerState
control_compartment_state_to_proto(compartment_state_t state)
{
	switch (state) {
	case COMPARTMENT_STATE_STOPPED:
		return CONTAINER_STATE__STOPPED;
	case COMPARTMENT_STATE_STARTING:
		return CONTAINER_STATE__STARTING;
	case COMPARTMENT_STATE_BOOTING:
		return CONTAINER_STATE__BOOTING;
	case COMPARTMENT_STATE_RUNNING:
		return CONTAINER_STATE__RUNNING;
	case COMPARTMENT_STATE_FREEZING:
		return CONTAINER_STATE__FREEZING;
	case COMPARTMENT_STATE_FROZEN:
		return CONTAINER_STATE__FROZEN;
	case COMPARTMENT_STATE_ZOMBIE:
		return CONTAINER_STATE__ZOMBIE;
	case COMPARTMENT_STATE_SHUTTING_DOWN:
		return CONTAINER_STATE__SHUTDOWN;
	case COMPARTMENT_STATE_SETUP:
		return CONTAINER_STATE__SETUP;
	case COMPARTMENT_STATE_REBOOTING:
		return CONTAINER_STATE__REBOOTING;
	default:
		FATAL("Unhandled value for compartment_state_t: %d", state);
	}
}
/**

 * The usual identity map between two corresponding C and protobuf enums.
 */
ContainerType
control_container_type_to_proto(container_type_t type)
{
	switch (type) {
	case CONTAINER_TYPE_CONTAINER:
		return CONTAINER_TYPE__CONTAINER;
	case CONTAINER_TYPE_KVM:
		return CONTAINER_TYPE__KVM;
	default:
		FATAL("Unhandled value for container_type_t: %d", type);
	}
}

/**
 * Get the ContainerStatus for the given container.
 *
 * @param container the container object from which to generate the ContainerStatus
 * @return  a new ContainerStatus object with information about the given container;
 *          has to be free'd with control_container_status_free()
 */
static ContainerStatus *
control_container_status_new(const container_t *container)
{
	ContainerStatus *c_status = mem_new(ContainerStatus, 1);
	container_status__init(c_status);
	c_status->uuid = mem_strdup(uuid_string(container_get_uuid(container)));
	c_status->name = mem_strdup(container_get_name(container));
	c_status->type = control_container_type_to_proto(container_get_type(container));
	c_status->state = control_compartment_state_to_proto(container_get_state(container));
	c_status->uptime = container_get_uptime(container);
	c_status->created = container_get_creation_time(container);

	const guestos_t *os = container_get_guestos(container);
	c_status->guestos = os ? mem_strdup(guestos_get_name(os)) : mem_strdup("none");

	c_status->trust_level = CONTAINER_TRUST__UNSIGNED;

	if (os) {
		switch (guestos_get_verify_result(os)) {
		case GUESTOS_SIGNED:
			c_status->trust_level = CONTAINER_TRUST__SIGNED;
			break;
		case GUESTOS_LOCALLY_SIGNED:
			c_status->trust_level = CONTAINER_TRUST__LOCALLY_SIGNED;
			break;
		default:
			c_status->trust_level = CONTAINER_TRUST__UNSIGNED;
		}
	}

	return c_status;
}

/**
 * Free the given ContainerStatus object that was previously allocated
 * by control_container_status_new().
 *
 * @param c_status the previously allocated ContainerStatus object
 */
static void
control_container_status_free(ContainerStatus *c_status)
{
	IF_NULL_RETURN(c_status);
	mem_free0(c_status->name);
	mem_free0(c_status->uuid);
	mem_free0(c_status->guestos);
	mem_free0(c_status);
}

static ssize_t
control_read_send(int cfd, int fd)
{
	uint8_t buf[1024];
	ssize_t count = -1;

	TRACE("Trying to read data from console socket.");

	if ((count = read(fd, buf, 1023)) > 0) {
		buf[count] = 0;

		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__EXEC_OUTPUT;
		out.has_exec_output = true;
		out.exec_output.len = count;
		out.exec_output.data = buf;

		TRACE("[CONTROL] Read %zd bytes: %s. Sending to control client...", count, buf);

		if (protobuf_send_message(cfd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send exec output to MDM");
		}
	} else {
		TRACE_ERRNO("[CONTROL] Read from console socket returned %zd", count);
	}

	return count;
}

static void
control_cb_read_console(int fd, unsigned events, event_io_t *io, void *data)
{
	int *cfd = data;

	TRACE("Console callback called, events: read: %u, write: %u, except: %u",
	      (events & EVENT_IO_READ), (events & EVENT_IO_WRITE), (events & EVENT_IO_EXCEPT));

	if ((events & EVENT_IO_READ)) {
		TRACE("Got output from exec'ed command, trying to read from console socket");

		int count = 0;

		// necessary to get all output from interactive commands
		do {
			TRACE("Trying to read all available data from socket");
			count = control_read_send(*cfd, fd);

			TRACE_ERRNO("Response from read was %d", count);
		} while (count > 0);
	}

	if ((events & EVENT_IO_EXCEPT)) {
		TRACE("Detected termination of executed command. Stop listening.");

		event_remove_io(io);
		event_io_free(io);
		close(fd);

		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__EXEC_END;

		if (protobuf_send_message(*cfd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send exec output to MDM");
		}

		TRACE("Sent notification of command termination to client");
		mem_free0(cfd);
	}
}

static container_t *
control_get_container_by_uuid_string(const char *uuid_str)
{
	uuid_t *uuid = uuid_new(uuid_str);
	if (!uuid) {
		WARN("Could not get UUID");
		return NULL;
	}
	container_t *container = cmld_container_get_by_uuid(uuid);
	if (!container) {
		WARN("Could not find container for UUID %s", uuid_string(uuid));
		uuid_free(uuid);
		return NULL;
	}
	uuid_free(uuid);
	return container;
}

/**
 * Returns a list of containers for all given UUIDs, or a list with all
 * available containers if the given UUID list is empty.
 */
static list_t *
control_build_container_list_from_uuids(size_t n_uuids, char **uuids)
{
	list_t *containers = NULL;
	if (n_uuids > 0) { // uuid list given in incoming message
		for (size_t i = 0; i < n_uuids; i++) {
			container_t *container = control_get_container_by_uuid_string(uuids[i]);
			if (container != NULL)
				containers = list_append(containers, container);
		}
	} else { // empty uuid list, return status for all containers
		n_uuids = cmld_containers_get_count();
		for (size_t i = 0; i < n_uuids; i++) {
			container_t *container = cmld_container_get_by_index(i);
			containers = list_append(containers, container);
		}
	}
	return containers;
}

int
control_send_message(control_message_t message, int fd)
{
	DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
	out.code = DAEMON_TO_CONTROLLER__CODE__RESPONSE;
	out.has_response = true;
	switch (message) {
	case CONTROL_RESPONSE_CONTAINER_START_OK:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_OK;
		break;

	case CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_LOCK_FAILED;
		break;

	case CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_UNLOCK_FAILED;
		break;

	case CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_PASSWD_WRONG;
		break;

	case CONTROL_RESPONSE_CONTAINER_START_EEXIST:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_EEXIST;
		break;

	case CONTROL_RESPONSE_CONTAINER_START_EINTERNAL:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_EINTERNAL;
		break;

	case CONTROL_RESPONSE_CONTAINER_STOP_OK:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_STOP_OK;
		break;

	case CONTROL_RESPONSE_CONTAINER_STOP_LOCK_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_STOP_LOCK_FAILED;
		break;

	case CONTROL_RESPONSE_CONTAINER_STOP_UNLOCK_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_STOP_UNLOCK_FAILED;
		break;

	case CONTROL_RESPONSE_CONTAINER_STOP_PASSWD_WRONG:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_STOP_PASSWD_WRONG;
		break;

	case CONTROL_RESPONSE_CONTAINER_STOP_FAILED_NOT_RUNNING:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_STOP_FAILED_NOT_RUNNING;
		break;

	case CONTROL_RESPONSE_CONTAINER_CTRL_EINTERNAL:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_CTRL_EINTERNAL;
		break;

	case CONTROL_RESPONSE_CONTAINER_TOKEN_UNINITIALIZED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_TOKEN_UNINIT;
		break;

	case CONTROL_RESPONSE_CONTAINER_TOKEN_UNPAIRED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_TOKEN_UNPAIRED;
		break;

	case CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_CHANGE_PIN_FAILED;
		break;

	case CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_SUCCESSFUL:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_CHANGE_PIN_SUCCESSFUL;
		break;

	case CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_LOCKED_TILL_REBOOT;
		break;

	case CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_USB_PIN_ENTRY_FAIL;
		break;

	case CONTROL_RESPONSE_DEVICE_PROVISIONING_ERROR:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__DEVICE_PROVISIONING_ERROR;
		break;

	case CONTROL_RESPONSE_DEVICE_CERT_ERROR:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__DEVICE_CERT_ERROR;
		break;

	case CONTROL_RESPONSE_DEVICE_CERT_OK:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__DEVICE_CERT_OK;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_INSTALL_STARTED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_INSTALL_STARTED;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_INSTALL_WAITING:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_INSTALL_WAITING;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_INSTALL_COMPLETED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_INSTALL_COMPLETED;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_INSTALL_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_INSTALL_FAILED;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_REGISTER_CA_ERROR:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_REGISTER_CA_ERROR;
		break;

	case CONTROL_RESPONSE_GUESTOS_MGR_REGISTER_CA_OK:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__GUESTOS_MGR_REGISTER_CA_OK;
		break;

	case CONTROL_RESPONSE_CMD_UNSUPPORTED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CMD_UNSUPPORTED;
		break;

	case CONTROL_RESPONSE_CMD_OK:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CMD_OK;
		break;

	case CONTROL_RESPONSE_CMD_FAILED:
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CMD_FAILED;
		break;

	default:
		DEBUG("Unknown message `%d' (not sent)", message);
		return -1;
	}

	return protobuf_send_message(fd, (ProtobufCMessage *)&out);
}

/**
 * Handles list_guestos_configs cmd.
 * Used in both priv and unpriv control handlers.
 */
static void
control_handle_cmd_list_guestos_configs(UNUSED const ControllerToDaemon *msg, int fd)
{
	// allocate memory for result
	size_t n = guestos_mgr_get_guestos_count();
	GuestOSConfig **results = mem_new(GuestOSConfig *, n);

	// fill result with data from guestos
	for (size_t i = 0; i < n; i++) {
		guestos_t *os = guestos_mgr_get_guestos_by_index(i);
		results[i] = guestos_get_raw_ptr(os);
	}

	// build and send response message to controller
	DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
	out.code = DAEMON_TO_CONTROLLER__CODE__GUESTOS_CONFIGS_LIST;
	out.n_guestos_configs = n;
	out.guestos_configs = results;
	if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
		WARN("Could not send list of guestos configs to MDM");
	}

	// collect garbage
	mem_free0(results);
}

/**
 * Handles push_guestos_configs cmd
 * Used in both priv and unpriv control handlers.
 */
static void
control_handle_cmd_push_guestos_configs(const ControllerToDaemon *msg, int fd)
{
	bool has_cfg = false, has_sig = false, has_cert = false;

	if (!(has_cfg = msg->has_guestos_config_file))
		WARN("PUSH_GUESTOS_CONFIG without config file");

	if (!(has_sig = msg->has_guestos_config_signature))
		WARN("PUSH_GUESTOS_CONFIG without config signature");

	if (!(has_cert = msg->has_guestos_config_certificate))
		WARN("PUSH_GUESTOS_CONFIG without config certificate");

	guestos_mgr_push_config(has_cfg ? msg->guestos_config_file.data : NULL,
				has_cfg ? msg->guestos_config_file.len : 0,
				has_sig ? msg->guestos_config_signature.data : NULL,
				has_sig ? msg->guestos_config_signature.len : 0,
				has_cert ? msg->guestos_config_certificate.data : NULL,
				has_cert ? msg->guestos_config_certificate.len : 0, fd);
}

/**
 * Handles register local cmd
 * Used in both priv and unpriv control handlers.
 */
static void
control_handle_cmd_register_localca(const ControllerToDaemon *msg, UNUSED int fd)
{
	if (!msg->has_guestos_rootcert)
		WARN("REGISTER_LOCALCA without root certificate");
	else {
		guestos_mgr_register_localca(msg->guestos_rootcert.data, msg->guestos_rootcert.len);
	}
}

typedef struct {
	cmld_container_ctrl_t container_ctrl;
	int resp_fd;
} control_csmartcard_resp_data_t;

static void
control_csmartcard_handle_error_cb(int err_code, void *data)
{
	control_csmartcard_resp_data_t *cbdata = data;
	ASSERT(cbdata);

	cmld_container_ctrl_t container_ctrl = cbdata->container_ctrl;
	int fd = cbdata->resp_fd;

	switch (err_code) {
	case CONTAINER_SMARTCARD_LOCK_FAILED:
		if (container_ctrl == CMLD_CONTAINER_CTRL_START)
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_LOCK_FAILED, fd);
		else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_LOCK_FAILED, fd);
		break;
	case CONTAINER_SMARTCARD_UNLOCK_FAILED:
		if (container_ctrl == CMLD_CONTAINER_CTRL_START)
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_UNLOCK_FAILED, fd);
		else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_UNLOCK_FAILED, fd);
		break;
	case CONTAINER_SMARTCARD_PASSWD_WRONG:
		if (container_ctrl == CMLD_CONTAINER_CTRL_START)
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG, fd);
		else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_PASSWD_WRONG, fd);
		break;
	case CONTAINER_SMARTCARD_TOKEN_UNINITIALIZED:
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNINITIALIZED, fd);
		break;
	case CONTAINER_SMARTCARD_TOKEN_UNPAIRED:
		control_send_message(CONTROL_RESPONSE_CONTAINER_TOKEN_UNPAIRED, fd);
		break;
	case CONTAINER_SMARTCARD_PAIRING_SECRET_FAILED:
	case CONTAINER_SMARTCARD_WRAPPING_ERROR:
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, fd);
		break;
	case CONTAINER_SMARTCARD_CHANGE_PIN_FAILED:
		control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_FAILED, fd);
		break;
	case CONTAINER_SMARTCARD_CHANGE_PIN_SUCCESSFUL:
		control_send_message(CONTROL_RESPONSE_CONTAINER_CHANGE_PIN_SUCCESSFUL, fd);
		break;
	case CONTAINER_SMARTCARD_LOCKED_TILL_REBOOT:
		control_send_message(CONTROL_RESPONSE_CONTAINER_LOCKED_TILL_REBOOT, fd);
		break;
	case CONTAINER_SMARTCARD_CB_OK:
		if (container_ctrl == CMLD_CONTAINER_CTRL_START)
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_OK, fd);
		else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_OK, fd);
		break;
	case CONTAINER_SMARTCARD_CB_FAILED:
		if (container_ctrl == CMLD_CONTAINER_CTRL_START)
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_EINTERNAL, fd);
		else if (container_ctrl == CMLD_CONTAINER_CTRL_STOP)
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_FAILED_NOT_RUNNING,
					     fd);
		break;
	}

	mem_free0(cbdata);
}

static void
control_input_handle_error_cb(int err_code, void *data)
{
	int *fd = data;
	ASSERT(fd);

	if (!err_code) {
		mem_free0(fd);
		return;
	}

	if (err_code == -2)
		control_send_message(CONTROL_RESPONSE_CONTAINER_CTRL_EINTERNAL, *fd);
	else
		control_send_message(CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL, *fd);

	mem_free0(fd);
}

/**
 * Starts a container with pre-specified keys or user supplied keys
 */
static int
control_handle_container_start(container_t *container, ContainerStartParams *start_params, int fd)
{
	TRACE("Starting container");
	int res = -1;

	if (start_params && start_params->has_setup) {
		INFO("Setting Setup mode for Container!");
		container_set_setup_mode(container, start_params->setup);
	}

	// Setup smartcard response handling
	if (start_params || container_get_usb_pin_entry(container)) {
		control_csmartcard_resp_data_t *cbdata =
			mem_new0(control_csmartcard_resp_data_t, 1);
		cbdata->container_ctrl = CMLD_CONTAINER_CTRL_START;
		cbdata->resp_fd = fd;

		if (container_set_smartcard_error_cb(container, control_csmartcard_handle_error_cb,
						     cbdata))
			mem_free(cbdata);
	}

	// Check if pin should be interactively requested via pin pad reader
	if (container_get_usb_pin_entry(container)) {
		TRACE("Container start with pin entry chosen. Starting");
		int *resp_fd = mem_new0(int, 1);
		*resp_fd = fd;
		res = cmld_container_ctrl_with_input(container, CMLD_CONTAINER_CTRL_START,
						     control_input_handle_error_cb, resp_fd);
		if (res != 0) {
			control_send_message(CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL, fd);
		}
	} else if (start_params) {
		char *key = start_params->key;
		TRACE("Default container start without pin entry chosen. Starting");
		res = cmld_container_ctrl_with_smartcard(container, key, CMLD_CONTAINER_CTRL_START);
		if (res != 0) {
			ERROR("Failed to start container %s", container_get_name(container));
		}
		if (res == -2)
			control_send_message(CONTROL_RESPONSE_CONTAINER_CTRL_EINTERNAL, fd);

		mem_memset0(key, strlen(key));
	} else if (container_is_encrypted(container)) {
		res = -1;
		control_send_message(CONTROL_RESPONSE_CONTAINER_START_PASSWD_WRONG, fd);
	} else {
		res = cmld_container_start(container);
		if (res < 0) {
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_EEXIST, fd);
		} else {
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_OK, fd);
		}
	}
	return res;
}

static int
control_handle_container_stop(container_t *container, ContainerStartParams *start_params, int fd)
{
	int res = -1;

	// Setup smartcard response handling
	if (start_params || container_get_usb_pin_entry(container)) {
		control_csmartcard_resp_data_t *cbdata =
			mem_new0(control_csmartcard_resp_data_t, 1);
		cbdata->container_ctrl = CMLD_CONTAINER_CTRL_STOP;
		cbdata->resp_fd = fd;

		if (container_set_smartcard_error_cb(container, control_csmartcard_handle_error_cb,
						     cbdata))
			mem_free(cbdata);
	}

	// Check if pin should be interactively requested via pin pad reader
	if (container_get_usb_pin_entry(container)) {
		TRACE("Container stop with pin entry chosen. Stopping");
		int *resp_fd = mem_new0(int, 1);
		*resp_fd = fd;
		res = cmld_container_ctrl_with_input(container, CMLD_CONTAINER_CTRL_STOP,
						     control_input_handle_error_cb, resp_fd);
		if (res != 0) {
			control_send_message(CONTROL_RESPONSE_CONTAINER_USB_PIN_ENTRY_FAIL, fd);
		}
	} else if (start_params) {
		char *key = start_params->key;
		TRACE("Default container stop without pin entry chosen. Stopping");
		res = cmld_container_ctrl_with_smartcard(container, key, CMLD_CONTAINER_CTRL_STOP);
		if (res != 0) {
			ERROR("Failed to stop container %s", container_get_name(container));
		}
		if (res == -2)
			control_send_message(CONTROL_RESPONSE_CONTAINER_CTRL_EINTERNAL, fd);

		mem_memset0(key, strlen(key));
	} else if (container_is_encrypted(container)) {
		res = -1;
		control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_PASSWD_WRONG, fd);
	} else {
		res = cmld_container_stop(container);
		if (res == -1) {
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_FAILED_NOT_RUNNING,
					     fd);
		} else {
			control_send_message(CONTROL_RESPONSE_CONTAINER_STOP_OK, fd);
		}
	}
	return res;
}

static bool
control_check_command(control_t *control, const ControllerToDaemon *msg)
{
#ifdef CC_MODE
	/* filter all unused command codes using a whitelist; generate a clientside .proto
	 * which only includes allowed messsages
	 */
	if (!((msg->command == CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__LIST_CONTAINERS) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CREATE_CONTAINER) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__REMOVE_CONTAINER) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__REGISTER_NEWCA) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__REBOOT_DEVICE) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__SET_PROVISIONED) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_PROVISIONED) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__PULL_DEVICE_CSR) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__PUSH_DEVICE_CERT) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_LIST_IFACES) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UPDATE_CONFIG) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CHANGE_TOKEN_PIN) ||
	      (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CMLD_HANDLES_PIN))) {
		TRACE("Received command %d is invalid in CC mode", msg->command);
		return false;
	}
#endif

	if (!control->privileged) {
		// Device is in unprivileged mode, only allow subset of commands
		if ((msg->command == CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS) ||
		    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG) ||
		    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__REGISTER_LOCALCA)) {
			TRACE("Received command %d is valid in unprivileged mode", msg->command);
			return true;
		} else {
			return false;
		}
	}

	// Device is in privileged mode and not yet provisioned or in hosted mode,
	// allow all commands
	if (!cmld_is_device_provisioned() || cmld_is_hostedmode_active()) {
		TRACE("Device is not provisioned or in hosted mode, all commands are accepted");
		return true;
	}
	// Device is in privileged provisioned mode, only allow subset of commands
	if ((msg->command == CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__LIST_CONTAINERS) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CHANGE_TOKEN_PIN) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CREATE_CONTAINER) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__REBOOT_DEVICE) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_PROVISIONED) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UPDATE_CONFIG) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CMLD_HANDLES_PIN) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_LIST_IFACES) ||
	    (msg->command == CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG)) {
		TRACE("Received command %d is valid in provisioned mode", msg->command);
		return true;
	}

	TRACE("Received command %d is not allowed in provisioned %s mode", msg->command,
	      control->privileged ? "privileged" : "unprivileged");
	return false;
}

/**
 * Handles a single decoded ControllerToDaemon message.
 *
 * @param msg	the ControllerToDaemon message to be handled
 * @param fd	file descriptor of the client connection
 *		(for sending a response, if necessary)
 */
static void
control_handle_message(control_t *control, const ControllerToDaemon *msg, int fd)
{
	int res = -1;
	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text;

		size_t msg_len =
			protobuf_string_from_message(&msg_text, (ProtobufCMessage *)msg, NULL);

		TRACE("Handling ControllerToDaemon message:\n%s", msg_len > 0 ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	// Check if this is a valid mode depending on the current mode
	if (!control_check_command(control, msg)) {
		WARN("Illegal ControllerToDaemon command: %d received. Command is only valid in non-provisioned or hosted mode",
		     msg->command);
		control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, fd);
		return;
	}

	// get container for container-specific commands in advance
	container_t *container =
		(msg->n_container_uuids == 1) ?
			control_get_container_by_uuid_string(msg->container_uuids[0]) :
			NULL;

	// Trace user for audit
	if (container) {
		uint32_t uid;
		if (sock_unix_get_peer_uid(fd, &uid) != 0) {
			WARN_ERRNO("Could not set login uid for control connection!");
		} else {
			container_audit_set_loginuid(container, uid);
		}
	}

	switch (msg->command) {
		// Global commands:

	case CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS: {
		control_handle_cmd_list_guestos_configs(msg, fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__LIST_CONTAINERS: {
		// assemble list of relevant containers and allocate memory for result
		size_t n = cmld_containers_get_count();
		char **results = mem_new(char *, n);

		// fill result with data from guestos
		for (size_t i = 0; i < n; i++) {
			container_t *container = cmld_container_get_by_index(i);
			const char *uuid = uuid_string(container_get_uuid(container));
			results[i] = mem_strdup(uuid);
		}

		// build and send response message to controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINERS_LIST;
		out.n_container_uuids = n;
		out.container_uuids = results;
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send list of containers to MDM");
		}

		// collect garbage
		for (size_t i = 0; i < n; i++)
			mem_free0(results[i]);
		mem_free0(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS: {
		// assemble list of relevant containers and allocate memory for result
		list_t *containers = control_build_container_list_from_uuids(msg->n_container_uuids,
									     msg->container_uuids);
		size_t n = list_length(containers);
		ContainerStatus **results = mem_new(ContainerStatus *, n);

		// fill result with data from container
		for (size_t i = 0; i < n; i++) {
			container_t *container = list_nth_data(containers, i);
			results[i] = control_container_status_new(container);
		}

		// build and send response message to controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_STATUS;
		out.n_container_status = n;
		out.container_status = results;
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container status to MDM");
		}

		// collect garbage
		list_delete(containers);
		for (size_t i = 0; i < n; i++)
			control_container_status_free(results[i]);
		mem_free0(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG: {
		// assemble list of relevant containers and allocate memory for result
		list_t *containers = control_build_container_list_from_uuids(msg->n_container_uuids,
									     msg->container_uuids);
		size_t n = list_length(containers);
		ContainerConfig **results = mem_new0(ContainerConfig *, n);
		char **result_uuids = mem_new(char *, n);

		size_t number_of_configs = 0;
		// fill result with data from container
		for (size_t i = 0; i < n; i++) {
			container_t *container = list_nth_data(containers, i);
			if (!container) {
				FATAL("Got NULL container pointer!");
			}
			TRACE("Getting container config for container %s",
			      container_get_name(container));
			const char *config_filename = container_get_config_filename(container);
			if (!config_filename) {
				WARN("Container %s has no config file set. Skipping.",
				     container_get_name(container));
			} else {
				TRACE("Container %s has config file; appending to list...",
				      container_get_name(container));
				results[number_of_configs] =
					(ContainerConfig *)protobuf_message_new_from_textfile(
						config_filename, &container_config__descriptor);
				if (results[number_of_configs] == NULL) {
					WARN("The config file of container %s is missing. Skipping.",
					     container_get_name(container));
					continue;
				}
				// overwrite vnet config with runtime configuration
				size_t n_vnet_configs = results[number_of_configs]->n_vnet_configs;
				for (size_t i = 0; i < n_vnet_configs; ++i) {
					protobuf_free_message(
						(ProtobufCMessage *)results[number_of_configs]
							->vnet_configs[i]);
					TRACE("freed config time results[%zu]->vnet_configs[%zu]",
					      number_of_configs, i);
				}
				mem_free0(results[number_of_configs]->vnet_configs);
				list_t *vnet_runtime_cfg_list =
					container_get_vnet_runtime_cfg_new(container);
				int vnet_config_len = list_length(vnet_runtime_cfg_list);
				ContainerVnetConfig **vnet_configs =
					mem_new0(ContainerVnetConfig *, vnet_config_len);
				for (int i = 0; i < vnet_config_len; ++i) {
					container_vnet_cfg_t *vnet_cfg =
						list_nth_data(vnet_runtime_cfg_list, i);
					vnet_configs[i] = mem_new0(ContainerVnetConfig, 1);
					container_vnet_config__init(vnet_configs[i]);
					vnet_configs[i]->if_name = mem_strdup(vnet_cfg->vnet_name);
					if (vnet_cfg->rootns_name)
						vnet_configs[i]->if_rootns_name =
							mem_strdup(vnet_cfg->rootns_name);
					vnet_configs[i]->if_mac = mem_printf(
						"%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
						":%02" PRIx8 ":%02" PRIx8,
						vnet_cfg->vnet_mac[0], vnet_cfg->vnet_mac[1],
						vnet_cfg->vnet_mac[2], vnet_cfg->vnet_mac[3],
						vnet_cfg->vnet_mac[4], vnet_cfg->vnet_mac[5]);
					vnet_configs[i]->configure = vnet_cfg->configure;
					TRACE("setup runtime vnet_configs[%d] vnetc: %s, vnetr: %s (%s)",
					      i, vnet_configs[i]->if_name,
					      vnet_configs[i]->if_rootns_name,
					      vnet_configs[i]->configure ? "configured" : "manual");
					mem_free0(vnet_cfg);
				}
				list_delete(vnet_runtime_cfg_list);
				results[number_of_configs]->n_vnet_configs = vnet_config_len;
				results[number_of_configs]->vnet_configs = vnet_configs;

				const char *uuid = uuid_string(container_get_uuid(container));
				result_uuids[number_of_configs] = mem_strdup(uuid);
				number_of_configs++;
			}
		}
		// build and send response message to controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_CONFIG;
		if (number_of_configs == 0) {
			WARN("Could not get any container configs");
			out.n_container_configs = 0;
			out.container_configs = NULL;
		} else {
			TRACE("Got %zu container configs", number_of_configs);
			out.n_container_configs = number_of_configs;
			out.container_configs = results;
			out.n_container_uuids = number_of_configs;
			out.container_uuids = result_uuids;
		}
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container configs to MDM");
		}

		// collect garbage
		list_delete(containers);
		for (size_t i = 0; i < number_of_configs; i++) {
			mem_free0(result_uuids[i]);
			if (results[i] != NULL)
				protobuf_free_message((ProtobufCMessage *)results[i]);
		}
		mem_free0(result_uuids);
		mem_free0(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_LAST_LOG: {
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__RESPONSE;
		out.has_response = true;
		out.response = DAEMON_TO_CONTROLLER__RESPONSE__CMD_FAILED;

		int dir_ret =
			dir_foreach(LOGFILE_DIR, &control_send_file_as_log_message_cb, (void *)&fd);

		if (dir_ret < 0) {
			WARN("Something went wrong during traversal of LOGFILE_DIR");
		} else if (dir_ret > 0) {
			WARN("%d logs could not be sent.", dir_ret);
		} else {
			out.response = DAEMON_TO_CONTROLLER__RESPONSE__CMD_OK;
		}
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			ERROR_ERRNO("Could not finish send LOG_END message");
			break;
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG: {
		control_handle_cmd_push_guestos_configs(msg, fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__REMOVE_GUESTOS: {
		if (!msg->guestos_name) {
			WARN("REMOVE_GUESTOS without name");
			control_send_message(CONTROL_RESPONSE_CMD_FAILED, fd);
		} else {
			res = cmld_guestos_delete(msg->guestos_name);
			control_send_message(
				res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK, fd);
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__REGISTER_NEWCA: {
		if (!msg->has_guestos_rootcert) {
			WARN("REGISTER_NEWCA without root certificate");
			res = -1;
		} else {
			res = guestos_mgr_register_newca(msg->guestos_rootcert.data,
							 msg->guestos_rootcert.len);
		}
		if (res == -1)
			control_send_message(CONTROL_RESPONSE_GUESTOS_MGR_REGISTER_CA_ERROR, fd);
		else
			control_send_message(CONTROL_RESPONSE_GUESTOS_MGR_REGISTER_CA_OK, fd);

	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__REGISTER_LOCALCA: {
		control_handle_cmd_register_localca(msg, fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__RELOAD_CONTAINERS: {
		res = cmld_reload_containers();
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__WIPE_DEVICE: {
		cmld_wipe_device();
		control_send_message(CONTROL_RESPONSE_CMD_OK, fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__REBOOT_DEVICE: {
		control_send_message(CONTROL_RESPONSE_CMD_OK, fd);
		cmld_reboot_device();
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__PULL_DEVICE_CSR: {
		uint8_t *csr = NULL;
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		csr = crypto_pull_device_csr_new(&out.device_csr.len);
		out.code = DAEMON_TO_CONTROLLER__CODE__DEVICE_CSR;
		out.has_device_csr = csr ? true : false;
		out.device_csr.data = csr;

		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send device csr!");
		}
		if (csr)
			mem_free0(csr);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__PUSH_DEVICE_CERT: {
		uint8_t *cert = NULL;
		ssize_t cert_len = 0;
		if (msg->has_device_cert) {
			cert = msg->device_cert.data;
			cert_len = msg->device_cert.len;
		}
		crypto_push_device_cert(fd, cert, cert_len);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__SET_PROVISIONED: {
		res = cmld_set_device_provisioned();
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_PROVISIONED: {
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__DEVICE_PROVISIONED_STATE;
		out.has_device_is_provisioned = true;
		out.device_is_provisioned = cmld_is_device_provisioned();

		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
			WARN("Could not send provisioned state");
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CREATE_CONTAINER: {
		char **cuuid_str = NULL;
		ContainerConfig **ccfg = NULL;

		// build default response message for controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_CONFIG;
		out.n_container_configs = 0;
		out.n_container_uuids = 0;

		if (!msg->has_container_config_file || msg->container_config_file.data == NULL) {
			WARN("CREATE_CONTAINER without config file does not work, doing nothing...");
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to CREATE");
			break;
		}
		container_t *c = NULL;
		if (msg->has_container_config_signature && msg->has_container_config_certificate) {
			c = cmld_container_create_from_config(
				msg->container_config_file.data, msg->container_config_file.len,
				msg->container_config_signature.data,
				msg->container_config_signature.len,
				msg->container_config_certificate.data,
				msg->container_config_certificate.len);
		} else {
			c = cmld_container_create_from_config(msg->container_config_file.data,
							      msg->container_config_file.len, NULL,
							      0, NULL, 0);
		}
		if (NULL == c) {
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to CREATE");
			break;
		}

		ccfg = mem_new(ContainerConfig *, 1);
		ccfg[0] = (ContainerConfig *)protobuf_message_new_from_textfile(
			container_get_config_filename(c), &container_config__descriptor);
		cuuid_str = mem_new(char *, 1);
		cuuid_str[0] = mem_strdup(uuid_string(container_get_uuid(c)));

		if (!ccfg[0]) {
			ERROR("Failed to get new config for %s", cuuid_str[0]);
			mem_free0(ccfg);
			mem_free0(cuuid_str[0]);
			mem_free0(cuuid_str);
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to CREATE");
			break;
		}
		// build and send response message to controller
		out.n_container_configs = 1;
		out.container_configs = ccfg;
		out.n_container_uuids = 1;
		out.container_uuids = cuuid_str;
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container config as Response to CREATE");
		}
		mem_free0(cuuid_str[0]);
		mem_free0(cuuid_str);
		protobuf_free_message((ProtobufCMessage *)ccfg[0]);
		mem_free0(ccfg);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_DEVICE_STATS: {
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__DEVICE_STATS;

		DeviceStats *device_stats = mem_new(DeviceStats, 1);
		device_stats__init(device_stats);

		device_stats->disk_system = file_disk_space(cmld_get_cmld_dir());
		device_stats->disk_system_free = file_disk_space_free(cmld_get_cmld_dir());
		device_stats->disk_system_used = file_disk_space_used(cmld_get_cmld_dir());

		if (!file_on_same_fs(cmld_get_cmld_dir(), cmld_get_containers_dir())) {
			device_stats->has_disk_containers = true;
			device_stats->has_disk_containers_free = true;
			device_stats->has_disk_containers_used = true;
			device_stats->disk_containers = file_disk_space(cmld_get_containers_dir());
			device_stats->disk_containers_free =
				file_disk_space_free(cmld_get_containers_dir());
			device_stats->disk_containers_used =
				file_disk_space_used(cmld_get_containers_dir());
		}

		proc_meminfo_t *meminfo = proc_meminfo_new();
		if (meminfo) {
			device_stats->has_mem_total = true;
			device_stats->has_mem_free = true;
			device_stats->has_mem_available = true;
			device_stats->mem_total = proc_get_mem_total(meminfo);
			device_stats->mem_free = proc_get_mem_free(meminfo);
			device_stats->mem_available = proc_get_mem_available(meminfo);
		}

		out.device_stats = device_stats;

		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
			WARN("Could not send provisioned state");

		proc_meminfo_free(meminfo);
		protobuf_free_message((ProtobufCMessage *)device_stats);
	} break;

	// Container-specific commands:
	case CONTROLLER_TO_DAEMON__COMMAND__REMOVE_CONTAINER:
		if (NULL == container) {
			INFO("Container does not exist, nothing to destroy!");
			control_send_message(CONTROL_RESPONSE_CMD_FAILED, fd);
			break;
		}
		res = cmld_container_destroy(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UPDATE_CONFIG: {
		char **cuuid_str = NULL;
		ContainerConfig **ccfg = NULL;

		// build default response message for controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_CONFIG;
		out.n_container_configs = 0;
		out.n_container_uuids = 0;

		if (NULL == container) {
			WARN("Container does not exist!");
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to UPDATE_CONFIG");
			break;
		}
		if (!msg->has_container_config_file) {
			WARN("UPDATE_CONFIG without config file does not work, doing nothing...");
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to UPDATE_CONFIG");
			break;
		}
		if (msg->has_container_config_signature && msg->has_container_config_certificate) {
			res = cmld_update_config(container, msg->container_config_file.data,
						 msg->container_config_file.len,
						 msg->container_config_signature.data,
						 msg->container_config_signature.len,
						 msg->container_config_certificate.data,
						 msg->container_config_certificate.len);
		} else {
			res = cmld_update_config(container, msg->container_config_file.data,
						 msg->container_config_file.len, NULL, 0, NULL, 0);
		}
		if (res) {
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to UPDATE_CONFIG");
			break;
		}

		ccfg = mem_new(ContainerConfig *, 1);
		ccfg[0] = (ContainerConfig *)protobuf_message_new_from_textfile(
			container_get_config_filename(container), &container_config__descriptor);
		cuuid_str = mem_new(char *, 1);
		cuuid_str[0] = mem_strdup(uuid_string(container_get_uuid(container)));

		if (!ccfg[0]) {
			ERROR("Failed to get new config for %s", cuuid_str[0]);
			mem_free0(ccfg);
			mem_free0(cuuid_str[0]);
			mem_free0(cuuid_str);
			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
				WARN("Could not send empty Response to UPDATE_CONFIG");
			break;
		}
		// reload configs if container is in state
		compartment_state_t state = container_get_state(container);
		if (state == COMPARTMENT_STATE_STOPPED) {
			// Reload container to make changes effective
			TRACE("Update: Reloading container %s from %s",
			      uuid_string(container_get_uuid(container)),
			      cmld_get_containers_dir());
			if (!cmld_reload_container(container_get_uuid(container),
						   cmld_get_containers_dir())) {
				ERROR("Failed to reload container on config update");
			}
		}

		// build and send response message to controller
		out.n_container_configs = 1;
		out.container_configs = ccfg;
		out.n_container_uuids = 1;
		out.container_uuids = cuuid_str;
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container config as Response to UPDATE_CONFIG");
		}
		mem_free0(cuuid_str[0]);
		mem_free0(cuuid_str);
		protobuf_free_message((ProtobufCMessage *)ccfg[0]);
		mem_free0(ccfg);
	} break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START: {
		if (NULL == container) {
			audit_log_event(NULL, FSA, CMLD, CONTAINER_MGMT,
					"container-start-not-existing", NULL, 0);
			WARN("Container does not exist!");
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_EEXIST, fd);
			break;
		}
		if (cmld_containers_get_c0() == container) {
			ERROR("CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START for c0!");
			control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, fd);
			break;
		}
		compartment_state_t compartment_state = container_get_state(container);
		if ((compartment_state == COMPARTMENT_STATE_RUNNING) ||
		    (compartment_state == COMPARTMENT_STATE_BOOTING) ||
		    (compartment_state == COMPARTMENT_STATE_SETUP) ||
		    (compartment_state == COMPARTMENT_STATE_REBOOTING) ||
		    (compartment_state == COMPARTMENT_STATE_STARTING)) {
			WARN("Container is already running or in the process of starting up!");
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"container-start-already-running",
					uuid_string(container_get_uuid(container)), 0);
			control_send_message(CONTROL_RESPONSE_CONTAINER_START_EEXIST, fd);
			break;
		}
		ContainerStartParams *start_params = msg->container_start_params;
		res = control_handle_container_start(container, start_params, fd);
		if (res) {
			WARN("Starting container failed!");
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP:
		IF_NULL_RETURN(container);

		if (cmld_containers_get_c0() == container) {
			ERROR("CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP for c0!");
			control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, fd);
			break;
		}

		ContainerStartParams *start_params = msg->container_start_params;
		res = control_handle_container_stop(container, start_params, fd);
		if (res) {
			WARN("Stoping container failed!");
		}
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_FREEZE:
		IF_NULL_RETURN(container);
		res = cmld_container_freeze(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNFREEZE:
		IF_NULL_RETURN(container);
		res = cmld_container_unfreeze(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ALLOWAUDIO:
		IF_NULL_RETURN(container);
		res = cmld_container_allow_audio(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_DENYAUDIO:
		IF_NULL_RETURN(container);
		res = cmld_container_deny_audio(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_WIPE:
		IF_NULL_RETURN(container);
		res = cmld_container_wipe(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SNAPSHOT:
		IF_NULL_RETURN(container);
		res = cmld_container_snapshot(container);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ASSIGNIFACE: {
		IF_NULL_RETURN(container);
		if (!msg->assign_iface_params || !msg->assign_iface_params->iface_name) {
			ERROR("Missing net iface information");
			break;
		}
		char *net_iface = msg->assign_iface_params->iface_name;
		bool persistent = (!msg->assign_iface_params->has_persistent) ?
					  false :
					  msg->assign_iface_params->persistent;
		container_pnet_cfg_t *pnet_cfg = container_pnet_cfg_new(net_iface, false, NULL);
		res = cmld_container_add_net_iface(container, pnet_cfg, persistent);
		if (res) {
			container_pnet_cfg_free(pnet_cfg);
			control_send_message(CONTROL_RESPONSE_CMD_FAILED, fd);
		} else {
			control_send_message(CONTROL_RESPONSE_CMD_OK, fd);
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNASSIGNIFACE: {
		IF_NULL_RETURN(container);
		if (!msg->assign_iface_params || !msg->assign_iface_params->iface_name) {
			ERROR("Missing net iface information");
			break;
		}
		char *net_iface = msg->assign_iface_params->iface_name;
		bool persistent = (!msg->assign_iface_params->has_persistent) ?
					  false :
					  msg->assign_iface_params->persistent;
		res = cmld_container_remove_net_iface(container, net_iface, persistent);
		control_send_message(res ? CONTROL_RESPONSE_CMD_FAILED : CONTROL_RESPONSE_CMD_OK,
				     fd);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_LIST_IFACES: {
		IF_NULL_RETURN(container);
		pid_t pid = container_get_pid(container);
		list_t *link_list = NULL;
		network_list_link_ns(pid, &link_list);

		// build and send response message to controller
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_IFACES;

		size_t n = list_length(link_list);
		char **results = mem_new(char *, n);

		for (size_t i = 0; i < n; i++) {
			char *link_line = list_nth_data(link_list, i);
			results[i] = mem_strdup(link_line);
		}

		out.n_container_ifaces = n;
		out.container_ifaces = results;
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container network interfaces to MDM");
		}

		// collect garbage
		list_delete(link_list);
		for (size_t i = 0; i < n; i++)
			mem_free0(results[i]);
		mem_free0(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_CMD: {
		IF_NULL_RETURN(container);
		TRACE("Got exec command: %s, attach PTY: %d", msg->exec_command, msg->exec_pty);
		if (!msg->exec_command || !msg->has_exec_pty) {
			ERROR("Missing command or exec_pty info");
			break;
		}
		if (container_run(container, msg->exec_pty, msg->exec_command, msg->n_exec_args,
				  msg->exec_args, fd) < 0) {
			ERROR("Failed to exec");

			DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
			out.code = DAEMON_TO_CONTROLLER__CODE__EXEC_END;

			if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
				WARN("Could not send exec output to MDM");
			}

			TRACE("Sent notification of command termination to control client");
			break;

		} else {
			DEBUG("Registering read callback for cmld console socket");
			int *cfd = mem_new(int, 1);
			*cfd = fd;
			event_io_t *event =
				event_io_new(container_get_console_sock_cmld(container, fd),
					     EVENT_IO_READ | EVENT_IO_EXCEPT,
					     control_cb_read_console, cfd);
			event_add_io(event);
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_EXEC_INPUT: {
		IF_NULL_RETURN(container);
		TRACE("Got input for exec'ed process. Sending message on fd");

		int ret = container_write_exec_input(container, msg->exec_input, fd);
		if (ret < 0) {
			ERROR_ERRNO("Failed to write input to exec'ed process");
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CHANGE_TOKEN_PIN: {
		IF_NULL_RETURN(container);
		if (cmld_containers_get_c0() == container) {
			ERROR("CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CHANGE_TOKEN_PIN for c0!");
			control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, fd);
			break;
		}

		if (msg->device_pin == NULL || msg->device_newpin == NULL) {
			ERROR("Current PIN or new PIN not specified");
			break;
		}
		control_csmartcard_resp_data_t *cbdata =
			mem_new0(control_csmartcard_resp_data_t, 1);
		cbdata->resp_fd = fd;

		if (container_set_smartcard_error_cb(container, control_csmartcard_handle_error_cb,
						     cbdata))
			mem_free(cbdata);

		res = cmld_container_change_pin(container, msg->device_pin, msg->device_newpin);
		if (res) {
			WARN("Changing the container PIN failed!");
		}
		mem_memset0(msg->device_pin, strlen(msg->device_pin));
		mem_memset0(msg->device_newpin, strlen(msg->device_newpin));
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_CMLD_HANDLES_PIN: {
		IF_NULL_RETURN(container);
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__CONTAINER_CMLD_HANDLES_PIN;
		out.has_container_cmld_handles_pin = true;
		out.container_cmld_handles_pin = container_get_usb_pin_entry(container);
		if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0) {
			WARN("Could not send container cmld handles pin info");
		}
	} break;

	default:
		WARN("Unsupported ControllerToDaemon command: %d received", msg->command);
		if (control_send_message(CONTROL_RESPONSE_CMD_UNSUPPORTED, fd))
			WARN("Could not send response to fd=%d", fd);
	}
}

/**
 * Event callback for incoming data that receives a ControllerToDaemon message (local)
 *
 * The handle_message function will be called to handle the received message.
 *
 * @param fd	    file descriptor of the client connection
 *		    from which the incoming message is read
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this control_t struct
 */
static void
control_cb_recv_message_local(int fd, unsigned events, event_io_t *io, void *data)
{
	control_t *control = data;
	/*
	 * always check READ flag first, since also if the peer called close()
	 * and there is pending data on the socet the READ and EXCEPT flags are set.
	 * Thus, we have to read pending date before handling the EXCEPT event.
	 */
	if (events & EVENT_IO_READ) {
		ControllerToDaemon *msg = (ControllerToDaemon *)protobuf_recv_message(
			fd, &controller_to_daemon__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);
		control_handle_message(control, msg, fd);
		TRACE("Handled control connection %d", fd);
		protobuf_free_message((ProtobufCMessage *)msg);
	}
	// also check EXCEPT flag
	if (events & EVENT_IO_EXCEPT) {
		INFO("Control client closed connection; disconnecting control socket.");
		goto connection_err;
	}
	return;

connection_err:
	cmld_container_ctrl_with_input_abort();
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected control socket");
	control->event_io_sock_connected_list =
		list_remove(control->event_io_sock_connected_list, io);
	return;
}

/**
 * Event callback for accepting incoming connections on the listening socket.
 *
 * @param fd	    file descriptor of the listening socket
 *		    from which incoming connectionis should be accepted
 * @param events    event flags
 * @param io	    pointer to associated event_io_t struct
 * @param data	    pointer to this control_t struct
  */
static void
control_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	control_t *control = (control_t *)data;
	ASSERT(control);
	ASSERT(control->sock == fd);

	if (events & EVENT_IO_EXCEPT) {
		TRACE("EVENT_IO_EXCEPT on socket %d, closing...", fd);
		event_remove_io(io);
		event_io_free(io);
		close(fd);
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	int cfd = accept(fd, NULL, 0);
	if (-1 == cfd) {
		WARN("Could not accept control connection");
		return;
	}
	DEBUG("Accepted control connection %d", cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event =
		event_io_new(cfd, EVENT_IO_READ, control_cb_recv_message_local, control);
	DEBUG("local control client connected on fd=%d", cfd);

	event_add_io(event);
}

control_t *
control_new(int sock, bool privileged)
{
	if (listen(sock, CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	control_t *control = mem_new0(control_t, 1);
	control->sock = sock;
	control->privileged = privileged;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, control_cb_accept, control);
	event_add_io(event);

	return control;
}

control_t *
control_local_new(const char *path)
{
	control_t *control;
	int sock = sock_unix_create_and_bind(SOCK_STREAM, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	control = control_new(sock, true);

	return control;
}

void
control_free(control_t *control)
{
	ASSERT(control);
	for (list_t *l = control->event_io_sock_connected_list; l; l = l->next) {
		event_io_t *event_io_sock_connected = l->data;
		event_remove_io(event_io_sock_connected);
		shutdown(event_io_get_fd(event_io_sock_connected), SHUT_RDWR);
		if (close(event_io_get_fd(event_io_sock_connected) < 0)) {
			WARN_ERRNO("Failed to close connected control socket");
		}
		event_io_free(event_io_sock_connected);
	}
	list_delete(control->event_io_sock_connected_list);
	control->event_io_sock_connected_list = NULL;

	control_list = list_remove(control_list, control);

	mem_free0(control);
	return;
}
