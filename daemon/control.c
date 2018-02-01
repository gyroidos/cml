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

#include "control.h"
#ifdef ANDROID
#include "device/fraunhofer/common/cml/daemon/control.pb-c.h"
#include "device/fraunhofer/common/cml/daemon/container.pb-c.h"
#else
#include "control.pb-c.h"
#include "container.pb-c.h"
#endif

#include "container.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "cmld.h"
#include "hardware.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/protobuf.h"
#include "common/sock.h"
#include "common/uuid.h"
#include "common/event.h"
#include "common/fd.h"
#include "common/logf.h"
#include "common/list.h"

#include <unistd.h>

#include <protobuf-c-text/protobuf-c-text.h>

// maximum no. of connections waiting to be accepted on the listening socket
#define CONTROL_SOCK_LISTEN_BACKLOG 8

// time between reconnection attempts of a remote client socket
#define CONTROL_REMOTE_RECONNECT_INTERVAL 10000

#define LOGGER_ENTRY_MAX_LEN             (5*1024)

struct control {
	int sock;		// listen socket fd
	int sock_client;
	//char const *format;	// TBD control message encoding format
	//uint32_t permissions; // TBD
	int type;
	char *hostip;		// remote host for inet (MDM) connection
	int port;		// remote port
	bool connected; // FIXME: we should reconsider this...
	event_timer_t *reconnect_timer;
};

// TODO really?!
static list_t *control_list = NULL;
UNUSED static logf_handler_t *control_logf_handler = NULL;

static int
control_remote_reconnect(control_t *control);

UNUSED static void
control_logf(logf_prio_t prio, const char *msg, UNUSED void *data)
{
	static bool log_bomb_prevention = false;
	if (log_bomb_prevention) {
		return;
	}
	log_bomb_prevention = true;

	if (prio < LOGF_PRIO_DEBUG) {
		log_bomb_prevention = false;
		return;
	}

	//Prevent the child process (after clone in container startup) from writing
	//to the socket
	if (getpid() == 1)
		return;

	for (list_t *l = control_list; l; l = l->next) {
		control_t *control = l->data;

		if (!control->connected)
			continue;

		LogMessage message = LOG_MESSAGE__INIT;
		message.prio = (LogPriority) prio; // FIXME
		message.msg = mem_strdup(msg);
		DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
		out.code = DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE;
		out.log_message = &message;
		if (cmld_get_device_uuid()) {
			out.device_uuid = mem_strdup(cmld_get_device_uuid());
		}
		if (protobuf_send_message(control->sock_client, (ProtobufCMessage *) &out) < 0) {
			WARN("Could not send log message");
			//Do not try to reconnect here
			//Reconnection handling is done by control_cb_recv_message()
		}
		mem_free(message.msg);
		mem_free(out.device_uuid);
	}
	log_bomb_prevention = false;
}

static void
UNUSED control_send_log_file(int fd, char *log_file_name, bool read_low_level,
						bool send_last_line_info)
{
	int fp_low = -1;
	bool skipped_lines = false;
	FILE *fp = NULL;
	char* line;
	char line_low[LOGGER_ENTRY_MAX_LEN+1];
	size_t HEADER_LENGTH = 21;
	ssize_t bytes_read;
	bool file_is_open = false;

	LogMessage message = LOG_MESSAGE__INIT;
	message.prio = (LogPriority) LOGF_PRIO_DEBUG;
	DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
	out.code = DAEMON_TO_CONTROLLER__CODE__LOG_MESSAGE;
	if (cmld_get_device_uuid()) {
		TRACE("Setting uuid: %s", cmld_get_device_uuid());
		out.device_uuid = mem_strdup(cmld_get_device_uuid());
	}

	DEBUG("Opening and sending %s", log_file_name);
	if (read_low_level) {
		fp_low = open(log_file_name, O_RDONLY | O_NONBLOCK);
		if (fp_low == -1) {
			ERROR("Could not open %s", log_file_name);
		}
		else {
			file_is_open = true;
		}
	} else {
		fp = fopen(log_file_name, "r");
		line = NULL;
		if (fp == NULL) {
			ERROR("Could not open %s", log_file_name);
		}
		else {
			file_is_open = true;
		}
	}

	while (file_is_open) {
		if (read_low_level) {
            /* The driver let's us read entry by entry */
			bytes_read = read(fp_low, line_low, LOGGER_ENTRY_MAX_LEN);
			if (bytes_read <= 0)
				break;
			char *first_string = line_low+HEADER_LENGTH;
			size_t string_len = strlen(first_string);
			char *second_string = line_low+HEADER_LENGTH+string_len+1;
			message.msg = mem_printf("%s/%s", first_string, second_string);
		} else {
			size_t len = 0;
			bytes_read = getline(&line, &len, fp);
			if (bytes_read == -1)
				break;
			message.msg = mem_strdup(line);
		}
		out.log_message = &message;
		if (protobuf_send_message(fd, (ProtobufCMessage *) &out) < 0) {
			ERROR_ERRNO("Could not finish sending %s", log_file_name);
			skipped_lines = true;
			break;
		}
		mem_free(message.msg);
	}
	if (send_last_line_info) {
		message.msg = "Last line of log";
		out.log_message = &message;
		if (protobuf_send_message(fd, (ProtobufCMessage *) &out) < 0) {
			ERROR("Could not sent last line info for %s", log_file_name);
		}
	}
	mem_free(out.device_uuid);
	if (file_is_open) {
		if (read_low_level) {
			close(fp_low);
		}
		else {
			fclose(fp);
			if (line)
				free(line);
		}
	}

	if (!skipped_lines) {
		DEBUG("Finished sending complete %s", log_file_name);
	} else {
		DEBUG("Finished sending %s; skipped lines", log_file_name);
	}
}

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
ContainerState
control_container_state_to_proto(container_state_t state)
{
	switch (state) {
	case CONTAINER_STATE_STOPPED:
		return CONTAINER_STATE__STOPPED;
	case CONTAINER_STATE_STARTING:
		return CONTAINER_STATE__STARTING;
	case CONTAINER_STATE_BOOTING:
		return CONTAINER_STATE__BOOTING;
	case CONTAINER_STATE_RUNNING:
		return CONTAINER_STATE__RUNNING;
	case CONTAINER_STATE_FREEZING:
		return CONTAINER_STATE__FREEZING;
	case CONTAINER_STATE_FROZEN:
		return CONTAINER_STATE__FROZEN;
	case CONTAINER_STATE_ZOMBIE:
		return CONTAINER_STATE__ZOMBIE;
	case CONTAINER_STATE_SHUTTING_DOWN:
		return CONTAINER_STATE__SHUTDOWN;
	default:
		FATAL("Unhandled value for container_state_t: %d", state);
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
	c_status->has_foreground = true;
	c_status->foreground = (cmld_containers_get_foreground() == container);
	c_status->state = control_container_state_to_proto(container_get_state(container));
	c_status->uptime = container_get_uptime(container);
	c_status->created = container_get_creation_time(container);
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
	mem_free(c_status->name);
	mem_free(c_status->uuid);
	mem_free(c_status);
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
	if (n_uuids > 0) {    // uuid list given in incoming message
		for (size_t i = 0; i < n_uuids; i++) {
			container_t *container = control_get_container_by_uuid_string(uuids[i]);
			if (container != NULL)
				containers = list_append(containers, container);
		}
	} else {    // empty uuid list, return status for all containers
		n_uuids = cmld_containers_get_count();
		for (size_t i = 0; i < n_uuids; i++) {
			container_t *container = cmld_container_get_by_index(i);
			containers = list_append(containers, container);
		}
	}
	return containers;
}

int
control_get_client_sock(control_t *control)
{
	return control->sock_client;
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

		case CONTROL_RESPONSE_CONTAINER_START_LOCKED_TILL_REBOOT:
			out.response = DAEMON_TO_CONTROLLER__RESPONSE__CONTAINER_START_LOCKED_TILL_REBOOT;
			break;

		default:
			DEBUG("Unknown message `%d' (not sent)", message);
			return -1;
	}

	return protobuf_send_message(fd, (ProtobufCMessage *)&out);
}

/**
 * Handles a single decoded ControllerToDaemon message.
 *
 * @param msg	the ControllerToDaemon message to be handled
 * @param fd	file descriptor of the client connection
 *		(for sending a response, if necessary)
 */
static void
control_handle_message(const ControllerToDaemon *msg, int fd)
{
	// TODO cases when and how to report the result back to the caller?
	// => for now, only reply if there is actual data to be sent back to the caller
	UNUSED int res = -1;
	if (NULL == msg) {
		WARN("msg=NULL, returning");
		return;
	}

	if (LOGF_PRIO_TRACE >= LOGF_LOG_MIN_PRIO) {
		char *msg_text = protobuf_c_text_to_string((ProtobufCMessage *)msg, NULL);
		TRACE("Handling ControllerToDaemon message:\n%s", msg_text ? msg_text : "NULL");
		if (msg_text)
			free(msg_text);
	}

	// get container for container-specific commands in advance
	container_t *container = (msg->n_container_uuids == 1)
		? control_get_container_by_uuid_string(msg->container_uuids[0])
		: NULL;

	switch (msg->command) {
	// Global commands:

	case CONTROLLER_TO_DAEMON__COMMAND__LIST_GUESTOS_CONFIGS: {
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
		mem_free(results);
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
			mem_free(results[i]);
		mem_free(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_STATUS: {
		// assemble list of relevant containers and allocate memory for result
		list_t *containers = control_build_container_list_from_uuids(
				msg->n_container_uuids, msg->container_uuids);
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
		mem_free(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_CONTAINER_CONFIG: {
		// assemble list of relevant containers and allocate memory for result
		list_t *containers = control_build_container_list_from_uuids(
				msg->n_container_uuids, msg->container_uuids);
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
			TRACE("Getting container config for container %s", container_get_name(container));
			const char *config_filename = container_get_config_filename(container);
			if (!config_filename) {
				WARN("Container %s has no config file set. Skipping.",
						container_get_name(container));
			} else {
				TRACE("Container %s has config file; appending to list...", container_get_name(container));
				results[number_of_configs] = (ContainerConfig *)
					protobuf_message_new_from_textfile(
							config_filename,
							&container_config__descriptor);
				if(results[number_of_configs] == NULL) {
					WARN("The config file of container %s is missing. Skipping.",
						container_get_name(container));
					continue;
				}
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
			mem_free(result_uuids[i]);
			if (results[i] != NULL)
				protobuf_free_message((ProtobufCMessage *) results[i]);
		}
		mem_free(result_uuids);
		mem_free(results);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__GET_LAST_LOG: {
		WARN("Due to privacy concerns this command is currently not supported.");
		//control_send_log_file(fd, "/proc/last_kmsg", false, false);
		//control_send_log_file(fd, "/dev/log/main", true, true);
	} break;
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_LOG_START: {
		WARN("Due to privacy concerns this command is currently not supported.");
		//if (control_logf_handler == NULL)
		//	control_logf_handler = logf_register(&control_logf, NULL);
	} break;
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_LOG_STOP: {
		WARN("Due to privacy concerns this command is currently not supported.");
		//if (control_logf_handler != NULL)
		//	logf_unregister(control_logf_handler);
		//	control_logf_handler = NULL;
	} break;
	// TODO
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_STATUS_START:
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_STATUS_STOP:
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_NOTIFICATIONS_START:
	case CONTROLLER_TO_DAEMON__COMMAND__OBSERVE_NOTIFICATIONS_STOP:
		WARN("ControllerToDaemon command %d not implemented yet", msg->command);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__PUSH_GUESTOS_CONFIG: {
		if (!msg->has_guestos_config_file)
			WARN("PUSH_GUESTOS_CONFIG without config file");
		else if (!msg->has_guestos_config_signature)
			WARN("PUSH_GUESTOS_CONFIG without config signature");
		else if (!msg->has_guestos_config_certificate)
			WARN("PUSH_GUESTOS_CONFIG without config certificate");
		else {
			guestos_mgr_push_config(msg->guestos_config_file.data, msg->guestos_config_file.len,
					msg->guestos_config_signature.data, msg->guestos_config_signature.len,
					msg->guestos_config_certificate.data, msg->guestos_config_certificate.len);
		}
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__WIPE_DEVICE: {
		cmld_wipe_device();
	} break;

	// Container-specific commands:
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_START: {
		char *key = NULL;
		bool no_switch = false;
		if (NULL == container) {
			WARN("Container does not exists!");
			res = -1;
			break;
		}
		ContainerStartParams *start_params = msg->container_start_params;
		if (start_params) {
			key = start_params->key;
			if (start_params->has_no_switch)
				no_switch = start_params->no_switch;
		}
		// key is asserted to be the user entered passwd/pin
		res = cmld_container_start_with_smartcard(container, key, no_switch);
	} break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_STOP:
		res = cmld_container_stop(container);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SWITCH:
		res = cmld_container_switch(container);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_FREEZE:
		res = cmld_container_freeze(container);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_UNFREEZE:
		res = cmld_container_unfreeze(container);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_ALLOWAUDIO:
		res = cmld_container_allow_audio(container);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_DENYAUDIO:
		res = cmld_container_deny_audio(container);
		break;
	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_WIPE:
		res = cmld_container_wipe(container);
		break;

	case CONTROLLER_TO_DAEMON__COMMAND__CONTAINER_SNAPSHOT:
		res = cmld_container_snapshot(container);
		break;

	default:
		WARN("Unknown ControllerToDaemon command: %d received", msg->command);
		/* DO NOTHING */
	}
}

/**
 * Event callback for incoming data that receives a ControllerToDaemon message (remote)
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
control_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	bool connection_error = false;
	control_t *control = data;

	if ( (events & EVENT_IO_WRITE) && control->type == AF_INET) {
		int res;
		socklen_t res_len = sizeof(int);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &res, &res_len) < 0) {
			TRACE_ERRNO("getsockopt failed for socket %d", fd);
			connection_error = true;
		}
		if (res != 0) {
			TRACE("res of getsockopt for %d says error %s", fd, strerror(res));
			connection_error = true;
		}
		else {
			DEBUG("Connected to remote host %s:%d", control->hostip, control->port);
			control->connected = true;
			container_t *container_a0 = cmld_containers_get_a0();
			char *imei = container_get_imei(container_a0);
			char *mac_address = container_get_mac_address(container_a0);
			char *phone_number = container_get_phone_number(container_a0);

			/* send LOGON_DEVICE message */
			DEBUG("Sending LOGON_DEVICE message to remote host %s:%d",
					control->hostip, control->port);
			DaemonToController out = DAEMON_TO_CONTROLLER__INIT;
			out.code = DAEMON_TO_CONTROLLER__CODE__LOGON_DEVICE;
			if (cmld_get_device_uuid()) {
				DEBUG("Setting uuid: %s", cmld_get_device_uuid());
				out.device_uuid = mem_strdup(cmld_get_device_uuid());
			}
			if (hardware_get_name()) {
				DEBUG("Setting hardware name: %s", hardware_get_name());
				out.logon_hardware_name = mem_strdup(hardware_get_name());
			}
			if (hardware_get_serial_number()) {
				DEBUG("Setting hardware serial number: %s", hardware_get_serial_number());
				out.logon_hardware_serial = mem_strdup(hardware_get_serial_number());
			}
			if(imei) {
				DEBUG("Setting imei: %s", imei);
				out.logon_imei = mem_strdup(imei);
			}
			if(mac_address) {
				DEBUG("Setting MAC address: %s", mac_address);
				out.logon_mac_address = mem_strdup(mac_address);
			}
			if(phone_number) {
				DEBUG("Setting phone_number: %s", phone_number);
				out.logon_phone_number = mem_strdup(phone_number);
			}
			if (protobuf_send_message(fd, (ProtobufCMessage *) &out) < 0) {
				WARN("Could not send LOGON message");
			}
			DEBUG("Sent LOGON message");
			mem_free(out.device_uuid);
			mem_free(out.logon_hardware_name);
			mem_free(out.logon_hardware_serial);
			mem_free(out.logon_imei);
			mem_free(out.logon_mac_address);
			mem_free(out.logon_phone_number);

			/* remove write watch */
			event_remove_io(io);
			event_io_free(io);
			io = event_io_new(control->sock_client, EVENT_IO_READ, control_cb_recv_message, control);
			event_add_io(io);
		}
	}
	else if (events & EVENT_IO_READ) {
		ControllerToDaemon *msg = (ControllerToDaemon *)protobuf_recv_message(fd, &controller_to_daemon__descriptor);
		if (msg != NULL) {
			control_handle_message(msg, fd);
			protobuf_free_message((ProtobufCMessage *)msg);
			TRACE("Handled control connection %d", fd);
			return;
		}
		if (!(events & EVENT_IO_EXCEPT)) {
			WARN("Failed to receive and decode ControllerToDaemon protobuf message!");
			if(control->type == AF_INET) connection_error = true;
		}
	}
	if ( (events & EVENT_IO_EXCEPT) || connection_error) {
		TRACE("MDM Connection Error: %d", (int)connection_error);
		event_remove_io(io);
		event_io_free(io);
		close(fd);
		control->sock_client = -1;
		if (control->type == AF_INET)
			control_remote_reconnect(control);
		return;
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

	if (events & EVENT_IO_EXCEPT) {
		WARN("Exception on connected socket to control client; closing socket");
		event_remove_io(io);
		event_io_free(io);
		if (close(fd) < 0)
			WARN_ERRNO("Failed to close connected control socket");
		control->sock_client = -1;
		return;
	}

	IF_FALSE_RETURN(events & EVENT_IO_READ);

	ControllerToDaemon *msg = (ControllerToDaemon *)protobuf_recv_message(fd, &controller_to_daemon__descriptor);
	if (!msg) {
		WARN("Failed to receive and decode ControllerToDaemon protobuf message!");
		return;
	}

	control_handle_message(msg, fd);
	protobuf_free_message((ProtobufCMessage *)msg);
	TRACE("Handled control connection %d", fd);
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
	ASSERT(control->type == AF_UNIX);

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
	control->sock_client = cfd;
	DEBUG("Accepted control connection %d", cfd);

	fd_make_non_blocking(cfd);

	event_io_t *event = event_io_new(cfd, EVENT_IO_READ, control_cb_recv_message_local, control);
	DEBUG("local control client connected on fd=%d", cfd);

	event_add_io(event);
}

/**
 * Timer callback to retry connection to remote socket till success
 */
static void
control_remote_reconnect_cb(UNUSED event_timer_t *timer, void *data)
{
	control_t *control = data;

	ASSERT(control);

	control->sock_client = sock_inet_create(SOCK_STREAM);
	if (control->sock_client < 0) {
		WARN("Could not create AF_INET socket");
		return;
	}
	fd_make_non_blocking(control->sock_client);

	int res = sock_inet_connect(control->sock_client, control->hostip, control->port);
	if (-1 == res) {
		DEBUG_ERRNO("Connecting failed to remote host %s:%d", control->hostip, control->port);
		return;
	}

	event_remove_timer(control->reconnect_timer);
	event_timer_free(control->reconnect_timer);
	control->reconnect_timer = NULL;

	/* connection succeeded so register socket for receiving data */
	fd_make_non_blocking(control->sock_client);

	event_io_t *event = event_io_new(control->sock_client, EVENT_IO_READ|EVENT_IO_WRITE, control_cb_recv_message, control);
	event_add_io(event);

}
/**
 * helper function to register timer for reconnect handler
 */
static int
control_remote_reconnect(control_t *control)
{
	ASSERT(control->type == AF_INET);
	ASSERT(control->hostip);
	ASSERT(control->port);
	control->connected = false;

	/* try to reconnect every CONTROL_REMOTE_RECONNECT_INTERVAL ms */
	if (control->reconnect_timer) {
		event_remove_timer(control->reconnect_timer);
		event_timer_free(control->reconnect_timer);
	}
	control->reconnect_timer =
		event_timer_new(CONTROL_REMOTE_RECONNECT_INTERVAL, -1, control_remote_reconnect_cb, control);
	event_add_timer(control->reconnect_timer);

	return 0;
}

control_t *
control_new(int sock)
{
	if (listen(sock, CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	control_t *control = mem_new0(control_t, 1);
	control->sock = sock;
	control->sock_client = -1;
	control->type = AF_UNIX;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, control_cb_accept, control);
	event_add_io(event);

	return control;
}

control_t *
control_local_new(const char *path)
{
	control_t *control;
	// TODO support giraffe bind?!? (needs to be done before registering event!)
	// Alternatively: shared mount (+symlink for transparent location)?
	int sock = sock_unix_create_and_bind(SOCK_STREAM, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	control = control_new(sock);

	return control;
}

control_t *
control_remote_new(const char *hostip, const char *service)
{
	control_t *control = mem_new0(control_t, 1);
	control->type = AF_INET;
	control->hostip = mem_strdup(hostip);
	control->port = atoi(service); // FIXME we should use getaddrinfo
	control->connected = false;
	control->sock = -1;
	control->sock_client = -1;

	control->reconnect_timer = NULL;

	control_list = list_append(control_list, control);

	return control;
}

int
control_remote_connect(control_t *control)
{
	/* handle connection to remote host asynchronously */
	if (!control->connected && !control->reconnect_timer)
		return control_remote_reconnect(control);
	else {
		DEBUG("Tried to connect remote control socket which already attempts a connection");
		return -1;
	}
}

bool
control_remote_connecting(control_t *control)
{
	return (control->connected || control->reconnect_timer);
}

void
control_remote_disconnect(control_t *control)
{
	if (control->reconnect_timer) {
		event_remove_timer(control->reconnect_timer);
		event_timer_free(control->reconnect_timer);
		control->reconnect_timer = NULL;
	}
	if (control->sock_client >= 0) {
		DEBUG("Shutting down control socket");
		if (shutdown(control->sock_client, SHUT_RDWR) == -1) {
			WARN_ERRNO("Shutting down the control socket failed");
		}
		if (close(control->sock_client) == -1) {
			WARN_ERRNO("Closing the control socket failed");
		}
	}
	control->connected = false;
}

void
control_free(control_t *control)
{
	ASSERT(control);
	if (control->sock_client >= 0) {
		shutdown(control->sock_client, SHUT_RDWR);
		close(control->sock_client);
	}
	if (control->hostip)
		mem_free(control->hostip);

	if (control->reconnect_timer) {
		event_remove_timer(control->reconnect_timer);
		event_timer_free(control->reconnect_timer);
		control->reconnect_timer = NULL;
	}

	control_list = list_remove(control_list, control);

	mem_free(control);
	return;
}
