/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
 * Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.

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

#define _GNU_SOURCE

#include "oci.h"

#include "container.h"
#include "cmld.h"
#include "crypto.h"
#include "audit.h"
#include "mount.h"

#include "oci_control.pb-c.h"

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
#include "common/network.h"
#include "common/reboot.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/event.h"

#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <runtime_spec_schema_config_schema.h>
#include <runtime_spec_schema_state_schema.h>

#define OCI_VERSION "1.0.2"
#define OCI_ROOT_OVERLAY_IMG_SIZE 1024

// maximum no. of connections waiting to be accepted on the listening socket
#define OCI_CONTROL_SOCK_LISTEN_BACKLOG 8

// time between reconnection attempts of a remote client socket
#define OCI_CONTROL_REMOTE_RECONNECT_INTERVAL 10000

struct oci_control {
	int sock;			      // listen socket fd
	list_t *event_io_sock_connected_list; // list of clients
};

struct oci_container {
	container_t *container; //!< 1:1 weak reference to container
	char *id;
	char *bundle;
	bool deleted; // we do not delete oci containers directly
	list_t *hook_prestart_list;
	list_t *hook_create_runtime_list;
	list_t *hook_create_container_list;
	list_t *hook_start_container_list;
	list_t *hook_poststart_list;
	list_t *hook_poststop_list;
};

typedef struct oci_hook {
	char *path;
	char **argv;
	char **envp;
} oci_hook_t;

static list_t *oci_containers_list = NULL;
static list_t *oci_control_list = NULL;

/**
 * The usual identity map between two corresponding C and protobuf enums.
 */
char *
oci_compartment_state_to_status(compartment_state_t state)
{
	switch (state) {
	case COMPARTMENT_STATE_STOPPED:
		return "stopped";
	case COMPARTMENT_STATE_STARTING:
		return "starting";
	case COMPARTMENT_STATE_BOOTING:
		return "created";
	case COMPARTMENT_STATE_RUNNING:
		return "running";
	case COMPARTMENT_STATE_FREEZING:
		return "freezing";
	case COMPARTMENT_STATE_FROZEN:
		return "frozen";
	case COMPARTMENT_STATE_ZOMBIE:
		return "zombie";
	case COMPARTMENT_STATE_SHUTTING_DOWN:
		return "shutting_down";
	case COMPARTMENT_STATE_SETUP:
		return "setup";
	case COMPARTMENT_STATE_REBOOTING:
		return "rebooting";
	default:
		FATAL("Unhandled value for compartment_state_t: %d", state);
	}
}

/**
 * Get the ContainerStatus for the given container.
 *
 * @param container the container object from which to generate the ContainerStatus
 * @return  a new runtime_spec_schema_state_schema object with information about the given container;
 *          has to be free'd with oci_container_state_free()
 */
static runtime_spec_schema_state_schema *
oci_container_state_new(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);
	IF_NULL_RETVAL(oci_container, NULL);

	runtime_spec_schema_state_schema *oci_state = mem_new0(runtime_spec_schema_state_schema, 1);

	oci_state->oci_version = mem_strdup(OCI_VERSION);
	oci_state->status =
		mem_strdup(oci_compartment_state_to_status(container_get_state(container)));
	oci_state->pid = container_get_pid(container);
	oci_state->pid_present = container_get_pid(container) > 0 ? true : false;

	oci_state->bundle = mem_strdup(oci_container->bundle);
	oci_state->id = mem_strdup(oci_container->id);

	return oci_state;
}

/**
 * Free the given runtime_spec_schema_state_schema object that was previously allocated
 * by oci_container_state_new().
 *
 * @param c_status the previously allocated ContainerStatus object
 */
static void
oci_container_state_free(runtime_spec_schema_state_schema *oci_state)
{
	IF_NULL_RETURN(oci_state);
	mem_free0(oci_state->oci_version);
	mem_free0(oci_state->id);
	mem_free0(oci_state->bundle);
	mem_free0(oci_state->status);
	mem_free0(oci_state);
}

static int
oci_control_dump_state(const container_t *container, int fd)
{
	runtime_spec_schema_state_schema *state = NULL;
	char *json_buf = NULL;
	parser_error err;

	state = oci_container_state_new(container);
	json_buf = runtime_spec_schema_state_schema_generate_json(state, NULL, &err);

	int ret = fd_write(fd, json_buf, strlen(json_buf));

	oci_container_state_free(state);
	mem_free(json_buf);
	return ret;
}

static oci_hook_t *
oci_hook_new(char *path, char **args, size_t args_len, char **env, size_t env_len)
{
	ASSERT(path);

	oci_hook_t *hook = mem_new0(oci_hook_t, 1);

	hook->path = mem_strdup(path);

	hook->argv = mem_new0(char *, args_len + 1);
	for (size_t i = 0; i < args_len; i++)
		hook->argv[i] = mem_strdup(args[i]);

	hook->envp = mem_new0(char *, env_len + 1);
	for (size_t i = 0; i < env_len; i++)
		hook->envp[i] = mem_strdup(env[i]);

	return hook;
}

static void
oci_hook_free(oci_hook_t *hook)
{
	ASSERT(hook);

	mem_free0(hook->path);

	for (char **arg = hook->argv; *arg; arg++)
		mem_free0(*arg);
	mem_free0(hook->argv);

	for (char **env = hook->envp; *env; env++)
		mem_free0(*env);
	mem_free0(hook->envp);

	mem_free0(hook);
}

static int
oci_do_hook(oci_hook_t *hook, const container_t *container)
{
	INFO("Executing hook: %s", hook->path);
	for (char **arg = hook->argv; *arg; arg++)
		INFO("\t %s", *arg);
	for (char **env = hook->envp; *env; env++)
		INFO("\t %s", *env);

	// TODO timer based abortion

	int status;
	int stdin_pipe[2];

	// oci container state needs to be provided through stdin
	IF_TRUE_RETVAL(-1 == pipe(stdin_pipe), -1);

	pid_t pid = fork();

	switch (pid) {
	case -1:
		ERROR_ERRNO("Could not fork for %s", hook->path);
		return -1;
	case 0:
		close(STDIN_FILENO);

		// dup read end of pipe to stdin
		if (-1 == dup2(stdin_pipe[0], STDIN_FILENO))
			FATAL_ERRNO("Could not dup2 stdin!");

		close(stdin_pipe[0]); // close read end of pipe
		close(stdin_pipe[1]); // close write end of pipe

		execvpe(hook->path, hook->argv, hook->envp);
		FATAL_ERRNO("Could not execvpe %s", hook->path);
		return -1;
	default:
		close(stdin_pipe[0]); // close read end of pipe

		// forward oci container state to forked child!
		if (oci_control_dump_state(container, stdin_pipe[1]) < 0)
			return -1;

		// done sending output (flush buffer)
		close(stdin_pipe[1]);

		if (waitpid(pid, &status, 0) != pid) {
			ERROR_ERRNO("Could not waitpid for '%s'", hook->path);
		} else if (!WIFEXITED(status)) {
			ERROR("Child '%s' terminated abnormally", hook->path);
		} else {
			TRACE("%s terminated normally", hook->path);
			return WEXITSTATUS(status) ? -1 : 0;
		}
	}
	return -1;
}

int
oci_do_hooks_prestart(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_prestart_list; l; l = l->next) {
		oci_hook_t *prestart_hook = l->data;
		if (-1 == oci_do_hook(prestart_hook, container))
			WARN("Failed to execute PRESTART hook!");
	}
	return 0;
}

int
oci_do_hooks_create_runtime(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_create_runtime_list; l; l = l->next) {
		oci_hook_t *hook_create_runtime = l->data;
		if (-1 == oci_do_hook(hook_create_runtime, container))
			WARN("Failed to execute CREATE_RUNTIME hook!");
	}
	return 0;
}

int
oci_do_hooks_create_container(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_create_container_list; l; l = l->next) {
		oci_hook_t *hook_create_container = l->data;
		if (-1 == oci_do_hook(hook_create_container, container))
			WARN("Failed to execute CREATE_CONTAINER hook!");
	}
	return 0;
}

int
oci_do_hooks_start_container(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_start_container_list; l; l = l->next) {
		oci_hook_t *hook_start_container = l->data;
		if (-1 == oci_do_hook(hook_start_container, container))
			WARN("Failed to execute START_CONTAINER hook!");
	}
	return 0;
}

int
oci_do_hooks_poststart(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_poststart_list; l; l = l->next) {
		oci_hook_t *hook_poststart = l->data;
		if (-1 == oci_do_hook(hook_poststart, container))
			WARN("Failed to execute POSTSTART hook!");
	}
	return 0;
}

int
oci_do_hooks_poststop(const container_t *container)
{
	oci_container_t *oci_container = oci_get_oci_container_by_container(container);

	for (list_t *l = oci_container->hook_poststop_list; l; l = l->next) {
		oci_hook_t *hook_poststop = l->data;
		if (-1 == oci_do_hook(hook_poststop, container))
			WARN("Failed to execute POSTSTOP hook!");
	}
	return 0;
}

oci_container_t *
oci_get_oci_container_by_container(const container_t *container)
{
	for (list_t *l = oci_containers_list; l; l = l->next) {
		oci_container_t *oci_container = l->data;
		if (container == oci_container->container)
			return oci_container;
	}
	return NULL;
}

static container_t *
oci_control_get_container_by_id_string(const char *id_str)
{
	uuid_t *uuid = uuid_new(id_str);
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

void
oci_container_free(oci_container_t *oci_container)
{
	IF_NULL_RETURN(oci_container);

	oci_containers_list = list_remove(oci_containers_list, oci_container);

	// do not free oci_container->container, this is done by cmld module

	mem_free0(oci_container->id);
	mem_free0(oci_container->bundle);

	for (list_t *l = oci_container->hook_prestart_list; l; l = l->next)
		oci_hook_free(l->data);

	for (list_t *l = oci_container->hook_create_runtime_list; l; l = l->next)
		oci_hook_free(l->data);

	for (list_t *l = oci_container->hook_create_container_list; l; l = l->next)
		oci_hook_free(l->data);

	for (list_t *l = oci_container->hook_start_container_list; l; l = l->next)
		oci_hook_free(l->data);

	for (list_t *l = oci_container->hook_poststart_list; l; l = l->next)
		oci_hook_free(l->data);

	for (list_t *l = oci_container->hook_poststop_list; l; l = l->next)
		oci_hook_free(l->data);

	mem_free0(oci_container);
}

static oci_container_t *
oci_container_new(const char *store_path, const char *peer_path, const char *bundle_path,
		  const char *id, const uint8_t *config, size_t config_len)
{
	ASSERT(store_path);
	ASSERT(peer_path);
	ASSERT(bundle_path);
	ASSERT(id);
	ASSERT(config);

	oci_container_t *oci_container = NULL;
	container_t *c = NULL;

	const char *name;
	bool ns_usr = true;
	bool ns_net = true;
	const void *os = NULL;
	char *config_filename;
	char *images_dir;
	unsigned int ram_limit = 0;
	const char *cpus_allowed = NULL;
	uint32_t color = 0;
	bool allow_autostart = true;
	char **allowed_devices = NULL;
	char **assigned_devices = NULL;
	const char *init = NULL;
	parser_error err;

	uuid_t *uuid = uuid_new(id);
	if (uuid == NULL)
		uuid = uuid_new(NULL);

	/* generate the container paths */
	config_filename = mem_printf("%s/%s.json", store_path, uuid_string(uuid));
	images_dir = mem_printf("%s/%s", store_path, uuid_string(uuid));

	DEBUG("New containers config filename is %s", config_filename);
	DEBUG("New containers images directory is %s", images_dir);

	if (-1 == file_write(config_filename, (char *)config, config_len))
		WARN("Could not store oci config!");

	// assure '\0' terminated string
	char *config_json = mem_new0(char, config_len + 1);
	memcpy(config_json, config, config_len);

	runtime_spec_schema_config_schema *config_schema =
		runtime_spec_schema_config_schema_parse_data(config_json, NULL, &err);
	if (!config_schema) {
		WARN("Failed loading oci container config from buf");
		goto out;
	}

	name = config_schema->hostname ? config_schema->hostname : id;

	ram_limit = 0;
	DEBUG("New containers max ram is %" PRIu32 "", ram_limit);

	cpus_allowed = NULL;
	color = 0;

	allow_autostart = true;

	ns_usr = file_exists("/proc/self/ns/user") ? true : false;
	ns_net = true;

	container_type_t type = CONTAINER_TYPE_CONTAINER;

	list_t *pnet_cfg_list = NULL;

	const char *dns_server = cmld_get_device_host_dns();

	list_t *vnet_cfg_list = NULL;
	list_t *usbdev_list = NULL;

	allowed_devices = NULL;
	assigned_devices = NULL;

	// if init provided by guestos does not exists use mapped c_service as init
	init = CSERVICE_TARGET;

	char **init_argv = mem_new0(char *, config_schema->process->args_len + 2);
	init_argv[0] = mem_strdup(CSERVICE_TARGET);
	for (size_t i = 0; i < config_schema->process->args_len; ++i)
		init_argv[i + 1] = mem_strdup(config_schema->process->args[i]);

	char **init_env = config_schema->process->env;
	size_t init_env_len = config_schema->process->env_len;

	// create FIFO list
	list_t *fifo_list = NULL;

	container_token_type_t ttype = CONTAINER_TOKEN_TYPE_NONE;

	bool usb_pin_entry = false;

	c = container_new(uuid, name, type, ns_usr, ns_net, os, config_filename, images_dir,
			  ram_limit, cpus_allowed, color, allow_autostart, dns_server,
			  pnet_cfg_list, allowed_devices, assigned_devices, vnet_cfg_list,
			  usbdev_list, init, init_argv, init_env, init_env_len, fifo_list, ttype,
			  usb_pin_entry);

	if (c) {
		DEBUG("Loaded oci config for container %s", container_get_name(c));
		cmld_containers_add(c);
	} else {
		goto out;
	}

	char *root_path =
		config_schema->root->path[0] == '/' ?
			mem_printf("%s%s", peer_path, config_schema->root->path) :
			mem_printf("%s/%s/%s", peer_path, bundle_path, config_schema->root->path);

	mount_add_entry(container_get_mnt(c), MOUNT_TYPE_BIND_DIR, root_path, "/", "none", 0);
	// confidential layer
	mount_add_entry(container_get_mnt(c), MOUNT_TYPE_OVERLAY_RW, "root_overlay", "/", "ext4",
			OCI_ROOT_OVERLAY_IMG_SIZE);

	mem_free(root_path);

	oci_container = mem_new0(oci_container_t, 1);
	oci_container->container = c;
	oci_container->id = mem_strdup(id);
	oci_container->bundle = mem_strdup(bundle_path);
	oci_container->deleted = false;

	if (config_schema->hooks) {
		if (config_schema->hooks->prestart_len) {
			for (size_t i = 0; i < config_schema->hooks->prestart_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->prestart[i];

				oci_container->hook_prestart_list = list_append(
					oci_container->hook_prestart_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
		if (config_schema->hooks->create_runtime_len) {
			for (size_t i = 0; i < config_schema->hooks->create_runtime_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->create_runtime[i];

				oci_container->hook_create_runtime_list = list_append(
					oci_container->hook_create_runtime_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
		if (config_schema->hooks->create_container_len) {
			for (size_t i = 0; i < config_schema->hooks->create_container_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->create_container[i];

				oci_container->hook_create_container_list = list_append(
					oci_container->hook_create_container_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
		if (config_schema->hooks->start_container_len) {
			for (size_t i = 0; i < config_schema->hooks->start_container_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->start_container[i];

				oci_container->hook_start_container_list = list_append(
					oci_container->hook_start_container_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
		if (config_schema->hooks->poststart_len) {
			for (size_t i = 0; i < config_schema->hooks->poststart_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->poststart[i];

				oci_container->hook_poststart_list = list_append(
					oci_container->hook_poststart_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
		if (config_schema->hooks->poststop_len) {
			for (size_t i = 0; i < config_schema->hooks->poststop_len; i++) {
				runtime_spec_schema_defs_hook *hook =
					(runtime_spec_schema_defs_hook *)
						config_schema->hooks->poststop[i];

				oci_container->hook_poststop_list = list_append(
					oci_container->hook_poststop_list,
					oci_hook_new(hook->path, hook->args, hook->args_len,
						     hook->env, hook->env_len));
			}
		}
	}

	oci_containers_list = list_append(oci_containers_list, oci_container);
out:
	uuid_free(uuid);
	mem_free0(images_dir);
	mem_free0(config_filename);
	free_runtime_spec_schema_config_schema(config_schema);

	return oci_container;
}

static void
oci_control_send_state(container_t *container, int fd)
{
	runtime_spec_schema_state_schema *state = NULL;
	char *json_buf = NULL;
	parser_error err;

	state = oci_container_state_new(container);
	json_buf = runtime_spec_schema_state_schema_generate_json(state, NULL, &err);

	OciResponse out = OCI_RESPONSE__INIT;
	out.code = OCI_RESPONSE__CODE__STATE;
	out.state = json_buf;
	if (container_get_pid(container) > 0) {
		out.has_pid = true;
		out.pid = container_get_pid(container);
	}
	out.status = oci_compartment_state_to_status(container_get_state(container));

	DEBUG("Send STATE RESPONSE with state '%s'.", out.status);

	if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
		WARN("Failed to send response to '%d'", fd);

	oci_container_state_free(state);
	mem_free(json_buf);
}

struct container_state_cb_data {
	compartment_state_t state;
	int fd;
};

static void
oci_container_state_cb(container_t *container, container_callback_t *cb, void *data)
{
	ASSERT(container);
	ASSERT(cb);
	ASSERT(data);

	struct container_state_cb_data *cb_data = data;

	int fd = cb_data->fd;
	compartment_state_t state = cb_data->state;

	/* skip if the container was not started */
	IF_FALSE_RETURN_TRACE(container_get_state(container) == state);

	/* unregister observer */
	container_unregister_observer(container, cb);

	if (state == COMPARTMENT_STATE_RUNNING)
		oci_do_hooks_poststart(container);

	oci_control_send_state(container, fd);

	mem_free(cb_data);
}

static void
oci_container_delete_cb(const char *path, UNUSED uint32_t mask, event_inotify_t *inotify,
			void *data)
{
	oci_container_t *oci_container = data;
	ASSERT(oci_container);

	INFO("INOTIFY event for oci id %s on path %s", oci_container->id, path);

	INFO("path %s was deleted, going to destroy container %s", path,
	     container_get_name(oci_container->container));

	if (cmld_container_destroy(oci_container->container) < 0)
		WARN("Failed to destroy container!");

	event_remove_inotify(inotify);
	event_inotify_free(inotify);
}

static int
oci_container_mark_deleted(oci_container_t *oci_container)
{
	IF_NULL_RETVAL_ERROR(oci_container, -1);

	oci_container->deleted = true;

	mount_t *mnt = container_get_mnt(oci_container->container);
	//const char *oci_root_path = mount_entry_get_img(mount_get_entry(mnt,0));

	// in docker and other high-level container engines the parent of the
	// oci root path survive a container stop but not a remove
	// oci remove is usually invoked e.g. by docker stop
	char *oci_parent_dir = mem_printf("%s/..", mount_entry_get_img(mount_get_entry(mnt, 0)));

	/* register delete watcher */
	event_inotify_t *event = event_inotify_new(oci_parent_dir, IN_DELETE_SELF,
						   &oci_container_delete_cb, oci_container);
	event_add_inotify(event);

	mem_free0(oci_parent_dir);

	return oci_do_hooks_poststop(oci_container->container);
}

/**
 * Handles a single decoded ControllerToDaemon message.
 *
 * @param msg	the ControllerToDaemon message to be handled
 * @param fd	file descriptor of the client connection
 *		(for sending a response, if necessary)
 */
static void
oci_control_handle_message(UNUSED oci_control_t *oci_control, const OciCommand *msg, int fd)
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

	// get container for container-specific commands in advance
	container_t *container = oci_control_get_container_by_id_string(msg->container_id);

	// Trace user for audit
	if (container) {
		uint32_t uid;
		if (sock_unix_get_peer_uid(fd, &uid) != 0) {
			WARN_ERRNO("Could not set login uid for control connection!");
		} else {
			container_audit_set_loginuid(container, uid);
		}
	}

	OciResponse out = OCI_RESPONSE__INIT;

	switch (msg->operation) {
	// Container-specific commands:
	case OCI_COMMAND__OPERATION__DELETE: {
		DEBUG("OCI_COMMAND__OPERATION_DELETE");
		if (NULL == container) {
			INFO("Container does not exist, nothing to destroy!");
			out.response = OCI_RESPONSE__RESPONSE__CMD_FAILED;
			break;
		}
		oci_container_t *oci_container =
			container ? oci_get_oci_container_by_container(container) : NULL;
		res = oci_container_mark_deleted(oci_container);
		// res = cmld_container_destroy(container);
		out.code = OCI_RESPONSE__CODE__RESPONSE;
		out.has_response = true;
		out.response =
			res ? OCI_RESPONSE__RESPONSE__CMD_FAILED : OCI_RESPONSE__RESPONSE__CMD_OK;
	} break;

	case OCI_COMMAND__OPERATION__CREATE: {
		DEBUG("OCI_COMMAND__OPERATION_CREATE");

		DEBUG("bundel path: %s", msg->bundle_path);
		DEBUG("oci config: %s", (char *)msg->oci_config_file.data);
		uint32_t pid;

		// prepend container path if control request comes from a container
		const char *peer_path = NULL;
		if (sock_unix_get_peer_pid(fd, &pid) != 0) {
			WARN_ERRNO("Could not get pid of controling peer connection!");
			peer_path = "";
		} else {
			container_t *peer = cmld_container_get_by_pid(pid);
			peer_path = peer ? container_get_rootdir(peer) : "";
		}

		oci_container_t *oci_container =
			container ? oci_get_oci_container_by_container(container) :
				    oci_container_new(cmld_get_containers_dir(), peer_path,
						      msg->bundle_path, msg->container_id,
						      msg->oci_config_file.data,
						      msg->oci_config_file.len);

		if (oci_container) {
			struct container_state_cb_data *cb_data =
				mem_new0(struct container_state_cb_data, 1);

			if (oci_container->deleted) {
				DEBUG("Start previosly created container %s, reuse previous state.",
				      container_get_name(oci_container->container));
				oci_container->deleted = false;
			}

			cb_data->fd = fd;
			cb_data->state = COMPARTMENT_STATE_BOOTING;
			container_register_observer(oci_container->container,
						    oci_container_state_cb, cb_data);
			cmld_container_start(oci_container->container);
			return;
		}

		out.code = OCI_RESPONSE__CODE__STATE;
		out.state = "failed";
	} break;

	case OCI_COMMAND__OPERATION__START: {
		DEBUG("OCI_COMMAND__OPERATION_START");

		if (!container) {
			out.code = OCI_RESPONSE__CODE__RESPONSE;
			out.has_response = true;
			out.response = OCI_RESPONSE__RESPONSE__CMD_FAILED;
			break;
		}

		DEBUG("continue start of container with pid %d", container_get_pid(container));

		struct container_state_cb_data *cb_data =
			mem_new0(struct container_state_cb_data, 1);

		cb_data->fd = fd;
		cb_data->state = COMPARTMENT_STATE_RUNNING;
		container_register_observer(container, oci_container_state_cb, cb_data);
		pid_t container_pid = container_get_pid(container);
		res = container_pid > 0 ? kill(container_pid, SIGINT) : -1;
		return;
	} break;

	case OCI_COMMAND__OPERATION__KILL: {
		DEBUG("OCI_COMMAND__OPERATION_KILL %s signal=%d", msg->container_id, msg->signal);
		out.code = OCI_RESPONSE__CODE__RESPONSE;
		out.has_response = true;
		out.response = OCI_RESPONSE__RESPONSE__CMD_FAILED;

		if (!msg->has_signal || !container)
			break;

		struct container_state_cb_data *cb_data =
			mem_new0(struct container_state_cb_data, 1);

		cb_data->fd = fd;
		cb_data->state = COMPARTMENT_STATE_STOPPED;

		if (container_get_state(container) == COMPARTMENT_STATE_STOPPED) {
			oci_control_send_state(container, fd);
			return;
		}

		container_register_observer(container, oci_container_state_cb, cb_data);

		pid_t container_pid = container_get_pid(container);
		DEBUG("Sending sig %d to container %s with pid %d.", msg->signal,
		      container_get_name(container), container_pid);

		int signal = msg->signal == SIGINT || SIGTERM ? SIGKILL : msg->signal;

		res = container_pid > 0 ? kill(container_pid, signal) : -1;
		return;
	} break;

	case OCI_COMMAND__OPERATION__STATE: {
		DEBUG("OCI_COMMAND__OPERATION_STATE");
		oci_control_send_state(container, fd);
		return;
	} break;

	default:
		WARN("Unsupported Oci command: %d received", msg->operation);
		out.response = OCI_RESPONSE__RESPONSE__CMD_FAILED;
	}

	if (protobuf_send_message(fd, (ProtobufCMessage *)&out) < 0)
		WARN("Failed to send response to '%d'", fd);
}

/**
 * Event callback for incoming data that receives a oci runtime command message (local)
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
oci_control_cb_recv_message(int fd, unsigned events, event_io_t *io, void *data)
{
	oci_control_t *oci_control = data;
	/*
	 * always check READ flag first, since also if the peer called close()
	 * and there is pending data on the socet the READ and EXCEPT flags are set.
	 * Thus, we have to read pending date before handling the EXCEPT event.
	 */
	if (events & EVENT_IO_READ) {
		// TODO handle incomming json stream
		OciCommand *msg = (OciCommand *)protobuf_recv_message(fd, &oci_command__descriptor);
		// close connection if client EOF, or protocol parse error
		IF_NULL_GOTO_TRACE(msg, connection_err);
		oci_control_handle_message(oci_control, msg, fd);
		TRACE("Handled control connection %d", fd);
		protobuf_free_message((ProtobufCMessage *)msg);
	}
	// also check EXCEPT flag
	if (events & EVENT_IO_EXCEPT) {
		INFO("OCI Control client closed connection; disconnecting oci control socket.");
		goto connection_err;
	}
	return;

connection_err:
	event_remove_io(io);
	event_io_free(io);
	if (close(fd) < 0)
		WARN_ERRNO("Failed to close connected oci control socket");
	oci_control->event_io_sock_connected_list =
		list_remove(oci_control->event_io_sock_connected_list, io);
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
oci_control_cb_accept(int fd, unsigned events, event_io_t *io, void *data)
{
	oci_control_t *oci_control = (oci_control_t *)data;
	ASSERT(oci_control);
	ASSERT(oci_control->sock == fd);

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
		event_io_new(cfd, EVENT_IO_READ, oci_control_cb_recv_message, oci_control);
	DEBUG("local oci control client connected on fd=%d", cfd);

	event_add_io(event);
}

oci_control_t *
oci_control_new(int sock)
{
	if (listen(sock, OCI_CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new control sock");
		return NULL;
	}

	oci_control_t *oci_control = mem_new0(oci_control_t, 1);
	oci_control->sock = sock;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, oci_control_cb_accept, oci_control);
	event_add_io(event);

	return oci_control;
}

oci_control_t *
oci_control_local_new(const char *path)
{
	int sock = sock_unix_create_and_bind(SOCK_STREAM, path);
	if (sock < 0) {
		WARN("Could not create and bind UNIX domain socket");
		return NULL;
	}
	if (listen(sock, OCI_CONTROL_SOCK_LISTEN_BACKLOG) < 0) {
		WARN_ERRNO("Could not listen on new oci control sock");
		return NULL;
	}

	oci_control_t *oci_control = mem_new0(oci_control_t, 1);
	oci_control->sock = sock;

	event_io_t *event = event_io_new(sock, EVENT_IO_READ, oci_control_cb_accept, oci_control);
	event_add_io(event);

	return oci_control;
}

void
oci_control_free(oci_control_t *oci_control)
{
	ASSERT(oci_control);
	for (list_t *l = oci_control->event_io_sock_connected_list; l; l = l->next) {
		event_io_t *event_io_sock_connected = l->data;
		event_remove_io(event_io_sock_connected);
		shutdown(event_io_get_fd(event_io_sock_connected), SHUT_RDWR);
		if (close(event_io_get_fd(event_io_sock_connected) < 0)) {
			WARN_ERRNO("Failed to close connected control socket");
		}
		event_io_free(event_io_sock_connected);
	}
	list_delete(oci_control->event_io_sock_connected_list);
	oci_control->event_io_sock_connected_list = NULL;

	oci_control_list = list_remove(oci_control_list, oci_control);

	mem_free0(oci_control);
	return;
}
