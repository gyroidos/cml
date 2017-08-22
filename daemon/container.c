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

#define _GNU_SOURCE
#include <sched.h>

#include "container.h"

#include "common/macro.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/list.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/proc.h"

#include "cmld.h"
#include "c_cgroups.h"
#include "c_net.h"
#include "c_vol.h"
#include "c_properties.h"
#include "c_cap.h"
#include "c_service.h"
#include "c_notification.h"
#include "container_config.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "hardware.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/android.h>

#define CLONE_STACK_SIZE 8192
/* Define some missing clone flags in BIONIC */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS             0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS            0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC            0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER           0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID            0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET            0x40000000
#endif

/* Timeout for a container boot. If the container does not come up in that time frame
 * it is killed forcefully */
/* TODO is that enough time for all benign starts? */
#define CONTAINER_START_TIMEOUT 800000
/* Timeout until a container to be stopped gets killed if not yet down */
#define CONTAINER_STOP_TIMEOUT 45000

// base port for local ports forwarded to adb in containers
#define ADB_FWD_PORT_BASE 55550

struct container {
	container_state_t state;
	uuid_t *uuid;
	char *name;
	mount_t *mnt;
	bool ns_net;
	bool ns_usr;
	bool privileged;
	char *config_filename;
	char *images_dir;
	char *key;
	uint32_t color;
	bool allow_autostart;
	bool allow_container_switch;
	unsigned int ram_limit; /* maximum RAM space the container may use */

	uuid_t *switch_to_container;
	bool audio_active;
	bool call_active;

	container_connectivity_t connectivity;
	bool airplane_mode;

	bool screen_on;

	char *description;

	list_t *csock_list; /* List of sockets bound inside the container */
	const guestos_t *os; /* weak reference */
	pid_t pid;		/* PID of the corresponding /init */
	int exit_status; /* if the container's init exited, here we store its exit status */

	char **init_argv; /* command line parameters for init */

	list_t *observer_list; /* list of function callbacks to be called when the state changes */
	event_timer_t *stop_timer; /* timer to handle container stop timeout */
	event_timer_t *start_timer; /* timer to handle a container start timeout */

	/* TODO maybe we should try to get rid of this state since it is only
	 * useful for the starting phase and only there to make it easier to pass
	 * the FD to the child via clone */
	int sync_sock_parent; /* parent sock for start synchronization */
	int sync_sock_child; /* child sock for start synchronization */

	// Submodules
	c_cgroups_t *cgroups;
	c_net_t *net; /* encapsulates given network interfaces*/

	c_vol_t *vol;
	c_properties_t *prop;
	c_service_t *service;
	// Wifi module?

	c_notification_t *notification;

	char *imei;
	char *mac_address;
	char *phone_number;

	/* list of enabled features checked against during overlay mounts */
	list_t *feature_enabled_list;

	char *dns_server;
};

struct container_callback {
	void (*cb)(container_t *, container_callback_t *, void *);
	void *data;
	bool todo;
};

typedef struct {
	int sockfd; /* The socket FD */
	char *path; /* The path the socket should be/is (pre/post start) bound to */
} container_sock_t;

/**
 * These are used for synchronizing the container start between parent
 * and child process
 */
enum container_start_sync_msg {
	CONTAINER_START_SYNC_MSG_GO = 1,
	CONTAINER_START_SYNC_MSG_STOP,
	CONTAINER_START_SYNC_MSG_SUCCESS,
	CONTAINER_START_SYNC_MSG_ERROR,
};

static uint16_t
container_get_next_adb_port(void)
{
	static uint16_t next_free_adb_port = ADB_FWD_PORT_BASE + 1;
	return next_free_adb_port++;
}

container_t *
container_new_internal(
	const uuid_t *uuid,
	const char *name,
	bool ns_usr,
	bool ns_net,
	bool privileged,
	const guestos_t *os,
	const char *config_filename,
	const char *images_dir,
	mount_t *mnt,
	unsigned int ram_limit,
	uint32_t color,
	uint16_t adb_port,
	bool allow_autostart,
	bool allow_container_switch,
	list_t *feature_enabled,
	const char *dns_server,
	const char *telephony_name
)
{
	container_t *container = mem_new0(container_t, 1);

	container->state = CONTAINER_STATE_STOPPED;

	container->uuid = uuid_new(uuid_string(uuid));
	container->name = mem_strdup(name);
	container->mnt = mnt;
	/* do not forget to update container->description in the setters of uuid and name */
	container->description = mem_printf("%s (%s)", container->name, uuid_string(container->uuid));

	container->switch_to_container = NULL;
	container->call_active = false;

	container->connectivity = CONTAINER_CONNECTIVITY_OFFLINE;
	container->airplane_mode = false;

	container->screen_on = false;

	/* initialize pid to a value indicating it is invalid */
	container->pid = -1;

	/* initialize exit_status to 0 */
	container->exit_status = 0;

	container->ns_usr = ns_usr;
	container->ns_net = ns_net;
	container->privileged = privileged;

	/* Allow config_filename to be NULL for "configless"/"anonymous" containers */
	if (config_filename)
		container->config_filename = mem_strdup(config_filename);
	else
		container->config_filename = NULL;

	container->images_dir = mem_strdup(images_dir);

	container->color = color;

	container->allow_autostart = allow_autostart;
	container->allow_container_switch = allow_container_switch;

	container->os = os;

	container->csock_list = NULL;
	container->observer_list = NULL;
	container->stop_timer = NULL;
	container->start_timer = NULL;

	container->imei = NULL;
	container->mac_address = NULL;
	container->phone_number = NULL;

	container->ram_limit = ram_limit;

	/* Create submodules */
	container->cgroups = c_cgroups_new(container);
	if (!container->cgroups) {
		WARN("Could not initialize cgroups subsystem for container %s (UUID: %s)", container->name,
		     uuid_string(container->uuid));
		goto error;
	}

	list_t *nw_name_list = hardware_get_nw_name_list();
	for (list_t* elem = nw_name_list; elem != NULL; elem = elem->next) {
		DEBUG("List element in nw_names_list: %s", (char*)(elem->data));
	}

	list_t *nw_mv_name_list = NULL;
	if (privileged && ns_net) {
		nw_mv_name_list = hardware_get_nw_mv_name_list();
		for (list_t* elem = nw_mv_name_list; elem != NULL; elem = elem->next) {
			DEBUG("List element in nw_names_list: %s", (char*)(elem->data));
		}
	}

	container->net = c_net_new(container, ns_net, nw_name_list, nw_mv_name_list, adb_port);
	if (!container->net) {
		WARN("Could not initialize net subsystem for container %s (UUID: %s)", container->name,
		     uuid_string(container->uuid));
		goto error;
	}
	list_delete(nw_name_list);
	list_delete(nw_mv_name_list);

	container->vol = c_vol_new(container);
	if (!container->vol) {
		WARN("Could not initialize volume subsystem for container %s (UUID: %s)", container->name,
		     uuid_string(container->uuid));
		goto error;
	}

	container->prop = c_properties_new(container, telephony_name);
	if (!container->prop) {
		WARN("Could not initialize property subsystem for container %s (UUID: %s)", container->name,
		     uuid_string(container->uuid));
		goto error;
	}

	container->service = c_service_new(container);
	if (!container->service) {
		WARN("Could not initialize service subsystem for container %s (UUID: %s)", container->name,
		     uuid_string(container->uuid));
		goto error;
	}

	container->notification = c_notification_new(container);
	if (!container->notification) {
		WARN("Could not initialize notification subsystem for container %s",
				container_get_description(container));
		goto error;
	}

	// construct an argv buffer for execve
	container->init_argv = guestos_get_init_argv_new(os);

	container->feature_enabled_list = feature_enabled;
	for (list_t* elem = container->feature_enabled_list; elem != NULL; elem = elem->next) {
		DEBUG("Feature %s enabeld for %s", (char*)(elem->data), container->name);
	}

	container->dns_server = dns_server ? mem_strdup(dns_server) : NULL;

	return container;

error:
	container_free(container);
	return NULL;
}

/**
 * Creates a new container container object. There are three different cases
 * depending on the combination of the given parameters:
 *
 * uuid && !config: In this case, a container with the given UUID must be already
 * present in the given store_path and is loaded from there.
 *
 * !uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config string and a random
 * UUID.
 *
 * uuid && config: In this case, the container does NOT yet exist and should be
 * created in the given store_path using the given config string and the given
 * UUID.
 *
 * @return The new container object or NULL if something went wrong.
 *
 */
/* TODO Error handling */
container_t *
container_new(const char *store_path, const uuid_t *existing_uuid, const char *config,
		size_t config_len)
{
	ASSERT(store_path);
	ASSERT(existing_uuid || config);

	const char *name;
	bool ns_usr;
	bool ns_net;
	const guestos_t *os;
	char *config_filename;
	char *images_dir;
	mount_t *mnt;
	unsigned int ram_limit;
	uint32_t color;
	uuid_t *uuid;
	uint64_t current_guestos_version;
	uint64_t new_guestos_version;
	bool allow_autostart;
	bool allow_container_switch;
	bool priv;

	if (!existing_uuid) {
		uuid = uuid_new(NULL);
	} else {
		uuid = uuid_new(uuid_string(existing_uuid));
	}

	/* generate the container paths */
	config_filename = mem_printf("%s/%s.conf", store_path, uuid_string(uuid));
	images_dir = mem_printf("%s/%s", store_path, uuid_string(uuid));

	DEBUG("New containers config filename is %s", config_filename);
	DEBUG("New containers images directory is %s", images_dir);

	/********************************
	 * Translate High Level Config into low-level parameters for internal
	 * constructor */
	container_config_t *conf = container_config_new(config_filename, config, config_len);

	if (!conf) {
		WARN("Could not read config file %s", config_filename);
		mem_free(config_filename);
		mem_free(images_dir);
		uuid_free(uuid);
		return NULL;
	}

	name = container_config_get_name(conf);

	const char *os_name = container_config_get_guestos(conf);
	DEBUG("New containers os name is %s", os_name);
	os = guestos_mgr_get_latest_by_name(os_name, true);
	if (!os) {
		WARN("Could not get GuestOS %s instance for container %s", os_name, name);
		mem_free(config_filename);
		mem_free(images_dir);
		uuid_free(uuid);
		return NULL;
	}

	mnt = mount_new();
	guestos_fill_mount(os, mnt);
	container_config_fill_mount(conf, mnt);

	ram_limit = container_config_get_ram_limit(conf);
	DEBUG("New containers max ram is %" PRIu32 "", ram_limit);

	color = container_config_get_color(conf);

	allow_autostart = container_config_get_allow_autostart(conf);
	allow_container_switch = container_config_get_allow_container_switch(conf);

	current_guestos_version = container_config_get_guestos_version(conf);
	new_guestos_version = guestos_get_version(os);
	if (current_guestos_version < new_guestos_version) {
		INFO("Updating guestos version from %" PRIu64 " to %" PRIu64 " for container %s",
						current_guestos_version, new_guestos_version, name);
		container_config_set_guestos_version(conf, new_guestos_version);
		INFO("guestos_version is now: %" PRIu64 "", container_config_get_guestos_version(conf));
	} else if (current_guestos_version == new_guestos_version) {
		INFO("Keeping current guestos version %" PRIu64 " for container %s",
											current_guestos_version, name);
	} else {
		WARN("The version of the found guestos (%" PRIu64 ") for container %s is to low",
											new_guestos_version, name);
		WARN("Current version is %" PRIu64 "; Aborting...", current_guestos_version);
		uuid_free(uuid);
		container_config_free(conf);
		mount_free(mnt);
		return NULL;
	}
	ns_usr = false;
	ns_net = container_config_has_netns(conf);

	priv = guestos_is_privileged(os);
	//priv |= !ns_net;

	uint16_t adb_port = container_get_next_adb_port();

	list_t *feature_enabled = container_config_get_feature_list_new(conf);

	const char* dns_server = (container_config_get_dns_server(conf)) ? container_config_get_dns_server(conf) : cmld_get_device_host_dns();

	container_t *c = container_new_internal(uuid, name, ns_usr, ns_net, priv, os, config_filename,
			images_dir, mnt, ram_limit, color, adb_port, allow_autostart, allow_container_switch, feature_enabled, dns_server, NULL);
	if (c)
		container_config_write(conf);

	uuid_free(uuid);
	//container_config_free(conf); // TODO: really think about this... This is bad!!
	return c;
}

void
container_free(container_t *container) {
	ASSERT(container);

	uuid_free(container->uuid);
	mem_free(container->name);

	for (list_t *l = container->csock_list; l; l = l->next) {
		container_sock_t *cs = l->data;
		mem_free(cs->path);
		mem_free(cs);
	}
	list_delete(container->csock_list);

	if (container->config_filename)
		mem_free(container->config_filename);

	if (container->init_argv) {
		for (char **arg = container->init_argv; *arg; arg++) {
			mem_free(*arg);
		}
		mem_free(container->init_argv);
	}

	for (list_t *l = container->feature_enabled_list; l; l = l->next) {
		char *feature = l->data;
		mem_free(feature);
	}
	list_delete(container->feature_enabled_list);

	if (container->mnt)
		mount_free(container->mnt);

	if (container->cgroups)
		c_cgroups_free(container->cgroups);
	if (container->net)
		c_net_free(container->net);
	if (container->notification)
		c_notification_free(container->notification);
	if (container->prop)
		c_properties_free(container->prop);
	if (container->vol)
		c_vol_free(container->vol);
	if (container->service)
		c_service_free(container->service);
	if (container->imei)
		mem_free(container->imei);
	if (container->mac_address)
		mem_free(container->mac_address);
	if (container->phone_number)
		mem_free(container->phone_number);
	if (container->dns_server)
		mem_free(container->dns_server);

	mem_free(container);
}

const uuid_t *
container_get_uuid(const container_t *container)
{
	ASSERT(container);
	return container->uuid;
}

const mount_t *
container_get_mount(const container_t *container)
{
	ASSERT(container);
	return container->mnt;
}

const guestos_t *
container_get_os(const container_t *container)
{
	ASSERT(container);
	return container->os;
}

const char *
container_get_name(const container_t *container)
{
	ASSERT(container);
	return container->name;
}

const char *
container_get_images_dir(const container_t *container)
{
	ASSERT(container);
	return container->images_dir;
}

/* TODO think about setters for name etc.
 * Old references retrieved with the getter should not become
 * invalid! */

const char *
container_get_description(const container_t *container)
{
	ASSERT(container);
	return container->description;
}

pid_t
container_get_pid(const container_t *container)
{
	ASSERT(container);
	return container->pid;
}

pid_t
container_get_service_pid(const container_t *container)
{
	/* Determine PID of container's init */
	pid_t init = container_get_pid(container);
	if (init <= 0) {
		DEBUG("Could not determine PID of container's init");
		return -1;
	}

	/* Determine PID of container's zygote */
	pid_t zygote = proc_find(init, "main");
	if (zygote <= 0) {
		DEBUG("Could not determine PID of container's zygote");
		return -1;
	}

	/* Determine PID of container's trustme service */
	pid_t service = proc_find(zygote, "trustme.service");
	if (service <= 0) {
		DEBUG("Could not determine PID of container's service");
		return -1;
	}

	return service;
}

void
container_oom_protect_service(const container_t *container)
{
    ASSERT(container);

    pid_t service_pid = container_get_service_pid(container);
	if (service_pid < 0) {
		WARN("Could not determine PID of container's service to protect against low memory killer. Ignoring...");
		return;
	}

    DEBUG("Setting oom_adj of trustme service (PID %d) in container %s to -17",
            service_pid, container_get_description(container));
    char *path = mem_printf("/proc/%d/oom_adj", service_pid);
    int ret = file_write(path, "-17", -1);
    if (ret < 0)
        ERROR_ERRNO("Failed to write to %s", path);
    mem_free(path);
}

int
container_get_exit_status(const container_t *container)
{
	ASSERT(container);
	return container->exit_status;
}

uint32_t
container_get_color(const container_t *container)
{
	ASSERT(container);
	return container->color;
}

char *
container_get_color_rgb_string(const container_t *container)
{
	ASSERT(container);
	return mem_printf("#%02X%02X%02X",
			(container->color >> 24) & 0xff,
			(container->color >> 16) & 0xff,
			(container->color >> 8) & 0xff);
}

int
container_write_config(container_t *container)
{
	ASSERT(container);

	if (container->config_filename) {
		ASSERT(0);
		//container_config_t *conf = container_config_new(container->config_filename, NULL);
		//container_config_set_ram_limit(conf, container->ram_limit);
		/* TODO ... */
		//container_config_write(conf);
		//container_config_free(conf);
		return 0;
	} else {
		WARN("Trying to write configless container to file... Try to set config" \
			   "filename first if you want to make the container config persistent");
		return -1;
	}
}

const char *
container_get_config_filename(const container_t *container)
{
	ASSERT(container);
	return container->config_filename;
}

bool
container_is_privileged(const container_t *container)
{
	ASSERT(container);
	return container->privileged;
}

int
container_destroy(container_t *container) {
	ASSERT(container);

	// TODO implement
	// shutdown container
	// cleanup container (submodules)
	// call c_<module>_destroy() hooks in submodules, especially for c_vol to remove images
	// remove config file (container->config_filename)
	return 0;
}

bool
container_is_active(container_t *container)
{
	ASSERT(container);

	if (container->pid == -1 || container->state == CONTAINER_STATE_STOPPED) {
		return false;
	}

	char *buf = file_read_new("/proc/dev_ns/active_ns_pid", 32);
	if (!buf) {
		WARN("Could not read /proc/dev_ns/active_ns_pid");
		return false;
	}

	pid_t pid = atoi(buf);
	mem_free(buf);

	return container->pid == pid;
}

int
container_set_active(container_t *container)
{
	ASSERT(container);

	if (container->pid == -1 || container->state == CONTAINER_STATE_STOPPED) {
		WARN("Cannot set container %s active since it has no PID yet...", container_get_description(container));
		return -1;
	}

	if (container_is_active(container)) {
	    DEBUG("Container is already active, doing nothing");
	    return 0;
	}

	DEBUG("Setting active device namespace to pid %d", container->pid);

	if (file_printf("/proc/dev_ns/active_ns_pid", "%d\n", container->pid) < 0) {
		ERROR("Could not set active device namespave to pid %d", container->pid);
		return -1;
	}

	// TODO: use description instead of name?
	if (file_printf("/proc/dev_ns/ns_tag", "%d:%s\n", container->pid, container->name) < 0) {
		ERROR("Could not set device namespace tag %d:%s", container->pid, container->name);
		return -1;
	}

	return 0;
}

int
container_suspend(container_t *container)
{
	return c_service_send_message(container->service, C_SERVICE_MESSAGE_SUSPEND);
}

int
container_resume(container_t *container)
{
	return c_service_send_message(container->service, C_SERVICE_MESSAGE_RESUME);
}

/**
 * This function should be called only on a (physically) not-running container and
 * should make sure that the container and all its submodules are in the same
 * state they had immediately after their creation with _new().
 * Return values are not gathered, as the cleanup should just work as the system allows.
 * This function also sets the container's state to stopped.
 */
static void
container_cleanup(container_t *container)
{
	c_cgroups_cleanup(container->cgroups);
	c_service_cleanup(container->service);
	c_net_cleanup(container->net);
	/* cleanup c_vol last, as it removes partitions */
	c_vol_cleanup(container->vol);
	c_notification_cleanup(container->notification);

	container->pid = -1;

	/* timer can be removed here, because container is on the transition to the stopped state */
	if (container->stop_timer) {
		DEBUG("Remove container stop timer for %s", container_get_description(container));
		event_remove_timer(container->stop_timer);
		event_timer_free(container->stop_timer);
		container->stop_timer = NULL;
	}

	if (container->start_timer) {
		DEBUG("Remove container start timer for %s", container_get_description(container));
		event_remove_timer(container->start_timer);
		event_timer_free(container->start_timer);
		container->start_timer = NULL;
	}

	container_set_state(container, CONTAINER_STATE_STOPPED);
}

void
container_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	container_t *container = data;

	DEBUG("SIGCHLD handler called for container %s with PID %d", container_get_description(container), container->pid);

	/* In the start function the childs init process gets set a process group which has
	 * the same pgid as its pid. We wait for all processes belonging to our container's
	 * process group, but only change the containers state to stopped if the init exited */
	pid_t container_pid = container->pid;
	pid_t pid = 0;
	int status = 0;
	while ((pid = waitpid(-(container_pid), &status, WNOHANG))) {
		if (pid == container_pid) {
			if (WIFEXITED(status)) {
				INFO("Container %s terminated (init process exited with status=%d)",
					container_get_description(container),
					WEXITSTATUS(status));
				container->exit_status = WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				INFO("Container %s killed by signal %d",
					container_get_description(container),
					WTERMSIG(status));
			} else {
				continue;
			}
			/* remove the sigchld callback for this container from the event loop */
			event_remove_signal(sig);
			event_signal_free(sig);
			/* the cleanup also sets the container state to stopped... */
			container_cleanup(container);
		} else if (pid == -1) {
			if (errno == ECHILD)
				DEBUG("Process group of container %s terminated completely",
					container_get_description(container));
			else
				WARN_ERRNO("waitpid failed for container %s", container_get_description(container));
			break;
		} else {
			DEBUG("Reaped a child with PID %d for container %s", pid, container_get_description(container));
		}
	}
}

static int
container_close_all_fds_cb(UNUSED const char *path, const char *file, UNUSED void *data)
{
	int fd = atoi(file);

	DEBUG("Closing file descriptor %d", fd);

	if (close(fd) < 0)
		WARN_ERRNO("Could not close file descriptor %d", fd);

	return 0;
}

static int
container_close_all_fds()
{
	if (dir_foreach("/proc/self/fd", &container_close_all_fds_cb, NULL) < 0) {
		WARN("Could not open /proc/self/fd directory, /proc not mounted?");
		return -1;
	}

	return 0;
}

static int
container_start_child(void *data)
{
	int ret = 0;

	container_t *container = data;

	close(container->sync_sock_parent);

	/*******************************************************************/
	// wait on synchronization socket for start message code from parent
	// check if everything went ok in the parent (else goto error)
	char msg;
	if (read(container->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);

	if (msg == CONTAINER_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	/* Reset umask and sigmask for /init */
	sigset_t sigset;
	umask(0);
	sigemptyset(&sigset);
	sigprocmask(SIG_SETMASK, &sigset, NULL);

	/* Make sure /init in node doesn`t kill CMLD daemon */
	if (setpgid(0, 0) < 0) {
		WARN("Could not move process group of container %s", container->name);
		goto error;
	}

	if (c_cgroups_start_child(container->cgroups) < 0) {
		ret = CONTAINER_ERROR_CGROUPS;
		goto error;
	}
	
	if (c_net_start_child(container->net) < 0) {
		ret = CONTAINER_ERROR_NET;
		goto error;
	}


	/* Make sure to execute the c_vol hook first, since it brings the childs mounts into
	 * place as it is expected by the other submodules */
	if (c_vol_start_child(container->vol) < 0) {
		ret = CONTAINER_ERROR_VOL;
		goto error;
	}

	if ((strcmp(guestos_get_name(container->os), "idsos") != 0 ) &&
				 (strcmp(guestos_get_name(container->os), "debos") != 0)) {
		if (c_properties_start_child(container->prop) < 0) {
			ret = CONTAINER_ERROR_PROP;
			goto error;
		}
	}

	if (c_service_start_child(container->service) < 0) {
		ret = CONTAINER_ERROR_SERVICE;
		goto error;
	}

	if (c_cap_start_child(container) < 0) {
		//ret = 1; // FIXME
		goto error;
	}

	if (chdir("/") < 0) {
		WARN_ERRNO("Could not chdir to \"/\" in container %s", uuid_string(container->uuid));
		goto error;
	}

	// bind sockets in csock_list
	// make sure this is done *after* the c_vol hook, which brings the childs mounts into place
	for (list_t *l = container->csock_list; l; l = l->next) {
		container_sock_t *cs = l->data;
		sock_unix_bind(cs->sockfd, cs->path);
	}

	// send success message to parent
	DEBUG("Sending CONTAINER_START_SYNC_MSG_SUCCESS to parent");
	char msg_success = CONTAINER_START_SYNC_MSG_SUCCESS;
	if (write(container->sync_sock_child, &msg_success, 1) < 0) {
		WARN_ERRNO("Could not write to sync socket");
		goto error;
	}

	/* Block on socket until the next sync message is sent by the parent */
	if (read(container->sync_sock_child, &msg, 1) != 1) {
		WARN_ERRNO("Could not read from sync socket");
		goto error;
	}

	DEBUG("Received message from parent %d", msg);

	if (msg == CONTAINER_START_SYNC_MSG_STOP) {
		DEBUG("Received stop message, exiting...");
		return 0;
	}

	DEBUG("Will start %s after closing filedescriptors of %s",
			guestos_get_init(container->os),
			container_get_description(container));

	DEBUG("init_argv:");
	for (char **arg = container->init_argv; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}

	if (setcon("u:r:init:s0") < 0) {
		WARN_ERRNO("Could not set security context init");
	}

	if (!container->privileged) {
		DEBUG("Dropping all trustme-lsm privileges for container %s", container_get_description(container));
		if (open("/sys/kernel/security/trustme/drop_privileges", 0) < 0)
			WARN_ERRNO("Could not drop trustme-lsm privileges");
	}

	if (hardware_backlight_on() < 0) {
		WARN("Could not turn on backlight for container start...");
	}

	DEBUG("After closing all file descriptors no further debugging info can be printed");

	if (container_close_all_fds()) {
		WARN("Closing all file descriptors failed, continuing anyway...");
	}

	execve(guestos_get_init(container->os), container->init_argv, NULL);
	WARN("Could not run exec for container %s", uuid_string(container->uuid));

	return CONTAINER_ERROR;

error:
	if (ret == 0) {
		ret = CONTAINER_ERROR;
	}

	// send error message to parent
	char msg_error = CONTAINER_START_SYNC_MSG_ERROR;
	if (write(container->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

	// TODO call c_<module>_cleanup_child() hooks

	if (container_close_all_fds()) {
		WARN("Closing all file descriptors in container start error failed");
	}
	return ret; // exit the child process
}

static void
container_start_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	container_t *container = data;

	/* Only kill the container in case it is still in the booting state.
	 * If this is not the case then simply remove the timer and do nothing
	 * Note that we do NOT have a problem with repeated container starts
	 * and overlapping start timeouts since the start_timer is cleared in
	 * container_cleanup which is called by the SIGCHLD handler as soon
	 * as the container goes down. */
	if (container_get_state(container) == CONTAINER_STATE_BOOTING) {
		WARN("Reached container start timeout for container %s and the container is still booting."
				" Killing it...", container_get_description(container));
		/* kill container. SIGCHLD cb handles the cleanup and state change */
		container_kill(container);
	}

	DEBUG("Freeing container start timeout timer");
	event_timer_free(timer);
	container->start_timer = NULL;

	return;
}

static void
container_start_post_clone_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	char msg;
	container_t *container = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		WARN("Received exception from child process");
		msg = CONTAINER_START_SYNC_MSG_ERROR;
	} else {
		// receive success or error message from started child
		if (read(fd, &msg, 1) != 1) {
			WARN_ERRNO("Could not read from sync socket");
			goto error;
		}
	}

	if (msg == CONTAINER_START_SYNC_MSG_ERROR) {
		WARN("Received error message from child process");
		return; // the child exits on its own and we cleanup in the sigchld handler
	}

	/********************************************************/
	/* on success call all c_<module>_start_pre_exec hooks */
	if (c_cgroups_start_pre_exec(container->cgroups) < 0) {
		WARN("c_cgroups_start_pre_exec failed");
		goto error_pre_exec;
	}

	if (c_service_start_pre_exec(container->service) < 0) {
		WARN("c_service_start_pre_exec failed");
		goto error_pre_exec;
	}

	container_set_state(container, CONTAINER_STATE_BOOTING);

	/* register a timer to kill the container if it does not come up in time */
	container->start_timer = event_timer_new(CONTAINER_START_TIMEOUT, 1,
		&container_start_timeout_cb, container);
	event_add_timer(container->start_timer);

	/* Notify child to do its exec */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(fd, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}

	/* Call all c_<module>_start_post_exec hooks */
	/* Currently, there are none.. */
	//if (c_cgroups_start_post_exec(container->cgroups) < 0) {
	//	WARN("c_cgroups_start_post_exec failed");
	//	goto error;
	//}

	event_remove_io(io);
	event_io_free(io);
	close(fd);

	return;

error_pre_exec:
	DEBUG("A pre-exec container start error occured, stopping container");
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(fd, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	return;
error:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	container_kill(container);
}

int
container_start(container_t *container)//, const char *key)
{
	ASSERT(container);

	if (container_get_state(container) != CONTAINER_STATE_STOPPED) {
		ERROR("Container %s is not stopped and can therefore not be started",
				container_get_description(container));
		return CONTAINER_ERROR;
	}

	int ret = 0;

	container_set_state(container, CONTAINER_STATE_STARTING);

	/*********************************************************/
	/* PRE CLONE HOOKS */
	if (c_cgroups_start_pre_clone(container->cgroups) < 0) {
		ret = CONTAINER_ERROR_CGROUPS;
		goto error_pre_clone;
	}

	if (c_net_start_pre_clone(container->net) < 0) {
		ret = CONTAINER_ERROR_NET;
		goto error_pre_clone;
	}

	if (c_service_start_pre_clone(container->service) < 0) {
		ret = CONTAINER_ERROR_SERVICE;
		goto error_pre_clone;
	}

	// Wifi module?

	/*********************************************************/
	/* PREPARE CLONE */

	void *container_stack = NULL;
	/* Allocate node stack */
	if (!(container_stack = alloca(CLONE_STACK_SIZE))) {
		WARN_ERRNO("Not enough memory for allocating container stack");
		goto error_pre_clone;
	}
	void *container_stack_high = (void *)((const char *)container_stack + CLONE_STACK_SIZE);

	unsigned long clone_flags = 0;
	clone_flags |= SIGCHLD;

	/* Set namespaces for node */
	/* set some basic and non-configurable namespaces */
	clone_flags |= CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC;
	if (container->ns_usr)
		clone_flags |= CLONE_NEWUSER;
	if (container->ns_net)
		clone_flags |= CLONE_NEWNET;

	/* Create a socketpair for synchronization and save it in the container structure to be able to
	 * pass it around */
	int fd[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd)) {
		WARN("Could not create socketpair for synchronization with child!");
		goto error_pre_clone;
	}
	container->sync_sock_parent = fd[0];
	container->sync_sock_child = fd[1];

	/*********************************************************/
	/* CLONE */

	/* TODO find out if stack is only necessary with CLONE_VM */
	pid_t container_pid = clone(container_start_child, container_stack_high, clone_flags, container);
	if (container_pid < 0) {
		WARN_ERRNO("Clone container failed");
		goto error_pre_clone;
	}
	container->pid = container_pid;

	/* close the childs end of the sync sockets */
	close(container->sync_sock_child);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event = event_io_new(container->sync_sock_parent, EVENT_IO_READ,
	                                     &container_start_post_clone_cb, container);
	event_add_io(sync_sock_parent_event);

	/* register SIGCHILD handler which sets the state and
	 * calls the appropriate cleanup functions if the child
	 * dies */
	event_signal_t *sig = event_signal_new(SIGCHLD, container_sigchld_cb, container);
	event_add_signal(sig);

	/*********************************************************/
	/* POST CLONE HOOKS */
	// execute all necessary c_<module>_start_post_clone hooks
	// goto error_post_clone on an error
	if (c_cgroups_start_post_clone(container->cgroups)) {
		ret = CONTAINER_ERROR_CGROUPS;
		goto error_post_clone;
	}

	if (c_net_start_post_clone(container->net)) {
		ret = CONTAINER_ERROR_NET;
		goto error_post_clone;
	}

	/*********************************************************/
	/* NOTIFY CHILD TO START */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(container->sync_sock_parent, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error_post_clone;
	}

	return 0;

error_post_clone:
	if (ret == 0)
		ret = CONTAINER_ERROR;
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(container->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}
	container_kill(container);
	return ret;

error_pre_clone:
	container_cleanup(container);
	return ret;
}

void
container_kill(container_t *container)
{
	ASSERT(container);

	if(container_get_state(container) == CONTAINER_STATE_STOPPED) {
		DEBUG("Trying to kill stopped container... doing nothing.");
		return;
	}

	// TODO kill container (possibly register callback and wait non-blocking)
	DEBUG("Killing container %s with pid: %d", container_get_description(container),
		container_get_pid(container));

	if (kill(container_get_pid(container), SIGKILL)) {
		ERROR_ERRNO("Failed to kill container %s", container_get_description(container));
	}
}

/* This callback determines the container's state and forces its shutdown,
 * when a container could not be stopped in time*/
static void
container_stop_timeout_cb(event_timer_t *timer, void *data)
{
	ASSERT(data);

	container_t *container = data;
	DEBUG("Reached container stop timeout for container %s. Doing the kill now", container_get_description(container));

	// kill container. sichld cb handles the cleanup and state change
	container_kill(container);

	event_timer_free(timer);
	container->stop_timer = NULL;

	return;
}

int
container_stop(container_t *container)
{
	ASSERT(container);

	int ret = 0;

	/* register timer with callback doing the kill, if stop fails */
	event_timer_t *container_stop_timer = event_timer_new(CONTAINER_STOP_TIMEOUT, 1,
		&container_stop_timeout_cb, container);
	event_add_timer(container_stop_timer);
	container->stop_timer = container_stop_timer;

	/* set state to shutting down (notifies observers) */
	container_set_state(container, CONTAINER_STATE_SHUTTING_DOWN);

	/* call stop hooks for c_* modules */
	DEBUG("Call stop hooks for modules");

	if (c_service_stop(container->service) < 0) {
		ret = CONTAINER_ERROR;
		goto error_stop;
	}

	// When the stop command was emitted, the TrustmeService tries to shut down the container
	// i.g. to terminate the container's init process.
	// we need to wait for the SIGCHLD signal for which we have a callback registered, which
	// does the cleanup and sets the state of the container to stopped.
	DEBUG("Stop container successfully emitted. Wait for child process to terminate (SICHLD)");

	return ret;

error_stop:
	DEBUG("Modules could not be stopped successfully, killing container.");
	container_kill(container);
	return ret;
}


int
container_bind_socket_before_start(container_t *container, const char *path)
{
	ASSERT(container);

	container_sock_t *cs = mem_new0(container_sock_t, 1);
	if ((cs->sockfd = sock_unix_create(SOCK_STREAM)) < 0) {
		mem_free(cs);
		return -1;
	}
	cs->path = mem_strdup(path);
	container->csock_list = list_append(container->csock_list, cs);

	return cs->sockfd;
}

int
container_bind_socket_after_start(UNUSED container_t *container, UNUSED const char *path)
{
//	int sock = container_bind_socket_before_start(container, socket_type, path);
//	// TODO find out what works and implement me
//	// EITHER:
//	char *bind_path = mem_printf("/proc/%s/root/%s", atoi(container->pid), path);
//	sock_unix_bind(sock, path_into_ns);
//
//	// OR:
//	// create a socketpair for synchronization
//	int fd[2];
//    pid_t pid;
//    socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
//    pid = fork();
//	if (pid == -1) {
//		WARN_ERRNO("Fork failed");
//		return -1;
//	}
//    if (pid == 0) {
//		// TODO synchronization
//		/* executed in child */
//        close(fd[0]);
//		char *mnt_ns_path = mem_printf("/proc/%s/ns/mnt", atoi(container->pid));
//		ns_fd = open(mnt_ns_path, O_RDONLY);
//		setns(ns_fd, 0); // switch into mount namespace of container
//		sock_unix_bind(sock, path);
//		exit(0);
//    } else {
//		/* executed in parent */
//        close(fd[1]);
//    }
	return 0;
}

int
container_freeze(container_t *container)
{
	ASSERT(container);

	container_state_t state = container_get_state(container);
	if (state == CONTAINER_STATE_FROZEN || state == CONTAINER_STATE_FREEZING) {
		DEBUG("Container already frozen or freezing, doing nothing...");
		return 0;
	} else if (state == CONTAINER_STATE_RUNNING) {
		return c_cgroups_freeze(container->cgroups);
	} else {
		WARN("Container not running");
		return -1;
	}
	return 0;
}

int
container_unfreeze(container_t *container)
{
	ASSERT(container);
	// TODO state checking
	return c_cgroups_unfreeze(container->cgroups);
}

int
container_allow_audio(container_t *container)
{
	ASSERT(container);
	// TODO state checking
	return c_cgroups_devices_allow_audio(container->cgroups);
}

int
container_deny_audio(container_t *container)
{
	ASSERT(container);
	// TODO state checking
	return c_cgroups_devices_deny_audio(container->cgroups);
}

int
container_snapshot(container_t *container)
{
	ASSERT(container);
	// TODO implement
	return 0;
}

static int
container_wipe_image_cb(const char *path, const char *name, UNUSED void *data)
{
	container_t *container = data;
	/* Only do the rest of the callback if the file name ends with .img */
	int len = strlen(name);
	if (len >= 4 && !strcmp(name + len - 4, ".img")) {
		char *image_path= mem_printf("%s/%s", path, name);
		DEBUG("Deleting image of container %s: %s", container_get_description(container), image_path);
		if (unlink(image_path) == -1) {
			ERROR_ERRNO("Could not delete image %s", image_path);
		}
		mem_free(image_path);
	}
	return 0;
}

int
container_wipe_finish(container_t *container)
{
	ASSERT(container);

	/* remove all images of the container */
	if (dir_foreach(container->images_dir, &container_wipe_image_cb, container) < 0) {
		WARN("Could not open %s images path for wiping container", container_get_description(container));
		return -1;
	}
	return 0;
}

static void
container_wipe_cb(container_t *container, container_callback_t *cb, UNUSED void *data)
{
	ASSERT(container);

	/* skip if the container is not stopped */
	if (container_get_state(container) != CONTAINER_STATE_STOPPED)
		return;

	/* wipe the container */
	if (container_wipe_finish(container) < 0) {
		ERROR("Could not wipe container");
	}

	/* unregister observer */
	container_unregister_observer(container, cb);
}

int
container_wipe(container_t *container)
{
	ASSERT(container);

	INFO("Wiping container %s", container_get_description(container));

	if (container_get_state(container) != CONTAINER_STATE_STOPPED) {
		container_kill(container);

		/* Register observer to wait for completed container_stop */
		if (!container_register_observer(container, &container_wipe_cb, NULL)) {
			DEBUG("Could not register wipe callback");
			return -1;
		}
		return 0;
	} else {
		/* Container is already stopped */
		return container_wipe_finish(container);
	}
}

static void
container_notify_observers(container_t *container)
{
	for (list_t *l = container->observer_list; l; l = l->next) {
		container_callback_t *ccb = l->data;
		ccb->todo = true;
	}
	// call all observer callbacks
	for (list_t *l = container->observer_list; l;) {
		container_callback_t *ccb = l->data;
		if (ccb->todo) {
			ccb->todo = false;
			(ccb->cb)(container, ccb, ccb->data);

			if (container->observer_list)
				l = container->observer_list;
			else
				break;
		} else {
			l = l->next;
		}
	}
}

void
container_set_state(container_t *container, container_state_t state)
{
	ASSERT(container);

	if (container->state == state)
		return;

	DEBUG("Setting container state: %d", state);
	container->state = state;

	container_notify_observers(container);
}

container_state_t
container_get_state(const container_t *container)
{
	ASSERT(container);
	return container->state;
}

void
container_set_notification(
		container_t *container,
		int id,
		char *tag,
		char *pkg_name,
		char *title,
		char *text,
		char *custom_icon) {
	ASSERT(container);

	int ret = c_notification_set_base(container->notification, id, tag,
					  pkg_name, title, text, custom_icon);

	if (ret == 0)
		container_notify_observers(container);
}

uint8_t *
container_get_notification_message(container_t *container) {
	ASSERT(container);

	return c_notification_get_filtered_packed_message(container->notification);
}

size_t
container_get_notification_message_size(container_t *container) {
	ASSERT(container);

	return c_notification_get_packed_message_size(container->notification);
}

void
container_set_notification_message(container_t *container, uint8_t *notification,
				   size_t notification_size) {
	ASSERT(container);

	c_notification_set_packed_message(container->notification, notification,
					  notification_size);
	container_notify_observers(container);
}

char *
container_get_notification_source_id(const container_t *container) {
	ASSERT(container);

	return c_notification_get_source_id(container->notification);
}

char *
container_get_notification_source_name(const container_t *container) {
	ASSERT(container);

	return c_notification_get_source_name(container->notification);
}

char *
container_get_notification_source_color_rgb_string(const container_t *container) {
	ASSERT(container);

	return c_notification_get_source_color_rgb_string(container->notification);
}

bool
container_has_base_notification(const container_t *container) {
	ASSERT(container);

	return c_notification_is_base_notification(container->notification);
}

bool
container_allows_notification(container_t *container, bool fg, const char *target_name) {
	ASSERT(container);

	return c_notification_allows_send_operation(container->notification,
						    fg, target_name);
}

int
container_send_notification_from_cmld(container_t *target) {
	ASSERT(target);

	c_notification_set_source_id(target->notification,
				     uuid_string(container_get_uuid(target))); // TODO what should we use here?
	c_notification_set_source_name(target->notification,
				       container_get_name(target));
	char *color_rgb_string = container_get_color_rgb_string(target);
	c_notification_set_source_color_rgb_string(target->notification, color_rgb_string);
	free(color_rgb_string);

	int ret = c_service_send_message(target->service,
					 C_SERVICE_MESSAGE_NOTIFICATION);
	c_notification_cleanup(target->notification);

	return ret;
}

int
container_send_notification_to_target(container_t *container, container_t *target) {
	ASSERT(container);
	ASSERT(target);

	size_t packed_size = c_notification_get_packed_message_size(container->notification);
	uint8_t *packed_message = c_notification_get_packed_message(container->notification);

	if (!packed_message || packed_size == 0) {
		WARN("Container tries to send empty message (may be NULL)");
		return -1;
	}

	c_notification_set_source_id(target->notification,
				     uuid_string(container_get_uuid(container)));
	c_notification_set_source_name(target->notification,
				       container_get_name(container));
	char *color_rgb_string = container_get_color_rgb_string(container);
	c_notification_set_source_color_rgb_string(target->notification, color_rgb_string);
	free(color_rgb_string);
	c_notification_set_packed_message(target->notification, packed_message,
					  packed_size);

	int ret = c_service_send_message(target->service,
					 C_SERVICE_MESSAGE_NOTIFICATION);
	c_notification_cleanup(target->notification);

	return ret;
}

void
container_cleanup_notification(container_t *container) {
	ASSERT(container);

	c_notification_cleanup(container->notification);
}


void
container_set_call_active(container_t *container, bool status)
{
	ASSERT(container);

	if (container->call_active == status)
		return;

	DEBUG("Call active state in container %s: %d", container_get_description(container), status);
	container->call_active = status;

	container_notify_observers(container);
}

bool
container_is_call_active(const container_t *container)
{
	ASSERT(container);
	return container->call_active;
}

container_callback_t *
container_register_observer(
		container_t *container,
		void (*cb)(container_t *, container_callback_t *, void *),
		void *data
		)
{
	ASSERT(container);
	ASSERT(cb);

	container_callback_t *ccb = mem_new0(container_callback_t, 1);
	ccb->cb = cb;
	ccb->data = data;
	container->observer_list = list_append(container->observer_list, ccb);
	DEBUG("Container %s: callback %p registered (nr of observers: %d)",
			container_get_description(container), CAST_FUNCPTR_VOIDPTR(cb),
			list_length(container->observer_list));
	return ccb;
}

void
container_unregister_observer(container_t *container, container_callback_t *cb)
{
	ASSERT(container);
	ASSERT(cb);

	if (list_find(container->observer_list, cb)) {
		container->observer_list = list_remove(container->observer_list, cb);
		mem_free(cb);
	}
	DEBUG("Container %s: callback %p unregistered (nr of observers: %d)",
			container_get_description(container), CAST_FUNCPTR_VOIDPTR(cb),
			list_length(container->observer_list));
}

const char *
container_get_key(const container_t *container)
{
	ASSERT(container);

	return container->key;
}

void
container_set_key(container_t *container, const char *key)
{
	ASSERT(container);
	ASSERT(key);

	if (container->key && !strcmp(container->key, key))
		return;

	if (container->key)
		mem_free(container->key);

	container->key = strdup(key);

	container_notify_observers(container);
}

unsigned int
container_get_ram_limit(const container_t *container)
{
	ASSERT(container);

	return container->ram_limit;
}

int
container_set_ram_limit(container_t *container, unsigned int ram_limit)
{
	ASSERT(container);

	if (container->ram_limit == ram_limit)
		return 0;

	container->ram_limit = ram_limit;

	/* Note that the c_cgroups submodule gets the ram_limit value from its container reference */
	return c_cgroups_set_ram_limit(container->cgroups);
}

void
container_set_switch_to_container(container_t *container, const char *target_container)
{
	ASSERT(container);

	if (!target_container) {
		if (container->switch_to_container)
			uuid_free(container->switch_to_container);
		container->switch_to_container = NULL;
		return;
	}

	uuid_t *tc = uuid_new(target_container);
	if (!tc) {
		WARN("Cannot switch to container %s: malformed UUID. Ignoring.", target_container);
		return;
	}

	if (uuid_equals(container->switch_to_container, tc)) {
		DEBUG("uuid %s equals %s; returning from container_set_switch_to_container", uuid_string(container->switch_to_container), uuid_string(tc));
		return;
	}

	DEBUG("Setting container switch_to_container request to %s for container %s",
			uuid_string(tc), container_get_description(container));

	if (container->switch_to_container)
		uuid_free(container->switch_to_container);
	container->switch_to_container = tc;

	container_notify_observers(container);
}

uuid_t *
container_get_switch_to_container(container_t *container)
{
	ASSERT(container);
	return container->switch_to_container;
}

void
container_set_audio_active(container_t *container, bool active)
{
	ASSERT(container);

	if (container->audio_active == active)
		return;

	DEBUG("Setting container audio state to %d for container %s",
			active, container_get_description(container));

	container->audio_active = active;

	container_notify_observers(container);
}

bool
container_is_audio_active(container_t *container)
{
	ASSERT(container);
	return container->audio_active;
}

void
container_set_connectivity(container_t *container, container_connectivity_t connectivity)
{
	ASSERT(container);

	if (container->connectivity == connectivity)
		return;

	DEBUG("Setting container connectivity state to %d for container %s",
			connectivity, container_get_description(container));
	container->connectivity = connectivity;

	container_notify_observers(container);
}

container_connectivity_t
container_get_connectivity(container_t *container)
{
	ASSERT(container);
	return container->connectivity;
}

void
container_set_airplane_mode(container_t *container, bool airplane_mode)
{
	ASSERT(container);

	if (container->airplane_mode == airplane_mode)
		return;

	DEBUG("Setting container airplane mode state to %d for container %s",
			airplane_mode, container_get_description(container));
	container->airplane_mode = airplane_mode;

	container_notify_observers(container);
}

bool
container_get_airplane_mode(container_t *container)
{
	ASSERT(container);
	return container->airplane_mode;
}

void
container_set_screen_on(container_t *container, bool screen_on)
{
	ASSERT(container);

	if (screen_on) {
		DEBUG("Setting screen on for container %s", container_get_description(container));
	} else {
		DEBUG("Setting screen off for container %s", container_get_description(container));
	}

	if (container->screen_on == screen_on)
		return;

	container->screen_on = screen_on;

	container_notify_observers(container);
}

bool
container_is_screen_on(container_t *container)
{
	ASSERT(container);

	return container->screen_on;
}

void
container_set_imei(container_t *container, char *imei)
{
	ASSERT(container);
	if (imei) {
		DEBUG("Setting container imei to %s for container %s",
				imei, container_get_description(container));
		if (container->imei)
			mem_free(container->imei);
		container->imei = mem_strdup(imei);
		container_notify_observers(container);
	}
}

char*
container_get_imei(container_t *container)
{
	ASSERT(container);
	return container->imei;
}

void
container_set_mac_address(container_t *container, char *mac_address)
{
	ASSERT(container);
	if(mac_address) {
		DEBUG("Setting container MAC address to %s for container %s",
				mac_address, container_get_description(container));
		if (container->mac_address)
			mem_free(container->mac_address);
		container->mac_address = mem_strdup(mac_address);
		container_notify_observers(container);
	}
}

char*
container_get_mac_address(container_t *container)
{
	ASSERT(container);
	return container->mac_address;
}

void
container_set_phone_number(container_t *container, char *phone_number)
{
	ASSERT(container);
	if(phone_number) {
		DEBUG("Setting container phone number to %s for container %s",
				phone_number, container_get_description(container));
		if (container->phone_number)
			mem_free(container->phone_number);
		container->phone_number = mem_strdup(phone_number);
		container_notify_observers(container);
	}
}

char*
container_get_phone_number(container_t *container)
{
	ASSERT(container);
	return container->phone_number;
}

bool
container_get_allow_autostart(container_t *container)
{
	ASSERT(container);
	return container->allow_autostart;
}

bool
container_get_allow_container_switch(container_t *container)
{
	ASSERT(container);
	return container->allow_container_switch;
}

const guestos_t*
container_get_guestos(const container_t *container)
{
	ASSERT(container);
	return container->os;
}

bool
container_is_feature_enabled(const container_t *container, const char *feature)
{
	for (list_t *l = container->feature_enabled_list; l; l = l->next) {
		char *feature_enabled = l->data;
		if (strcmp(feature, feature_enabled) == 0)
			return true;
	}
	return false;
}

static void
container_set_feature_enable(container_t* container, const char* feature)
{
	if (container_is_feature_enabled(container, feature))
		return;

	// TODO syncronize this with config file
	container->feature_enabled_list = list_append(container->feature_enabled_list, mem_strdup(feature));
}

void
container_enable_bluetooth(container_t* container)
{
	container_set_feature_enable(container, "bluetooth");
}

void
container_enable_camera(container_t* container)
{
	container_set_feature_enable(container, "camera");
}

void
container_enable_gps(container_t* container)
{
	container_set_feature_enable(container, "gps");
}

void
container_enable_telephony(container_t* container)
{
	container_set_feature_enable(container, "telephony");
}

void
container_enable_gapps(container_t* container)
{
	container_set_feature_enable(container, "gapps");
}

void
container_enable_fhgapps(container_t* container)
{
	container_set_feature_enable(container, "fhgapps");
}

void
container_set_telephony_name(container_t *container, const char *name)
{
	ASSERT(container);
	c_properties_set_telephony_name(container->prop, name);
}

const char *
container_get_dns_server(const container_t *container)
{
	ASSERT(container);
	return container->dns_server;
}

bool
container_has_netns(const container_t *container)
{
	ASSERT(container);
	return container->ns_net;
}

char *
container_get_first_ip_new(container_t *container)
{
	ASSERT(container);
	return c_net_get_ip_new(container->net);
}

char *
container_get_first_subnet_new(container_t *container)
{
	ASSERT(container);
	return c_net_get_subnet_new(container->net);
}
