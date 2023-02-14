/*
 * This file is part of trust|me
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
 * Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
 */

#define _GNU_SOURCE
#include <sched.h>

#include "container.h"

//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
#include "common/macro.h"
#include "common/mem.h"
#include "common/uuid.h"
#include "common/list.h"
#include "common/nl.h"
#include "common/sock.h"
#include "common/event.h"
#include "common/file.h"
#include "common/dir.h"
#include "common/proc.h"
#include "common/ns.h"

#include "cmld.h"
#include "c_user.h"
#include "c_cgroups.h"
#include "c_net.h"
#include "c_vol.h"
#include "c_cap.h"
#include "c_fifo.h"
#include "c_service.h"
#include "c_time.h"
#include "c_run.h"
#include "c_run.h"
#include "c_audit.h"
#include "c_automnt.h"
#include "container_config.h"
#include "guestos_mgr.h"
#include "guestos.h"
#include "hardware.h"
#include "uevent.h"
#include "audit.h"
#include "smartcard.h"

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
#include <pty.h>

#define CLONE_STACK_SIZE 8192
/* Define some missing clone flags in BIONIC */
#ifndef CLONE_NEWNS
#define CLONE_NEWNS 0x00020000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS 0x04000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC 0x08000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWPID
#define CLONE_NEWPID 0x20000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif

/* Timeout for a container boot. If the container does not come up in that time frame
 * it is killed forcefully */
/* TODO is that enough time for all benign starts? */
#define CONTAINER_START_TIMEOUT 800000
/* Timeout until a container to be stopped gets killed if not yet down */
#define CONTAINER_STOP_TIMEOUT 45000

struct container {
	container_state_t state;
	container_state_t prev_state;
	uuid_t *uuid;
	char *name;
	container_type_t type;
	mount_t *mnt;
	mount_t *mnt_setup;
	bool ns_net;
	bool ns_usr;
	bool ns_ipc;
	char *config_filename;
	char *images_dir;
	char *key;
	uint32_t color;
	bool allow_autostart;
	unsigned int ram_limit; /* maximum RAM space the container may use */
	char *cpus_allowed;

	char *description;

	list_t *csock_list;  /* List of sockets bound inside the container */
	const guestos_t *os; /* weak reference */
	pid_t pid;	     /* PID of the corresponding /init */
	pid_t pid_early;     /* PID of the corresponding early start child */
	int exit_status;     /* if the container's init exited, here we store its exit status */

	char **init_argv; /* command line parameters for init */
	char **init_env;  /* environment variables passed to init */

	list_t *observer_list; /* list of function callbacks to be called when the state changes */
	event_timer_t *stop_timer;  /* timer to handle container stop timeout */
	event_timer_t *start_timer; /* timer to handle a container start timeout */

	/* TODO maybe we should try to get rid of this state since it is only
	 * useful for the starting phase and only there to make it easier to pass
	 * the FD to the child via clone */
	int sync_sock_parent; /* parent sock for start synchronization */
	int sync_sock_child;  /* child sock for start synchronization */

	// Submodules
	c_user_t *user;
	c_cgroups_t *cgroups;
	c_net_t *net; /* encapsulates given network interfaces*/
	c_fifo_t *fifo;

	c_vol_t *vol;
	c_service_t *service;
	c_run_t *run;
	c_audit_t *audit;
	c_automnt_t *automnt;
	c_time_t *time;
	// Wifi module?

	char *imei;
	char *mac_address;
	char *phone_number;

	// list of allowed devices (rules)
	char **device_allowed_list;

	// list of exclusively assigned devices (rules)
	char **device_assigned_list;

	// list of uevent_usbdev_t devices to allow/assign for container
	list_t *usbdev_list;

	char *dns_server;
	bool setup_mode;

	container_token_config_t token;

	bool usb_pin_entry;

	// indicate if the container is synced with its config
	bool is_synced;
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

void
container_free_key(container_t *container)
{
	ASSERT(container);

	IF_NULL_RETURN(container->key);

	mem_memset0(container->key, strlen(container->key));
	mem_free0(container->key);

	INFO("Key of container %s was freed", container->name);
}

container_t *
container_new_internal(const uuid_t *uuid, const char *name, container_type_t type, bool ns_usr,
		       bool ns_net, const guestos_t *os, const char *config_filename,
		       const char *images_dir, mount_t *mnt, unsigned int ram_limit,
		       const char *cpus_allowed, uint32_t color, bool allow_autostart,
		       const char *dns_server, list_t *net_ifaces, char **allowed_devices,
		       char **assigned_devices, list_t *vnet_cfg_list, list_t *usbdev_list,
		       char **init_env, size_t init_env_len, list_t *fifo_list,
		       container_token_type_t ttype, bool usb_pin_entry)
{
	container_t *container = mem_new0(container_t, 1);

	container->state = CONTAINER_STATE_STOPPED;
	container->prev_state = CONTAINER_STATE_STOPPED;

	container->uuid = uuid_new(uuid_string(uuid));
	container->name = mem_strdup(name);
	container->type = type;
	container->mnt = mnt;

	container->mnt_setup = mount_new();
	guestos_fill_mount_setup(os, container->mnt_setup);

	/* do not forget to update container->description in the setters of uuid and name */
	container->description =
		mem_printf("%s (%s)", container->name, uuid_string(container->uuid));

	/* initialize pid to a value indicating it is invalid */
	container->pid = -1;
	container->pid_early = -1;

	/* initialize exit_status to 0 */
	container->exit_status = 0;

	container->ns_usr = ns_usr;
	container->ns_net = ns_net;
	container->ns_ipc = hardware_supports_systemv_ipc() ? true : false;

	/* Allow config_filename to be NULL for "configless"/"anonymous" containers */
	if (config_filename)
		container->config_filename = mem_strdup(config_filename);
	else
		container->config_filename = NULL;

	container->images_dir = mem_strdup(images_dir);
	if (mkdir(images_dir, 0755) < 0 && errno != EEXIST) {
		ERROR_ERRNO("Cound not mkdir container directory %s", images_dir);
		goto error;
	}

	container->color = color;

	container->allow_autostart = allow_autostart;

	container->os = os;

	container->csock_list = NULL;
	container->observer_list = NULL;
	container->stop_timer = NULL;
	container->start_timer = NULL;

	container->imei = NULL;
	container->mac_address = NULL;
	container->phone_number = NULL;

	container->ram_limit = ram_limit;
	container->cpus_allowed = (cpus_allowed) ? mem_strdup(cpus_allowed) : NULL;

	/* Create submodules */
	container->user = c_user_new(container, ns_usr);
	if (!container->user) {
		WARN("Could not initialize user subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->cgroups = c_cgroups_new(container);
	if (!container->cgroups) {
		WARN("Could not initialize cgroups subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	// virtual network interfaces from container config
	for (list_t *elem = vnet_cfg_list; elem != NULL; elem = elem->next) {
		container_vnet_cfg_t *vnet_cfg = elem->data;
		DEBUG("vnet: %s will be added to conatiner (%s)", vnet_cfg->vnet_name,
		      (vnet_cfg->configure) ? "configured" : "unconfigured");
	}

	// network interfaces from container config
	for (list_t *elem = net_ifaces; elem != NULL; elem = elem->next) {
		container_pnet_cfg_t *pnet_cfg = elem->data;
		DEBUG("List element in net_ifaces: %s", pnet_cfg->pnet_name);
	}

	container->net = c_net_new(container, ns_net, vnet_cfg_list, net_ifaces);
	if (!container->net) {
		WARN("Could not initialize net subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->vol = c_vol_new(container);
	if (!container->vol) {
		WARN("Could not initialize volume subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->service = c_service_new(container);
	if (!container->service) {
		WARN("Could not initialize service subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->fifo = c_fifo_new(container, fifo_list);
	if (!container->fifo) {
		WARN("Could not initialize fifo subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->run = c_run_new(container);
	if (!container->run) {
		WARN("Could not initialize run subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->time = c_time_new(container);
	if (!container->time) {
		WARN("Could not initialize time subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->audit = c_audit_new(container);
	if (!container->audit) {
		WARN("Could not initialize audit subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	container->automnt = c_automnt_new(container);
	if (!container->automnt) {
		WARN("Could not initialize automnt subsystem for container %s (UUID: %s)",
		     container->name, uuid_string(container->uuid));
		goto error;
	}

	// construct an argv buffer for execve
	container->init_argv = guestos_get_init_argv_new(os);

	// construct a NULL terminated env buffer for execve
	size_t total_len;
	if (__builtin_add_overflow(guestos_get_init_env_len(os), init_env_len, &total_len)) {
		WARN("Overflow detected when calculating buffer size for container's env");
		goto error;
	}
	if (__builtin_add_overflow(total_len, 1, &total_len)) {
		WARN("Overflow detected when calculating buffer size for container's env");
		goto error;
	}
	container->init_env = mem_new0(char *, total_len);
	size_t i = 0;
	char **os_env = guestos_get_init_env(os);
	for (; i < guestos_get_init_env_len(os); i++)
		container->init_env[i] = mem_strdup(os_env[i]);
	for (size_t j = 0; j < init_env_len; ++j)
		container->init_env[i + j] = mem_strdup(init_env[j]);

	container->dns_server = dns_server ? mem_strdup(dns_server) : NULL;
	container->device_allowed_list = allowed_devices;
	container->device_assigned_list = assigned_devices;
	container->usbdev_list = usbdev_list;

	container->setup_mode = false;

	container->token.type = ttype;
	if (ttype == CONTAINER_TOKEN_TYPE_USB) {
		for (list_t *l = container->usbdev_list; l; l = l->next) {
			uevent_usbdev_t *ud = (uevent_usbdev_t *)l->data;
			if (uevent_usbdev_get_type(ud) == UEVENT_USBDEV_TYPE_TOKEN) {
				container->token.serial =
					mem_strdup(uevent_usbdev_get_i_serial(ud));
				DEBUG("container %s configured to use usb token reader with serial %s",
				      container->name, container->token.serial);
				uevent_usbdev_set_sysfs_props(ud);
				uevent_register_usbdevice(container, ud);
				break; // TODO: handle misconfiguration with several usbtoken?
			}
		}
		if (NULL == container->token.serial) {
			ERROR("Usbtoken reader serial missing in container config. Abort creation of container");
			goto error;
		}
	}

	container->usb_pin_entry = usb_pin_entry;
	container->is_synced = true;

	return container;

error:
	container_free(container);
	return NULL;
}

bool
container_uuid_is_c0id(const uuid_t *uuid)
{
	ASSERT(uuid);
	uuid_t *uuid_c0 = uuid_new("00000000-0000-0000-0000-000000000000");
	bool ret = uuid_equals(uuid, uuid_c0);
	uuid_free(uuid_c0);
	return ret;
}

/* TODO Error handling */
container_t *
container_new(const char *store_path, const uuid_t *existing_uuid, const uint8_t *config,
	      size_t config_len, uint8_t *sig, size_t sig_len, uint8_t *cert, size_t cert_len)
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
	const char *cpus_allowed;
	uint32_t color;
	uuid_t *uuid;
	uint64_t current_guestos_version;
	uint64_t new_guestos_version;
	bool allow_autostart;
	char **allowed_devices;
	char **assigned_devices;

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
	container_config_t *conf = container_config_new(config_filename, config, config_len, sig,
							sig_len, cert, cert_len);

	if (!conf) {
		WARN("Could not read config file %s", config_filename);
		mem_free0(config_filename);
		mem_free0(images_dir);
		uuid_free(uuid);
		return NULL;
	}

	name = container_config_get_name(conf);

	const char *os_name = container_config_get_guestos(conf);
	DEBUG("New containers os name is %s", os_name);

	// if signed config files are used, always load
	// OS version specified in container config
	if (cmld_uses_signed_configs()) {
		os = guestos_mgr_get_by_version(os_name, container_config_get_guestos_version(conf),
						true);
	} else {
		os = guestos_mgr_get_latest_by_name(os_name, true);
	}

	if (!os) {
		WARN("Could not get GuestOS %s instance for container %s with version v%" PRIu64,
		     os_name, name, container_config_get_guestos_version(conf));
		mem_free0(config_filename);
		mem_free0(images_dir);
		uuid_free(uuid);
		container_config_free(conf);
		return NULL;
	}

	mnt = mount_new();
	guestos_fill_mount(os, mnt);
	container_config_fill_mount(conf, mnt);

	ram_limit = container_config_get_ram_limit(conf);
	DEBUG("New containers max ram is %" PRIu32 "", ram_limit);

	cpus_allowed = container_config_get_cpus_allowed(conf);
	DEBUG("New containers allowed cpu cores are %s", cpus_allowed);

	color = container_config_get_color(conf);

	allow_autostart = container_config_get_allow_autostart(conf);

	current_guestos_version = container_config_get_guestos_version(conf);
	new_guestos_version = guestos_get_version(os);
	if ((current_guestos_version < new_guestos_version) && !cmld_uses_signed_configs()) {
		INFO("Updating guestos version from %" PRIu64 " to %" PRIu64 " for container %s",
		     current_guestos_version, new_guestos_version, name);
		container_config_set_guestos_version(conf, new_guestos_version);
		INFO("guestos_version is now: %" PRIu64 "",
		     container_config_get_guestos_version(conf));
	} else if (current_guestos_version == new_guestos_version) {
		INFO("Keeping current guestos version %" PRIu64 " for container %s",
		     current_guestos_version, name);
	} else {
		WARN("The version of the found guestos (%" PRIu64 ") for container %s is to low",
		     new_guestos_version, name);
		WARN("Current version is %" PRIu64 "; Aborting...", current_guestos_version);
		mem_free0(config_filename);
		mem_free0(images_dir);
		uuid_free(uuid);
		container_config_free(conf);
		mount_free(mnt);
		return NULL;
	}
	ns_usr = file_exists("/proc/self/ns/user") ? container_config_has_userns(conf) : false;
	ns_net = container_config_has_netns(conf);

	container_type_t type = container_config_get_type(conf);

	list_t *net_ifaces = container_config_get_net_ifaces_list_new(conf);

	const char *dns_server = (container_config_get_dns_server(conf)) ?
					 container_config_get_dns_server(conf) :
					 cmld_get_device_host_dns();

	list_t *vnet_cfg_list = (ns_net && !container_uuid_is_c0id(uuid)) ?
					container_config_get_vnet_cfg_list_new(conf) :
					NULL;
	list_t *usbdev_list = container_config_get_usbdev_list_new(conf);

	allowed_devices = container_config_get_dev_allow_list_new(conf);
	assigned_devices = container_config_get_dev_assign_list_new(conf);

	char **init_env = container_config_get_init_env(conf);
	size_t init_env_len = container_config_get_init_env_len(conf);

	// create FIFO list
	char **fifos = container_config_get_fifos(conf);
	list_t *fifo_list = NULL;

	for (size_t i = 0; i < container_config_get_fifos_len(conf); i++) {
		DEBUG("Adding FIFO \'%s\' to container's FIFO list", fifos[i]);

		fifo_list = list_append(fifo_list, mem_strdup(fifos[i]));
	}

	container_token_type_t ttype = container_config_get_token_type(conf);

	bool usb_pin_entry = container_config_get_usb_pin_entry(conf);

	container_t *c =
		container_new_internal(uuid, name, type, ns_usr, ns_net, os, config_filename,
				       images_dir, mnt, ram_limit, cpus_allowed, color,
				       allow_autostart, dns_server, net_ifaces, allowed_devices,
				       assigned_devices, vnet_cfg_list, usbdev_list, init_env,
				       init_env_len, fifo_list, ttype, usb_pin_entry);
	if (c)
		container_config_write(conf);

	uuid_free(uuid);
	mem_free0(images_dir);
	mem_free0(config_filename);

	for (list_t *l = vnet_cfg_list; l; l = l->next) {
		container_vnet_cfg_t *vnet_cfg = l->data;
		mem_free0(vnet_cfg->vnet_name);
		mem_free0(vnet_cfg);
	}
	list_delete(vnet_cfg_list);

	for (list_t *l = net_ifaces; l; l = l->next) {
		container_pnet_cfg_t *pnet_cfg = l->data;
		container_pnet_cfg_free(pnet_cfg);
	}
	list_delete(net_ifaces);

	container_config_free(conf);
	return c;
}

void
container_free(container_t *container)
{
	ASSERT(container);

	/* unregister usb tokens from uevent subsystem */
	for (list_t *l = container_get_usbdev_list(container); l; l = l->next) {
		uevent_usbdev_t *usbdev = l->data;
		if (UEVENT_USBDEV_TYPE_TOKEN == uevent_usbdev_get_type(usbdev))
			uevent_unregister_usbdevice(container, usbdev);
	}

	container_free_key(container);

	uuid_free(container->uuid);
	mem_free0(container->name);

	for (list_t *l = container->csock_list; l; l = l->next) {
		container_sock_t *cs = l->data;
		mem_free0(cs->path);
		mem_free0(cs);
	}
	list_delete(container->csock_list);

	if (container->config_filename)
		mem_free0(container->config_filename);

	mem_free0(container->cpus_allowed);

	if (container->init_argv) {
		for (char **arg = container->init_argv; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(container->init_argv);
	}
	if (container->init_env) {
		for (char **arg = container->init_env; *arg; arg++) {
			mem_free0(*arg);
		}
		mem_free0(container->init_env);
	}

	if (container->mnt)
		mount_free(container->mnt);
	if (container->mnt_setup)
		mount_free(container->mnt_setup);

	if (container->user)
		c_user_free(container->user);
	if (container->cgroups)
		c_cgroups_free(container->cgroups);
	if (container->net)
		c_net_free(container->net);
	if (container->vol)
		c_vol_free(container->vol);
	if (container->run)
		c_run_free(container->run);
	if (container->time)
		c_time_free(container->time);
	if (container->service)
		c_service_free(container->service);
	if (container->automnt)
		c_automnt_free(container->automnt);
	if (container->imei)
		mem_free0(container->imei);
	if (container->mac_address)
		mem_free0(container->mac_address);
	if (container->phone_number)
		mem_free0(container->phone_number);
	if (container->dns_server)
		mem_free0(container->dns_server);
	mem_free0(container->device_allowed_list);
	mem_free0(container->device_assigned_list);

	for (list_t *l = container->usbdev_list; l; l = l->next) {
		mem_free0(l->data);
	}
	list_delete(container->usbdev_list);

	if (container->token.uuid)
		uuid_free(container->token.uuid);

	if (container->token.serial)
		mem_free0(container->token.serial);

	if (container->token.devpath)
		mem_free0(container->token.devpath);
	mem_free0(container);
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

const mount_t *
container_get_mount_setup(const container_t *container)
{
	ASSERT(container);
	return container->mnt_setup;
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

	DEBUG("Setting oom_adj of trustme service (PID %d) in container %s to -17", service_pid,
	      container_get_description(container));
	char *path = mem_printf("/proc/%d/oom_adj", service_pid);
	int ret = file_write(path, "-17", -1);
	if (ret < 0)
		ERROR_ERRNO("Failed to write to %s", path);
	mem_free0(path);
}

c_cgroups_t *
container_get_cgroups(const container_t *container)
{
	ASSERT(container);
	return container->cgroups;
}

int
container_add_pid_to_cgroups(const container_t *container, pid_t pid)
{
	ASSERT(container);
	return c_cgroups_add_pid(container->cgroups, pid);
}

int
container_set_cap_current_process(const container_t *container)
{
	ASSERT(container);
	return c_cap_set_current_process(container);
}

int
container_get_console_sock_cmld(const container_t *container, int session_fd)
{
	ASSERT(container);
	return c_run_get_console_sock_cmld(container->run, session_fd);
}

int
container_setuid0(const container_t *container)
{
	ASSERT(container);
	return c_user_setuid0(container->user);
}

bool
container_get_sync_state(const container_t *container)
{
	ASSERT(container);
	return container->is_synced;
}

void
container_set_sync_state(container_t *container, bool state)
{
	ASSERT(container);
	container->is_synced = state;
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
	return mem_printf("#%02X%02X%02X", (container->color >> 24) & 0xff,
			  (container->color >> 16) & 0xff, (container->color >> 8) & 0xff);
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
		WARN("Trying to write configless container to file... Try to set config"
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
	return container_uuid_is_c0id(container->uuid);
}

bool
container_is_encrypted(const container_t *container)
{
	ASSERT(container);
	return c_vol_is_encrypted(container->vol);
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

const char *
container_audit_get_last_ack(const container_t *container)
{
	ASSERT(container);
	return c_audit_get_last_ack(container->audit);
}

void
container_audit_set_last_ack(const container_t *container, const char *last_ack)
{
	ASSERT(container);
	c_audit_set_last_ack(container->audit, last_ack);
}

int
container_audit_get_processing_ack(const container_t *container)
{
	ASSERT(container);
	return c_audit_get_processing_ack(container->audit);
}

void
container_audit_set_processing_ack(const container_t *container, bool processing_ack)
{
	ASSERT(container);
	c_audit_set_processing_ack(container->audit, processing_ack);
}

int
container_audit_record_notify(const container_t *container, uint64_t remaining_storage)
{
	ASSERT(container);
	return c_service_audit_notify(container->service, remaining_storage);
}

int
container_audit_record_send(const container_t *container, const uint8_t *buf, uint32_t buflen)
{
	ASSERT(container);
	return c_service_audit_send_record(container->service, buf, buflen);
}

int
container_audit_notify_complete(const container_t *container)
{
	ASSERT(container);
	return c_service_send_message(container->service, C_SERVICE_MESSAGE_AUDIT_COMPLETE);
}

int
container_audit_process_ack(const container_t *container, const char *ack)
{
	return audit_process_ack(container, ack);
}

void
container_audit_set_loginuid(container_t *container, uint32_t uid)
{
	ASSERT(container);
	c_audit_set_loginuid(container->audit, uid);
}

uint32_t
container_audit_get_loginuid(const container_t *container)
{
	ASSERT(container);
	return c_audit_get_loginuid(container->audit);
}

/**
 * This function should be called only on a (physically) not-running container and
 * should make sure that the container and all its submodules are in the same
 * state they had immediately after their creation with _new().
 * Return values are not gathered, as the cleanup should just work as the system allows.
 * It also sets container state to rebooting if 'is_rebooting' is set and
 * stopped otherwise.
 */
static void
container_cleanup(container_t *container, bool is_rebooting)
{
	c_automnt_cleanup(container->automnt);
	c_fifo_cleanup(container->fifo);
	c_cgroups_cleanup(container->cgroups);
	c_service_cleanup(container->service);
	c_run_cleanup(container->run);
	c_time_cleanup(container->time);

	/*
	 * maintain some state concerning mounts and corresponding shifted uid
	 * states in case of rebooting. We need this, since the volume key for
	 * encrypted volumes is cleared from cmld's memory after initial use.
	 */
	c_net_cleanup(container->net, is_rebooting);
	c_user_cleanup(container->user, is_rebooting);
	/* cleanup c_vol last, as it removes partitions */
	c_vol_cleanup(container->vol, is_rebooting);

	container->pid = -1;
	container->pid_early = -1;

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

	container_state_t state =
		is_rebooting ? CONTAINER_STATE_REBOOTING : CONTAINER_STATE_STOPPED;
	container_set_state(container, state);
}

void
container_sigchld_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	ASSERT(data);

	container_t *container = data;

	TRACE("SIGCHLD handler called for container %s with PID %d",
	      container_get_description(container), container->pid);

	/* In the start function the childs init process gets set a process group which has
	 * the same pgid as its pid. We wait for all processes belonging to our container's
	 * process group, but only change the containers state to stopped if the init exited */
	pid_t container_pid = container->pid;
	pid_t pid = 0;
	int status = 0;
	while ((pid = waitpid(-(container_pid), &status, WNOHANG))) {
		if (pid == container_pid) {
			bool rebooting = false;
			if (WIFEXITED(status)) {
				INFO("Container %s terminated (init process exited with status=%d)",
				     container_get_description(container), WEXITSTATUS(status));
				container->exit_status = WEXITSTATUS(status);
			} else if (WIFSIGNALED(status)) {
				INFO("Container %s killed by signal %d",
				     container_get_description(container), WTERMSIG(status));
				/* Since Kernel 3.4 reboot inside pid namspaces
				 * are signaled by SIGHUP (see manpage REBOOT(2)) */
				if (WTERMSIG(status) == SIGHUP)
					rebooting = true;
			} else {
				continue;
			}
			/* remove the sigchld callback for this container from the event loop */
			event_remove_signal(sig);
			event_signal_free(sig);

			audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
					rebooting ? "reboot" : "stop",
					uuid_string(container_get_uuid(container)), 0);

			/* cleanup and set states accordingly to notify observers */
			container_cleanup(container, rebooting);

		} else if (pid == -1) {
			if (errno == ECHILD) {
				DEBUG("Process group of container %s terminated completely",
				      container_get_description(container));

				if (!container_get_sync_state(container)) {
					DEBUG("Container is out of sync with its config. Reloading..");
					if (cmld_reload_container(container_get_uuid(container),
								  cmld_get_containers_dir()) != 0) {
						ERROR("Failed to reload container on config update");
					}
				}

			} else {
				audit_log_event(container_get_uuid(container), FSA, CMLD,
						CONTAINER_MGMT, "container-observer-error",
						uuid_string(container_get_uuid(container)), 0);
				WARN_ERRNO("waitpid failed for container %s",
					   container_get_description(container));
			}
			break;
		} else {
			DEBUG("Reaped a child with PID %d for container %s", pid,
			      container_get_description(container));
		}
	}

	TRACE("No more childs to reap. Callback exiting...");
}

void
container_sigchld_early_cb(UNUSED int signum, event_signal_t *sig, void *data)
{
	container_t *container = data;
	ASSERT(container);

	pid_t pid;
	int status = 0;

	TRACE("SIGCHLD handler called for container %s early start child with PID %d",
	      container_get_description(container), container->pid);

	if ((pid = waitpid(container->pid_early, &status, WNOHANG)) > 0) {
		TRACE("Reaped early container child process: %d", pid);
		/* remove the sigchld callback for this early child from the event loop */
		event_remove_signal(sig);
		event_signal_free(sig);
		// cleanup if early child returned with an error
		if ((WIFEXITED(status) && WEXITSTATUS(status)) || WIFSIGNALED(status)) {
			container_set_state(container, CONTAINER_STATE_STOPPED);
			container->pid_early = -1;
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
	ASSERT(data);

	int ret = 0;

	container_t *container = data;
	char *kvm_root = mem_printf("/tmp/%s", uuid_string(container->uuid));

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

	if (c_user_start_child(container->user) < 0) {
		ret = CONTAINER_ERROR_USER;
		goto error;
	}

	if (c_net_start_child(container->net) < 0) {
		ret = CONTAINER_ERROR_NET;
		goto error;
	}

	if (c_cgroups_start_child(container->cgroups) < 0) {
		ret = CONTAINER_ERROR_CGROUPS;
		goto error;
	}

	if (c_vol_start_child(container->vol) < 0) {
		ret = CONTAINER_ERROR_VOL;
		goto error;
	}

	if (c_time_start_child(container->time) < 0) {
		ret = CONTAINER_ERROR_TIME;
		goto error;
	}

	if (c_service_start_child(container->service) < 0) {
		ret = CONTAINER_ERROR_SERVICE;
		goto error;
	}

	if (c_cap_start_child(container) < 0) {
		//ret = 1; // FIXME
		goto error;
	}

	char *root = (container->type == CONTAINER_TYPE_KVM) ? kvm_root : "/";
	if (chdir(root) < 0) {
		WARN_ERRNO("Could not chdir to \"%s\" in container %s", root,
			   uuid_string(container->uuid));
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

	if (c_cgroups_start_pre_exec_child(container->cgroups) < 0) {
		ret = CONTAINER_ERROR_CGROUPS;
		goto error;
	}

	if (c_time_start_pre_exec_child(container->time) < 0) {
		ret = CONTAINER_ERROR_TIME;
		goto error;
	}

	DEBUG("Will start %s after closing filedescriptors of %s", guestos_get_init(container->os),
	      container_get_description(container));

	DEBUG("init_argv:");
	for (char **arg = container->init_argv; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}
	DEBUG("init_env:");
	for (char **arg = container->init_env; *arg; arg++) {
		DEBUG("\t%s", *arg);
	}

	if (container->type == CONTAINER_TYPE_KVM) {
		int fd_master;
		int pid = forkpty(&fd_master, NULL, NULL, NULL);

		if (pid == -1) {
			ERROR_ERRNO("Forkpty() failed!");
			goto error;
		}
		if (pid == 0) { // child
			char *const argv[] = { "/usr/bin/lkvm", "run", "-d", kvm_root, NULL };
			execv(argv[0], argv);
			WARN("Could not run exec for kvm container %s",
			     uuid_string(container->uuid));
		} else { // parent
			char buffer[128];
			ssize_t read_bytes;
			char *kvm_log =
				mem_printf("%s.kvm.log", container_get_images_dir(container));
			read_bytes = read(fd_master, buffer, 128);
			file_write(kvm_log, buffer, read_bytes);
			while ((read_bytes = read(fd_master, buffer, 128))) {
				file_write_append(kvm_log, buffer, read_bytes);
			}
			return CONTAINER_ERROR;
		}
	}

	if (container_get_state(container) != CONTAINER_STATE_SETUP) {
		DEBUG("After closing all file descriptors no further debugging info can be printed");
		if (container_close_all_fds()) {
			WARN("Closing all file descriptors failed, continuing anyway...");
		}
	}

	// if init provided by guestos does not exists use mapped c_service as init
	const char *container_init = file_exists(guestos_get_init(container->os)) ?
					     guestos_get_init(container->os) :
					     CSERVICE_TARGET;
	execve(container_init, container->init_argv, container->init_env);

	/* handle possibly empty rootfs in setup_mode */
	if (container_get_state(container) == CONTAINER_STATE_SETUP) {
		// fallback: if there is still no init, just idle to keep namespaces open
		event_reset();
		WARN("No init found for container '%s', just loop forever!",
		     uuid_string(container->uuid));
		event_loop();
	}

	WARN_ERRNO("Could not run exec for container %s", uuid_string(container->uuid));

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

static int
container_start_child_early(void *data)
{
	ASSERT(data);

	int ret = 0;

	container_t *container = data;

	close(container->sync_sock_parent);

	if (c_audit_start_child_early(container->audit) < 0) {
		ret = CONTAINER_ERROR_AUDIT;
		goto error;
	}

	if (c_vol_start_child_early(container->vol) < 0) {
		ret = CONTAINER_ERROR_VOL;
		goto error;
	}

	if (c_automnt_start_child_early(container->automnt) < 0) {
		ret = CONTAINER_ERROR_VOL;
		goto error;
	}

	void *container_stack = NULL;
	/* Allocate node stack */
	if (!(container_stack = alloca(CLONE_STACK_SIZE))) {
		WARN_ERRNO("Not enough memory for allocating container stack");
		goto error;
	}
	void *container_stack_high = (void *)((const char *)container_stack + CLONE_STACK_SIZE);
	/* Set namespaces for node */
	/* set some basic and non-configurable namespaces */
	unsigned long clone_flags = 0;
	clone_flags |= SIGCHLD | CLONE_PARENT; // sig child to main process
	clone_flags |= CLONE_NEWUTS | CLONE_NEWNS | CLONE_NEWPID;
	if (container->ns_ipc)
		clone_flags |= CLONE_NEWIPC;

	// on reboots of c0 rejoin existing userns and netns
	if (cmld_containers_get_c0() == container &&
	    container->prev_state == CONTAINER_STATE_REBOOTING) {
		if (c_user_join_userns(container->user) < 0) {
			ret = CONTAINER_ERROR_USER;
			goto error;
		}
		if (c_net_join_netns(container->net) < 0) {
			ret = CONTAINER_ERROR_NET;
			goto error;
		}
	} else {
		if (container->ns_usr)
			clone_flags |= CLONE_NEWUSER;
		if (container->ns_net)
			clone_flags |= CLONE_NEWNET;
	}

	container->pid = clone(container_start_child, container_stack_high, clone_flags, container);
	if (container->pid < 0) {
		ERROR_ERRNO("Double clone container failed");
		goto error;
	}

	char *msg_pid = mem_printf("%d", container->pid);
	if (write(container->sync_sock_child, msg_pid, strlen(msg_pid)) < 0) {
		ERROR_ERRNO("write pid '%s' to sync socket failed", msg_pid);
		goto error;
	}
	mem_free0(msg_pid);
	return 0;

error:
	if (ret == 0) {
		ret = CONTAINER_ERROR;
	}

	// send error message to parent
	char msg_error = CONTAINER_START_SYNC_MSG_ERROR;
	if (write(container->sync_sock_child, &msg_error, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}

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
		     " Killing it...",
		     container_get_description(container));
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
	ASSERT(data);

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
	if (c_time_start_pre_exec(container->time) < 0) {
		WARN("c_time_start_pre_exec failed");
		goto error_pre_exec;
	}

	if (c_cgroups_start_pre_exec(container->cgroups) < 0) {
		WARN("c_cgroups_start_pre_exec failed");
		goto error_pre_exec;
	}
	// during reboot c_vol state is not cleared, thus skip pre_exec here
	if (c_vol_start_pre_exec(container->vol) < 0) {
		WARN("c_vol_start_pre_exec failed");
		goto error_pre_exec;
	}

	if (c_service_start_pre_exec(container->service) < 0) {
		WARN("c_service_start_pre_exec failed");
		goto error_pre_exec;
	}

	// skip setup of start timer and maintain SETUP state if in SETUP mode
	if (container_get_state(container) != CONTAINER_STATE_SETUP) {
		container_set_state(container, CONTAINER_STATE_BOOTING);

		/* register a timer to kill the container if it does not come up in time */
		container->start_timer = event_timer_new(CONTAINER_START_TIMEOUT, 1,
							 &container_start_timeout_cb, container);
		event_add_timer(container->start_timer);
	}

	/* Notify child to do its exec */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(fd, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error;
	}

	/* Call all c_<module>_start_post_exec hooks */
	if (c_time_start_post_exec(container->time) < 0) {
		WARN("c_time_start_post_exec failed");
		goto error;
	}

	if (c_automnt_start_post_exec(container->automnt) < 0) {
		WARN("c_automnt_start_post_exec failed");
		goto error;
	}

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
container_run(container_t *container, int create_pty, char *cmd, ssize_t argc, char **argv,
	      int session_fd)
{
	ASSERT(container);
	ASSERT(cmd);

	switch (container_get_state(container)) {
	case CONTAINER_STATE_BOOTING:
	case CONTAINER_STATE_RUNNING:
	case CONTAINER_STATE_SETUP:
		break;
	default:
		WARN("Container %s is not running thus no command could be exec'ed",
		     container_get_description(container));
		return -1;
	}

	TRACE("Forwarding request to c_run subsystem");
	return c_run_exec_process(container->run, create_pty, cmd, argc, argv, session_fd);
}

int
container_write_exec_input(container_t *container, char *exec_input, int session_fd)
{
	TRACE("Forwarding write request to c_run subsystem");
	return c_run_write_exec_input(container->run, exec_input, session_fd);
}

static void
container_start_post_clone_early_cb(int fd, unsigned events, event_io_t *io, void *data)
{
	ASSERT(data);
	int ret = 0;

	container_t *container = data;

	DEBUG("Received event from child process %u", events);

	if (events == EVENT_IO_EXCEPT) {
		ERROR("Received exception from child process");
		goto error_pre_clone;
	}

	// receive success or error message from started child
	char *pid_msg = mem_alloc0(34);
	if (read(container->sync_sock_parent, pid_msg, 33) <= 0) {
		WARN_ERRNO("Could not read from sync socket");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	if (pid_msg[0] == CONTAINER_START_SYNC_MSG_ERROR) {
		WARN("Early child died with error!");
		mem_free0(pid_msg);
		goto error_pre_clone;
	}

	// release post_clone_early io handler
	event_remove_io(io);
	event_io_free(io);

	DEBUG("Received pid message from child %s", pid_msg);
	container->pid = atoi(pid_msg);
	mem_free0(pid_msg);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(fd, EVENT_IO_READ, &container_start_post_clone_cb, container);
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

	if (c_user_start_post_clone(container->user)) {
		ret = CONTAINER_ERROR_USER;
		goto error_post_clone;
	}

	if (c_fifo_start_post_clone(container->fifo)) {
		ret = CONTAINER_ERROR_FIFO;
		goto error_post_clone;
	}

	/*********************************************************/
	/* NOTIFY CHILD TO START */
	char msg_go = CONTAINER_START_SYNC_MSG_GO;
	if (write(container->sync_sock_parent, &msg_go, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
		goto error_post_clone;
	}

	return;

error_pre_clone:
	event_remove_io(io);
	event_io_free(io);
	close(fd);
	return;

error_post_clone:
	if (ret == 0)
		ret = CONTAINER_ERROR;
	char msg_stop = CONTAINER_START_SYNC_MSG_STOP;
	if (write(container->sync_sock_parent, &msg_stop, 1) < 0) {
		WARN_ERRNO("write to sync socket failed");
	}
	container_kill(container);
	return;
}

int
container_start(container_t *container)
{
	ASSERT(container);

	if ((container_get_state(container) != CONTAINER_STATE_STOPPED) &&
	    (container_get_state(container) != CONTAINER_STATE_REBOOTING)) {
		ERROR("Container %s is not stopped and can therefore not be started",
		      container_get_description(container));
		return CONTAINER_ERROR;
	}

	int ret = 0;

	container_set_state(container, CONTAINER_STATE_STARTING);

	/*********************************************************/
	/* PRE CLONE HOOKS */

	if (c_user_start_pre_clone(container->user) < 0) {
		ret = CONTAINER_ERROR_USER;
		goto error_pre_clone;
	}

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

	// activate setup mode in perent and child
	if (container->setup_mode) {
		container_set_state(container, CONTAINER_STATE_SETUP);
		INFO("Container in setup mode!");
	}

	/* TODO find out if stack is only necessary with CLONE_VM */
	pid_t container_pid =
		clone(container_start_child_early, container_stack_high, clone_flags, container);
	if (container_pid < 0) {
		WARN_ERRNO("Clone container failed");
		goto error_pre_clone;
	}
	container->pid = container_pid;

	/* close the childs end of the sync sockets */
	close(container->sync_sock_child);

	/*********************************************************/
	/* REGISTER SOCKET TO RECEIVE STATUS MESSAGES FROM CHILD */
	event_io_t *sync_sock_parent_event =
		event_io_new(container->sync_sock_parent, EVENT_IO_READ,
			     &container_start_post_clone_early_cb, container);
	event_add_io(sync_sock_parent_event);

	// handler for early start child process which dies after double fork
	event_signal_t *sig = event_signal_new(SIGCHLD, container_sigchld_early_cb, container);
	event_add_signal(sig);

	if (c_audit_start_post_clone_early(container->audit)) {
		ERROR("c_audit_start_post_clone");
	}

	return 0;

error_pre_clone:
	container_cleanup(container, false);
	return ret;
}

void
container_kill(container_t *container)
{
	ASSERT(container);

	if (container_get_state(container) == CONTAINER_STATE_STOPPED) {
		DEBUG("Trying to kill stopped container... doing nothing.");
		return;
	}

	if (container_get_pid(container) < 0) {
		ERROR("No pid (%d) for container %s -> state mismatch, do not kill anything!",
		      container_get_pid(container), container_get_description(container));
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
	DEBUG("Reached container stop timeout for container %s. Doing the kill now",
	      container_get_description(container));

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
	event_timer_t *container_stop_timer =
		event_timer_new(CONTAINER_STOP_TIMEOUT, 1, &container_stop_timeout_cb, container);
	event_add_timer(container_stop_timer);
	container->stop_timer = container_stop_timer;

	/* remove setup_mode for next run */
	if (container_get_state(container) == CONTAINER_STATE_SETUP)
		container_set_setup_mode(container, false);

	/* set state to shutting down (notifies observers) */
	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "shutting-down",
			uuid_string(container_get_uuid(container)), 0);
	container_set_state(container, CONTAINER_STATE_SHUTTING_DOWN);

	/* call stop hooks for c_* modules */
	DEBUG("Call stop hooks for modules");

	if (c_service_stop(container->service) < 0) {
		ret = CONTAINER_ERROR;

		char *argv[] = { "halt", NULL };
		if (c_run_exec_process(container->run, false, argv[0], 1, argv, -1)) {
			audit_log_event(container_get_uuid(container), FSA, CMLD, CONTAINER_MGMT,
					"request-clean-shutdown",
					uuid_string(container_get_uuid(container)), 0);
			goto error_stop;
		}
	}

	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT,
			"request-clean-shutdown", uuid_string(container_get_uuid(container)), 0);

	// When the stop command was emitted, the TrustmeService tries to shut down the container
	// i.g. to terminate the container's init process.
	// we need to wait for the SIGCHLD signal for which we have a callback registered, which
	// does the cleanup and sets the state of the container to stopped.
	DEBUG("Stop container successfully emitted. Wait for child process to terminate (SICHLD)");

	return ret;

error_stop:
	DEBUG("Modules could not be stopped successfully, killing container.");
	container_kill(container);
	audit_log_event(container_get_uuid(container), SSA, CMLD, CONTAINER_MGMT, "force-stop",
			uuid_string(container_get_uuid(container)), 0);
	return ret;
}

int
container_bind_socket_before_start(container_t *container, const char *path)
{
	ASSERT(container);

	container_sock_t *cs = mem_new0(container_sock_t, 1);
	if ((cs->sockfd = sock_unix_create(SOCK_STREAM)) < 0) {
		mem_free0(cs);
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
	ASSERT(data);
	container_t *container = data;
	/* Only do the rest of the callback if the file name ends with .img */
	int len = strlen(name);
	if (len >= 4 && !strcmp(name + len - 4, ".img")) {
		char *image_path = mem_printf("%s/%s", path, name);
		DEBUG("Deleting image of container %s: %s", container_get_description(container),
		      image_path);
		if (unlink(image_path) == -1) {
			ERROR_ERRNO("Could not delete image %s", image_path);
		}
		mem_free0(image_path);
	}
	return 0;
}

int
container_wipe_finish(container_t *container)
{
	ASSERT(container);

	/* remove all images of the container */
	if (dir_foreach(container->images_dir, &container_wipe_image_cb, container) < 0) {
		WARN("Could not open %s images path for wiping container",
		     container_get_description(container));
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

int
container_destroy(container_t *container)
{
	ASSERT(container);
	int ret = -1;

	INFO("Destroying container %s with uuid=%s", container_get_name(container),
	     uuid_string(container_get_uuid(container)));

	/* wipe the container */
	if (file_is_dir(container_get_images_dir(container))) {
		// wipe_finish only removes data images not configs */
		if ((ret = container_wipe_finish(container))) {
			ERROR("Could not wipe container");
			return ret;
		}
		if (rmdir(container_get_images_dir(container)))
			WARN("Could not delete leftover container dir");
	}

	/* remove config files */
	char *file_name_created = mem_printf("%s.created", container_get_images_dir(container));
	if (file_exists(file_name_created))
		if (0 != unlink(file_name_created)) {
			ERROR_ERRNO("Can't delete .created file!");
		}
	mem_free0(file_name_created);

	char *file_name_uid = mem_printf("%s.uid", container_get_images_dir(container));
	if (file_exists(file_name_uid))
		if (0 != unlink(file_name_uid)) {
			ERROR_ERRNO("Can't delete .uid file!");
		}
	mem_free0(file_name_uid);

	if (smartcard_release_pairing(container)) {
		ERROR("Can't remove token paired file!");
	}

	if ((ret = unlink(container_get_config_filename(container))))
		ERROR_ERRNO("Can't delete config file!");
	return ret;
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

	// maintaining SETUP state in following cases
	if (container->state == CONTAINER_STATE_SETUP) {
		switch (state) {
		case CONTAINER_STATE_BOOTING:
		case CONTAINER_STATE_RUNNING:
			return;
		default:
			break;
		}
	}

	// save previous state
	container->prev_state = container->state;

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

container_state_t
container_get_prev_state(const container_t *container)
{
	ASSERT(container);
	return container->prev_state;
}

container_type_t
container_get_type(const container_t *container)
{
	ASSERT(container);
	return container->type;
}

container_callback_t *
container_register_observer(container_t *container,
			    void (*cb)(container_t *, container_callback_t *, void *), void *data)
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
		mem_free0(cb);
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

	container_free_key(container);

	container->key = strdup(key);

	container_notify_observers(container);
}

unsigned int
container_get_ram_limit(const container_t *container)
{
	ASSERT(container);

	return container->ram_limit;
}

const char *
container_get_cpus_allowed(const container_t *container)
{
	ASSERT(container);

	return container->cpus_allowed;
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
container_set_imei(container_t *container, char *imei)
{
	ASSERT(container);
	if (imei) {
		DEBUG("Setting container imei to %s for container %s", imei,
		      container_get_description(container));
		if (container->imei)
			mem_free0(container->imei);
		container->imei = mem_strdup(imei);
		container_notify_observers(container);
	}
}

char *
container_get_imei(container_t *container)
{
	ASSERT(container);
	return container->imei;
}

void
container_set_mac_address(container_t *container, char *mac_address)
{
	ASSERT(container);
	if (mac_address) {
		DEBUG("Setting container MAC address to %s for container %s", mac_address,
		      container_get_description(container));
		if (container->mac_address)
			mem_free0(container->mac_address);
		container->mac_address = mem_strdup(mac_address);
		container_notify_observers(container);
	}
}

char *
container_get_mac_address(container_t *container)
{
	ASSERT(container);
	return container->mac_address;
}

void
container_set_phone_number(container_t *container, char *phone_number)
{
	ASSERT(container);
	if (phone_number) {
		DEBUG("Setting container phone number to %s for container %s", phone_number,
		      container_get_description(container));
		if (container->phone_number)
			mem_free0(container->phone_number);
		container->phone_number = mem_strdup(phone_number);
		container_notify_observers(container);
	}
}

char *
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

const guestos_t *
container_get_guestos(const container_t *container)
{
	ASSERT(container);
	return container->os;
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

bool
container_has_userns(const container_t *container)
{
	ASSERT(container);
	return container->ns_usr;
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

time_t
container_get_uptime(const container_t *container)
{
	ASSERT(container);
	return c_time_get_uptime(container->time);
}

time_t
container_get_creation_time(const container_t *container)
{
	ASSERT(container);
	return c_time_get_creation_time(container->time);
}

int
container_add_net_iface(container_t *container, container_pnet_cfg_t *pnet_cfg, bool persistent)
{
	ASSERT(container);
	IF_NULL_RETVAL(pnet_cfg, -1);

	int res = 0;
	container_t *c0 = cmld_containers_get_c0();
	container_state_t state_c0 = container_get_state(c0);
	bool c0_is_up = (state_c0 == CONTAINER_STATE_RUNNING ||
			 state_c0 == CONTAINER_STATE_BOOTING || state_c0 == CONTAINER_STATE_SETUP);

	if (c0 == container) {
		if (c0_is_up)
			res = c_net_add_interface(container->net, pnet_cfg);
		return res;
	}

	/* if c0 is running the interface is occupied by c0, thus we have
	 * to take it back to cml first.
	 */
	if (c0_is_up)
		res = c_net_remove_interface(c0->net, pnet_cfg->pnet_name);

	res |= c_net_add_interface(container->net, pnet_cfg);
	if (res || !persistent)
		return res;

	container_config_t *conf =
		container_config_new(container->config_filename, NULL, 0, NULL, 0, NULL, 0);
	container_config_append_net_ifaces(conf, pnet_cfg->pnet_name);
	container_config_write(conf);
	container_config_free(conf);
	return 0;
}

int
container_remove_net_iface(container_t *container, const char *iface, bool persistent)
{
	ASSERT(container);
	int res = c_net_remove_interface(container->net, iface);
	if (res || !persistent)
		return res;

	container_config_t *conf =
		container_config_new(container->config_filename, NULL, 0, NULL, 0, NULL, 0);
	container_config_remove_net_ifaces(conf, iface);
	container_config_write(conf);
	container_config_free(conf);
	return 0;
}

const char **
container_get_dev_allow_list(const container_t *container)
{
	ASSERT(container);
	return (const char **)container->device_allowed_list;
}

const char **
container_get_dev_assign_list(const container_t *container)
{
	ASSERT(container);
	return (const char **)container->device_assigned_list;
}

list_t *
container_get_usbdev_list(const container_t *container)
{
	ASSERT(container);
	return container->usbdev_list;
}

void
container_set_setup_mode(container_t *container, bool setup)
{
	ASSERT(container);
	if (container->setup_mode == setup)
		return;

	container->setup_mode = setup;
}

bool
container_has_setup_mode(const container_t *container)
{
	ASSERT(container);
	return container->setup_mode;
}

container_vnet_cfg_t *
container_vnet_cfg_new(const char *if_name, const char *rootns_name, const uint8_t mac[6],
		       bool configure)
{
	IF_NULL_RETVAL(if_name, NULL);
	container_vnet_cfg_t *vnet_cfg = mem_new(container_vnet_cfg_t, 1);
	vnet_cfg->vnet_name = mem_strdup(if_name);
	memcpy(vnet_cfg->vnet_mac, mac, 6);
	vnet_cfg->rootns_name = rootns_name ? mem_strdup(rootns_name) : NULL;
	vnet_cfg->configure = configure;
	return vnet_cfg;
}

/**
 * Create a new container_pnet_cfg_t structure for physical NICs that should be
 * made accessible to a container.
 */
container_pnet_cfg_t *
container_pnet_cfg_new(const char *if_name_mac, bool mac_filter, list_t *mac_whitelist)
{
	container_pnet_cfg_t *pnet_cfg = mem_new0(container_pnet_cfg_t, 1);

	pnet_cfg->pnet_name = mem_strdup(if_name_mac);
	pnet_cfg->mac_filter = mac_filter;
	pnet_cfg->mac_whitelist = NULL;

	if (!mac_filter)
		return pnet_cfg;

	for (list_t *l = mac_whitelist; l; l = l->next) {
		uint8_t *mac = mem_alloc0(6);
		memcpy(mac, l->data, 6);
		pnet_cfg->mac_whitelist = list_append(pnet_cfg->mac_whitelist, mac);
	}

	return pnet_cfg;
}

void
container_pnet_cfg_free(container_pnet_cfg_t *pnet_cfg)
{
	IF_NULL_RETURN(pnet_cfg);

	for (list_t *l = pnet_cfg->mac_whitelist; l; l = l->next) {
		uint8_t *mac = l->data;
		mem_free0(mac);
	}
	list_delete(pnet_cfg->mac_whitelist);
	mem_free0(pnet_cfg);
}

void
container_vnet_cfg_free(container_vnet_cfg_t *vnet_cfg)
{
	IF_NULL_RETURN(vnet_cfg);
	if (vnet_cfg->vnet_name)
		mem_free0(vnet_cfg->vnet_name);
	if (vnet_cfg->rootns_name)
		mem_free0(vnet_cfg->rootns_name);
	mem_free0(vnet_cfg);
}

list_t *
container_get_vnet_runtime_cfg_new(container_t *container)
{
	return c_net_get_interface_mapping_new(container->net);
}

int
container_device_allow(container_t *container, int major, int minor, bool assign)
{
	ASSERT(container);
	return c_cgroups_devices_chardev_allow(container->cgroups, major, minor, assign);
}

int
container_device_deny(container_t *container, int major, int minor)
{
	ASSERT(container);
	return c_cgroups_devices_chardev_deny(container->cgroups, major, minor);
}

bool
container_is_device_allowed(const container_t *container, int major, int minor)
{
	ASSERT(container);
	return c_cgroups_devices_is_dev_allowed(container->cgroups, major, minor);
}

char *
container_get_rootdir(const container_t *container)
{
	return c_vol_get_rootdir(container->vol);
}

int
container_shift_ids(const container_t *container, const char *path, bool is_root)
{
	ASSERT(container);
	if (!container->ns_usr)
		return 0;

	return c_user_shift_ids(container->user, path, is_root);
}

int
container_shift_mounts(const container_t *container)
{
	ASSERT(container);
	if (!container->ns_usr)
		return 0;

	return c_user_shift_mounts(container->user);
}

int
container_get_uid(const container_t *container)
{
	ASSERT(container);
	return c_user_get_uid(container->user);
}

container_token_type_t
container_get_token_type(const container_t *container)
{
	ASSERT(container);
	return container->token.type;
}

char *
container_get_usbtoken_serial(const container_t *container)
{
	ASSERT(container);
	IF_FALSE_RETVAL_ERROR(CONTAINER_TOKEN_TYPE_USB == container->token.type, NULL);

	return container->token.serial;
}

char *
container_get_usbtoken_devpath(const container_t *container)
{
	ASSERT(container);
	IF_FALSE_RETVAL_ERROR(CONTAINER_TOKEN_TYPE_USB == container->token.type, NULL);

	return container->token.devpath;
}

void
container_set_usbtoken_devpath(container_t *container, char *devpath)
{
	ASSERT(container);
	IF_FALSE_RETURN(CONTAINER_TOKEN_TYPE_USB == container->token.type);

	if (container->token.devpath)
		mem_free0(container->token.devpath);

	DEBUG("Setting token devpath for container %s to %s", container->name, devpath);

	container->token.devpath = devpath;
}

void
container_set_token_uuid(container_t *container, const char *tuuid)
{
	ASSERT(container);
	container->token.uuid = uuid_new(tuuid);
}

uuid_t *
container_get_token_uuid(const container_t *container)
{
	ASSERT(container);
	return container->token.uuid;
}

void
container_set_token_is_init(container_t *container, const bool is_init)
{
	ASSERT(container);
	container->token.is_init = is_init;
}

bool
container_get_token_is_init(const container_t *container)
{
	ASSERT(container);
	return container->token.is_init;
}

void
container_set_token_is_linked_to_device(container_t *container, const bool is_paired)
{
	ASSERT(container);
	container->token.is_paired_with_device = is_paired;
}

bool
container_get_token_is_linked_to_device(const container_t *container)
{
	ASSERT(container);
	return container->token.is_paired_with_device;
}

int
container_exec_cap_systime(const container_t *container, char *const *argv)
{
	ASSERT(container);
	return c_cap_exec_cap_systime(container, argv);
}

bool
container_get_usb_pin_entry(const container_t *container)
{
	ASSERT(container);
	return container->usb_pin_entry;
}
