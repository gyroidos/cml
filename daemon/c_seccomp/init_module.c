/*
 * This file is part of GyroidOS
 * Copyright(c) 2013 - 2024 Fraunhofer AISEC
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
 * @file c_seccomp/init_module.c
 *
 * This file is part of c_seccomp module. It contains the emulation code for the finit_module()
 * system call. We call this module 'init_module' analodous to the manpage which lists
 * finit_module() syscall under man init_module(2).
 */

#define _GNU_SOURCE

#include "../compartment.h"
#include "../container.h"
#include "../audit.h"

#include <common/macro.h>
#include <common/mem.h>
#include <common/proc.h>

#include "seccomp.h"

#include <fcntl.h>
#include <string.h>

#include <sys/syscall.h>
#include <sys/utsname.h>

#include <linux/capability.h>
#include <linux/module.h>

//#undef LOGF_LOG_MIN_PRIO
//#define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE

#ifndef MODULE_INIT_COMPRESSED_FILE
#define MODULE_INIT_COMPRESSED_FILE 4
#endif

static int
finit_module(int fd, const char *param_values, int flags)
{
	return syscall(__NR_finit_module, fd, param_values, flags);
}

/**
 * Parse module dependencies file "/lib/modules/<release>/modules.dep"
 * to retrieve module dependencies for an allowed module
 */
list_t *
c_seccomp_get_module_dependencies_new(const char *module_name)
{
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
	list_t *ret_list = NULL;

	struct utsname u_name;
	uname(&u_name);

	char *modules_dep_path = mem_printf("/lib/modules/%s/modules.dep", u_name.release);

	fp = fopen(modules_dep_path, "r");
	mem_free0(modules_dep_path);

	IF_NULL_RETVAL(fp, NULL);

	const char *mod_suffix = ".ko";
	char *mod_name = mem_alloc0(strlen(module_name) + strlen(mod_suffix) + 1);
	char *_mod_name = mem_alloc0(strlen(module_name) + strlen(mod_suffix) + 1);

	size_t i;
	for (i = 0; i < strlen(module_name); i++) {
		mod_name[i] = (module_name[i] == '_') ? '-' : module_name[i];
		_mod_name[i] = (module_name[i] == '-') ? '_' : module_name[i];
	}
	for (size_t j = 0; j < strlen(mod_suffix); j++) {
		mod_name[i + j] = mod_suffix[j];
		_mod_name[i + j] = mod_suffix[j];
	}

	TRACE("Searching for (_)mod_name '%s' and '%s'", mod_name, _mod_name);

	bool mod_found_in_line = false;
	ssize_t n;
	/*
	 * Sample lines in modules.dep may look like:
	 *
	 * kernel/arch/x86/crypto/twofish-x86_64.ko.xz: kernel/crypto/twofish_common.ko.xz
	 * [...]
	 * kernel/crypto/twofish_common.ko.xz:
	 *
	 * so we have to match only the first token. If we only use strstr() on
	 * 'line' we would also match the first line if module name was twofish_common
	 */
	while ((n = getline(&line, &len, fp)) != -1) {
		char *_line = mem_strdup(line);
		char *mod_tok = strtok(_line, ":");
		if (strstr(mod_tok, mod_name) || strstr(mod_tok, _mod_name)) {
			mod_found_in_line = true;
			TRACE("found line '%s'", line);
			mem_free(_line);
			break;
		}
		mem_free(_line);
	}

	mem_free0(mod_name);
	mem_free0(_mod_name);

	fclose(fp);

	IF_FALSE_GOTO_ERROR(mod_found_in_line, out);

	/*
	 * A line in modules.dep file looks like:
	 * kernel/net/smc/smc_diag.ko: kernel/net/smc/smc.ko kernel/drivers/infiniband/core/ib_core.ko
	 *
	 * If container config has a module set like this: 'allow_module: "smc-diag"'
	 * this is matched against the constructed '_mode_name = "smc_diag.ko"'
	 *
	 * Thus, now we match the first string by delimiter ": "
	 *	kernel/net/smc/smc_diag.ko: -> first token
	 * afterwards we set the delimiter for tokenizing to " "
	 * 	kernel/net/smc/smc.ko -> second token
	 * 	kernel/drivers/infiniband/core/ib_core.ko -> third token
	 * and append those tokens to the module list
	 */
	char *mod_dep_tok = strtok(line, ": ");
	while (mod_dep_tok) {
		INFO("modules.dep: adding module '%s' to internal matching list!", mod_dep_tok);
		ret_list = list_append(ret_list, mem_strdup(mod_dep_tok));
		mod_dep_tok = strtok(NULL, " ");
	}

out:
	mem_free0(line);
	return ret_list;
}

void
c_seccomp_emulate_finit_module(c_seccomp_t *seccomp, struct seccomp_notif *req,
			       struct seccomp_notif_resp *resp)
{
	int ret_finit_module = -1;
	char *param_values = NULL;
	char *mod_filename = NULL;
	int cml_mod_fd = -1;

	if (!(COMPARTMENT_FLAG_MODULE_LOAD & compartment_get_flags(seccomp->compartment))) {
		DEBUG("Blocking call to SYS_finit_module by PID %d", req->pid);
		goto out;
	}

	DEBUG("Got finit_module from pid %d, fd: %lld, const char params_values *: %p, flags: %lld",
	      req->pid, req->data.args[0], (void *)req->data.args[1], req->data.args[2]);

	int fd_in_target = req->data.args[0];
	int flags = req->data.args[2];

	// Check cap of target pid in its namespace
	if (!c_seccomp_capable(req->pid, CAP_SYS_MODULE)) {
		ERROR("Missing CAP_SYS_MODULE for process %d!", req->pid);
		goto out;
	}

	mod_filename = proc_get_filename_of_fd_new(req->pid, fd_in_target);

	// Check against list of allowed modules
	bool module_allowed = false;
	for (list_t *l = seccomp->module_list; l; l = l->next) {
		char *mod_name = l->data;
		if (strstr(mod_filename, mod_name)) {
			module_allowed = true;
			break;
		}
	}

	if (!module_allowed) {
		ERROR("Check whitelist for '%s' failed!", mod_filename);
		goto out;
	}

	// Validate path for module location
	bool valid_prefix = false;
	const char *valid_path[2] = { "/lib/modules", "/usr/lib/modules" };
	for (int i = 0; i < 2 && valid_prefix == false; ++i) {
		if (0 == strncmp(valid_path[i], mod_filename, strlen(valid_path[i]))) {
			valid_prefix = true;
			break;
		}
	}

	if (!valid_prefix) {
		ERROR("Path validation for '%s' failed! %d!", mod_filename, req->pid);
		goto out;
	}

	// kernel cmdline and modparams are restricted to 1024 chars
	int param_max_len = 1024;
	param_values = mem_alloc0(param_max_len);
	if (!(param_values = (char *)c_seccomp_fetch_vm_new(
		      seccomp, req->pid, (void *)req->data.args[1], param_max_len))) {
		ERROR_ERRNO("Failed to fetch module parameters string");
		goto out;
	}

	/*
	 * unitl we do not have a proper module parameters sanity checking,
	 * we white out parameters, since there may be dangerous ones.
	 */
	param_values = mem_strdup("");

	DEBUG("Executing finit_module on behalf of container using module %s"
	      " with parameters '%s' from CML",
	      mod_filename, param_values);
	cml_mod_fd = open(mod_filename, O_RDONLY);
	if (cml_mod_fd < 0) {
		ERROR_ERRNO("Failed to open module %s in CML", mod_filename);
		goto out;
	}
	/*
	 * for security reasons we strip out flags MODULE_INIT_IGNORE_MODVERSIONS
	 * MODULE_INIT_IGNORE_VERMAGIC which skips sanity checks and only allow
	 * @flag_mask (currently this is MODULE_INIT_COMPRESSED_FILE only)
	 * however to be save on additional introduced module flags, we do not
	 * explicitly mask out the known bad flags like this:
	 *
	 *	flags &= ~(MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC);
	 */
	int flag_mask = MODULE_INIT_COMPRESSED_FILE;
	flags &= flag_mask;

	if (-1 == (ret_finit_module = finit_module(cml_mod_fd, param_values, flags))) {
		audit_log_event(NULL, FSA, CMLD, CONTAINER_ISOLATION, "seccomp-emulation-failed",
				compartment_get_name(seccomp->compartment), 2, "syscall",
				SYS_finit_module);
		ERROR_ERRNO("Failed to execute finit_module");
		goto out;
	}

	DEBUG("finit_module returned %d", ret_finit_module);

	// prepare answer
	resp->id = req->id;
	resp->error = 0;
	resp->val = ret_finit_module;
out:
	if (cml_mod_fd > 0)
		close(cml_mod_fd);
	if (param_values)
		mem_free0(param_values);
	if (mod_filename)
		mem_free0(mod_filename);
}
