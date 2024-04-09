/*
 * This file is part of GyroidOS
 * Copyright(c) 2023 Fraunhofer AISEC
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
 * @file c_cgroup_sockopt.c
 *
 * This submodule provides functionality to setup some inline eBPF cgroup/sockopt
 * programs which are getting loaded and attached on container start.
 */

#define MOD_NAME "c_cgroup_sockopt"

#define _GNU_SOURCE

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"
#include "common/list.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "container.h"
#include "bpf_insn.h"

// cgroup subtree where cmld is running in (provided by c_cgroups_v2.c)
extern char *c_cgroups_subtree;

typedef struct c_cgroups_sockopt_prog {
	struct bpf_insn *insn;
	int insn_n_structs;
	int fd;
	char *name;
} c_cgroups_sockopt_prog_t;

typedef struct c_cgroups_sockopt {
	container_t *container; // weak reference
	char *path;		// path to cgroup of the container

	list_t *bpf_progs; // list of c_cgroups_sockopt_prog_t structurs
} c_cgroups_sockopt_t;

static __u64
ptr_to_u64(void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int
bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(SYS_bpf, cmd, attr, size);
}

static c_cgroups_sockopt_prog_t *
c_cgroups_sockopt_prog_new(const struct bpf_insn *insn, int insn_nr, const char *name)
{
	IF_TRUE_RETVAL(insn == NULL || insn_nr <= 0, NULL);

	c_cgroups_sockopt_prog_t *prog = mem_new0(c_cgroups_sockopt_prog_t, 1);
	prog->insn = mem_new0(struct bpf_insn, insn_nr);
	memcpy(prog->insn, insn, sizeof(struct bpf_insn) * insn_nr);

	prog->insn_n_structs = insn_nr;
	prog->name = mem_printf("cml_%s", name);

	return prog;
}

static void
c_cgroups_sockopt_prog_free(c_cgroups_sockopt_prog_t *prog)
{
	IF_NULL_RETURN(prog);

	if (prog->insn)
		mem_free0(prog->insn);
	if (prog->name)
		mem_free0(prog->name);
	mem_free0(prog);
}

static void
c_cgroups_sockopt_prog_deactivate(c_cgroups_sockopt_t *sockopt)
{
	ASSERT(sockopt);

	int cgroup_fd = open(sockopt->path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);

	for (list_t *l = sockopt->bpf_progs; l; l = l->next) {
		c_cgroups_sockopt_prog_t *prog = l->data;

		union bpf_attr detach_attr = {
			.attach_type = BPF_CGROUP_SETSOCKOPT,
			.target_fd = cgroup_fd,
			.attach_bpf_fd = prog->fd,
		};

		// if cgroup still exist detach the program from it
		if (cgroup_fd > 0 && bpf(BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr)))
			WARN_ERRNO("Failed to detach bpf sock program!");

		close(prog->fd);
		c_cgroups_sockopt_prog_free(prog);
	}

	list_delete(sockopt->bpf_progs);
	sockopt->bpf_progs = NULL;

	close(cgroup_fd);
}

#define BPF_LOG_SIZE 1024 * 1024
#define BPF_PROG_LOAD_RETRIES 10

static int
c_cgroups_sockopt_prog_activate(c_cgroups_sockopt_t *sockopt, c_cgroups_sockopt_prog_t *prog)
{
	ASSERT(sockopt);
	ASSERT(prog);

	int cgroup_fd = -1;

	union bpf_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_CGROUP_SOCKOPT,
		.insns = ptr_to_u64(prog->insn),
		.insn_cnt = prog->insn_n_structs,
		.license = ptr_to_u64("GPL"),
		.expected_attach_type = BPF_CGROUP_SETSOCKOPT,
	};

	strncpy(load_attr.prog_name, prog->name, BPF_OBJ_NAME_LEN - 1);

	INFO("bpf insns: %d, %llx", load_attr.insn_cnt, load_attr.insns);

	prog->fd = bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));

	int retry = 0;
	while (prog->fd < 0 && errno == EAGAIN && retry < BPF_PROG_LOAD_RETRIES) {
		retry++;
		TRACE_ERRNO("Failed to load bpf program retrying (retry %d)!", retry);
		prog->fd = bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	}

	if (prog->fd < 0) {
		WARN_ERRNO("Failed to load bpf program retrying with logbuffer!");
		char *bpf_log = mem_new0(char, BPF_LOG_SIZE);
		load_attr.log_buf = ptr_to_u64(bpf_log);
		load_attr.log_size = BPF_LOG_SIZE;
		load_attr.log_level = 1;
		// try again to get log
		prog->fd = bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
		if (prog->fd < 0) {
			ERROR_ERRNO("Failed to load bpf program '%s'!", bpf_log);
			mem_free0(bpf_log);
			goto error;
		}
		mem_free0(bpf_log);
	}

	cgroup_fd = open(sockopt->path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);

	IF_TRUE_RETVAL(cgroup_fd < 0, -COMPARTMENT_ERROR_CGROUPS);

	union bpf_attr attach_attr = {
		.attach_type = BPF_CGROUP_SETSOCKOPT,
		.target_fd = cgroup_fd,
		.attach_bpf_fd = prog->fd,
		.attach_flags = BPF_F_ALLOW_MULTI,
	};

	int ret = bpf(BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
	if (ret) {
		ERROR_ERRNO("Failed to attach bpf program!");
		goto error;
	}

	sockopt->bpf_progs = list_append(sockopt->bpf_progs, prog);
	close(cgroup_fd);

	return 0;
error:

	close(prog->fd);
	close(cgroup_fd);
	c_cgroups_sockopt_prog_free(prog);
	return -1;
}

static void *
c_cgroups_sockopt_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_cgroups_sockopt_t *sockopt = mem_new0(c_cgroups_sockopt_t, 1);
	sockopt->container = compartment_get_extension_data(compartment);

	sockopt->path = mem_printf("%s/%s", c_cgroups_subtree,
				   uuid_string(container_get_uuid(sockopt->container)));

	return sockopt;
}

static void
c_cgroups_sockopt_free(void *sockoptp)
{
	c_cgroups_sockopt_t *sockopt = sockoptp;
	ASSERT(sockopt);

	mem_free0(sockopt);
}

// kernel example .descr = "setsockopt: allow IP_TOS <= 128",
static c_cgroups_sockopt_prog_t *
c_cgroups_sockopt_allow_ip_tos_128_generate()
{
	const struct bpf_insn insn[] = {
		/* r6 = ctx->optval */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, offsetof(struct bpf_sockopt, optval)),
		/* r7 = ctx->optval + 1 */
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_6),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 1),

		/* r8 = ctx->optval_end */
		BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_1, offsetof(struct bpf_sockopt, optval_end)),

		/* if (ctx->optval + 1 <= ctx->optval_end) { */
		BPF_JMP_REG(BPF_JGT, BPF_REG_7, BPF_REG_8, 4),

		/* r9 = ctx->optval[0] */
		BPF_LDX_MEM(BPF_B, BPF_REG_9, BPF_REG_6, 0),

		/* if (ctx->optval[0] < 128) */
		BPF_JMP_IMM(BPF_JGT, BPF_REG_9, 128, 2),
		BPF_MOV64_IMM(BPF_REG_0, 1),
		BPF_JMP_A(1),
		/* } */

		/* } else { */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* } */

		BPF_EXIT_INSN(),
	};

	int total_insn_nr = (sizeof(insn) / sizeof(struct bpf_insn));

	DEBUG("Generated BPF prog with total_insn_nr ='%d'", total_insn_nr);

	c_cgroups_sockopt_prog_t *prog = c_cgroups_sockopt_prog_new(insn, total_insn_nr, "tos_128");

	return prog;
}

static int
c_cgroups_sockopt_start_post_clone(void *sockoptp)
{
	c_cgroups_sockopt_t *sockopt = sockoptp;
	ASSERT(sockopt);

	/* activate actual bpf programs */
	c_cgroups_sockopt_prog_t *prog = c_cgroups_sockopt_allow_ip_tos_128_generate();
	IF_NULL_RETVAL(prog, -COMPARTMENT_ERROR_CGROUPS);

	IF_TRUE_RETVAL(-1 == c_cgroups_sockopt_prog_activate(sockopt, prog),
		       -COMPARTMENT_ERROR_CGROUPS);

	return 0;
}

static void
c_cgroups_sockopt_cleanup(void *sockoptp, UNUSED bool is_rebooting)
{
	c_cgroups_sockopt_t *sockopt = sockoptp;
	ASSERT(sockopt);

	/* detach and cleanup bpf prog */
	if (sockopt->bpf_progs)
		c_cgroups_sockopt_prog_deactivate(sockopt);
}

static compartment_module_t c_cgroups_sockopt_module = {
	.name = MOD_NAME,
	.compartment_new = c_cgroups_sockopt_new,
	.compartment_free = c_cgroups_sockopt_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = c_cgroups_sockopt_start_post_clone,
	.start_pre_exec = NULL,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child_early = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_cgroups_sockopt_cleanup,
	.join_ns = NULL,
};

static void INIT
c_cgroups_sockopt_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_cgroups_sockopt_module);
}
