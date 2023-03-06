/*
 * This file is part of GyroidOS
 * Copyright(c) 2022 Fraunhofer AISEC
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
 * @file c_cgroups_dev.c
 *
 * This submodule provides functionality to setup the device contrller of
 * v2 control groups to restirct access to block/char devices in containers.
 * This includes the generation of the corresponding eBPF program.
 */

#define MOD_NAME "c_cgroups_dev"

#define _GNU_SOURCE

#include "common/mem.h"
#include "common/macro.h"
#include "common/file.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "container.h"
#include "hardware.h"
#include "bpf_insn.h"

// cgroup subtree where cmld is running in (provided by c_cgroups_v2.c)
extern char *c_cgroups_subtree;

#define LEGACY_DEVCG_ACC_ALL (BPF_DEVCG_ACC_READ | BPF_DEVCG_ACC_WRITE | BPF_DEVCG_ACC_MKNOD)
#define LEGACY_DEVCG_DEV_ALL (BPF_DEVCG_DEV_BLOCK | BPF_DEVCG_DEV_CHAR)

typedef struct c_cgroups_dev_item {
	int major, minor;
	short type;
	short access;
} c_cgroups_dev_item_t;

typedef struct c_cgroups_bpf_prog {
	struct bpf_insn *insn;
	int insn_n_structs;
	int fd;
} c_cgroups_bpf_prog_t;

typedef struct c_cgroups_dev {
	container_t *container; // weak reference
	char *path;		// path to cgroup of the container

	list_t *assigned_devs; /* list of 2 element int arrays, representing maj:min of exclusively assigned devices.
				  wildcard '*' is mapped to -1 */
	list_t *allowed_devs; /* list of 2 element int arrays, representing maj:min of devices allowed to be accessed.
				  wildcard '*' is mapped to -1 */

	c_cgroups_bpf_prog_t *bpf_prog; // generated bpf prog from allowed_devs list
} c_cgroups_dev_t;

/* List of of devices (c_cgroups_dev_item_t) allowed to be used in the running containers.
 * list_t *global_allowed_devs_list = NULL;
 */
list_t *global_allowed_devs_list = NULL;

/* List of of devices (c_cgroups_dev_item_t) exclusivly assigned to the running
 * containers.
 */
list_t *global_assigned_devs_list = NULL;

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

/**
 * Generic whitelist of devices to be available for all containers independent
 * from hardware and container configuration
 */
static const char *c_cgroups_dev_generic_whitelist[] = {
	/*************/
	/* Character */

	/* Memory Devices */
	//"c 1:1 rwm", // physical mem
	//"c 1:2 rwm", // kmem
	"c 1:3 rwm", // null
	"c 1:5 rwm", // zero
	"c 1:7 rwm", // full
	"c 1:8 rwm", // random
	"c 1:9 rwm", // urandom
	//"c 1:11 rwm", // kmsg

	/* TTY */
	//"c 2:* rwm", // BSD pseudo-tty masters (deprecated)
	//"c 3:* rwm", // BSD pseudo-tty slaves  (deprecated)

	//"c 4:0 rwm", // tty0

	/* alternate tty devices - seem to be necessary for android logwrapper */
	//"c 5:0 rwm", // tty
	//"c 5:1 rwm", // console
	"c 5:2 rwm", // ptmx

	//"c 7:* rwm", // Virtual console capture devices

	/* Misc */
	"c 10:183 rwm", // hw_random
	"c 10:200 rwm", // tun (for VPN inside containers)
	"c 10:229 rwm", // fuse
	//"c 10:236 rwm", // mapper/control
	//"c 10:237 rwm", // loop-control

	/* Input Core */
	//"c 13:* rwm",

	/* Universal frame buffer */
	//"c 29:* rwm",

	/* camera v4l */
	//"c 81:* rwm", // video*, v4l-subdev*

	/* i2c */
	//"c 89:* rwm",

	/* ppp */
	//"c 108:* rwm",

	/* Unix98 PTY Slaves (majors 136-143) */
	"c 136:* rwm", // e.g. used for ssh sessions

	/* USB */
	//"c 180:* rwm", // USB
	//"c 188:* rwm", // USB serial converters
	//"c 189:* rwm", // USB serial converters - alternate devices

	/*************/
	/* Block     */
	//"b 1:* rwm", // ramdisks
	//"b 7:* rwm", // loopback devs
	//"b 253:* rwm", // ZRAM
	//"b 254:* rwm", // device-mapper

	NULL
};

/* parses major and minor device numbers from a rule (v1 style) to an
 * c_cgroups_dev_item_t */
static c_cgroups_dev_item_t *
c_cgroups_dev_from_rule_new(const char *rule)
{
	c_cgroups_dev_item_t *dev_item = mem_new0(c_cgroups_dev_item_t, 1);

	// strtok manipulates string thus use a copy here;
	char *rule_cp = mem_strdup(rule);
	char *pointer;

	char *type = strtok_r(rule_cp, " ", &pointer);
	IF_NULL_GOTO_TRACE(type, error);

	switch (type[0]) {
	case 'c':
		dev_item->type = BPF_DEVCG_DEV_CHAR;
		break;
	case 'b':
		dev_item->type = BPF_DEVCG_DEV_BLOCK;
		break;
	case 'a':
		dev_item->type = 0;
		break;
	default:
		ERROR("Could not parse dev type!");
		goto error;
	}

	char *dev = strtok_r(NULL, " ", &pointer);
	IF_NULL_GOTO_TRACE(dev, error);

	pointer = NULL;

	char *maj_str = strtok_r(dev, ":", &pointer);
	IF_NULL_GOTO_TRACE(maj_str, error);

	// default wildcard
	dev_item->major = -1;
	if (strncmp("*", maj_str, 1)) {
		errno = 0;
		long int parsed_int = strtol(maj_str, NULL, 10);
		IF_TRUE_GOTO_TRACE(errno == ERANGE, error);
		IF_TRUE_GOTO_TRACE(parsed_int < INT_MIN, error);
		IF_TRUE_GOTO_TRACE(parsed_int > INT_MAX, error);
		dev_item->major = (int)parsed_int;
	}

	char *min_str = strtok_r(NULL, " ", &pointer);
	IF_NULL_GOTO_TRACE(min_str, error);

	// default wildcard
	dev_item->minor = -1;
	if (strncmp("*", min_str, 1)) {
		errno = 0;
		long int parsed_int = strtol(min_str, NULL, 10);
		IF_TRUE_GOTO_TRACE(errno == ERANGE, error);
		IF_TRUE_GOTO_TRACE(parsed_int < INT_MIN, error);
		IF_TRUE_GOTO_TRACE(parsed_int > INT_MAX, error);
		dev_item->minor = (int)parsed_int;
	}

	char *access = strtok_r(NULL, ":", &pointer);
	if (!access) {
		dev_item->access = LEGACY_DEVCG_ACC_ALL;
	} else {
		IF_TRUE_GOTO_TRACE((strlen(access) > 3) || (strlen(access) == 0), error);

		for (size_t i = 0; i < strlen(access); ++i) {
			switch (access[i]) {
			case 'r':
				dev_item->access |= BPF_DEVCG_ACC_READ;
				break;
			case 'w':
				dev_item->access |= BPF_DEVCG_ACC_WRITE;
				break;
			case 'm':
				dev_item->access |= BPF_DEVCG_ACC_MKNOD;
				break;
			default:
				goto error;
			}
		}
	}

	mem_free0(rule_cp);
	return dev_item;

error:
	mem_free0(rule_cp);
	mem_free(dev_item);
	return NULL;
}

static void
c_cgroups_dev_item_free(c_cgroups_dev_item_t *dev_item)
{
	mem_free0(dev_item);
}

static c_cgroups_bpf_prog_t *
c_cgroups_dev_bpf_prog_append(c_cgroups_bpf_prog_t *prog, const struct bpf_insn *insn,
			      int insn_n_structs)
{
	if (prog == NULL) {
		prog = mem_new0(c_cgroups_bpf_prog_t, 1);
		prog->insn = mem_new0(struct bpf_insn, insn_n_structs);
		prog->insn_n_structs = 0;
	} else {
		prog->insn = mem_renew(struct bpf_insn, prog->insn,
				       prog->insn_n_structs + insn_n_structs);
	}
	memcpy(prog->insn + prog->insn_n_structs, insn, insn_n_structs * sizeof(struct bpf_insn));
	prog->insn_n_structs += insn_n_structs;
	return prog;
}

static void
c_cgroups_dev_bpf_prog_free(c_cgroups_bpf_prog_t *prog)
{
	if (prog->insn)
		mem_free0(prog->insn);
	mem_free0(prog);
}

#define INSNR_TYPE(di) ((di->type > 0) ? 1 : 0)
#define INSNR_MAJOR(di) ((di->major >= 0) ? 1 : 0)
#define INSNR_MINOR(di) ((di->minor >= 0) ? 1 : 0)
#define INSNR_ACCESS(di) ((di->access != LEGACY_DEVCG_ACC_ALL) ? 3 : 0)

/*
 * inspired by implementations of lxc, procd and systemd
 */
static c_cgroups_bpf_prog_t *
c_cgroups_dev_bpf_prog_generate(list_t *dev_items)
{
	const struct bpf_insn pre_insn[] = {
		// load type to R2
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 0),
		BPF_ALU32_IMM(BPF_AND, BPF_REG_2, 0xFFFF),

		// load access to > R3
		BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 0),
		BPF_ALU32_IMM(BPF_RSH, BPF_REG_3, 16),

		// load major to R4
		BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 4),

		// load iminor to R5
		BPF_LDX_MEM(BPF_W, BPF_REG_5, BPF_REG_1, 8),
	};

	int total_insn_nr = (sizeof(pre_insn) / sizeof(struct bpf_insn));
	c_cgroups_bpf_prog_t *prog = c_cgroups_dev_bpf_prog_append(NULL, pre_insn, total_insn_nr);

	for (list_t *l = dev_items; l; l = l->next) {
		c_cgroups_dev_item_t *dev_item = l->data;
		// instructions for one rule including 2 byte for 'allow' end closing instruction
		total_insn_nr += INSNR_TYPE(dev_item) + INSNR_ACCESS(dev_item) +
				 INSNR_MAJOR(dev_item) + INSNR_MINOR(dev_item) + 2;
	}

	// instructions for deny all as default behavior
	total_insn_nr += 2;

	DEBUG("Generate BPF prog with total_insn_nr ='%d'", total_insn_nr);

	for (list_t *l = dev_items; l; l = l->next) {
		c_cgroups_dev_item_t *dev_item = l->data;
		int next_ins = 1 + INSNR_TYPE(dev_item) + INSNR_ACCESS(dev_item) +
			       INSNR_MAJOR(dev_item) + INSNR_MINOR(dev_item);

		if (dev_item->type > 0) {
			struct bpf_insn insn[] = {
				// compare type (char/block)
				BPF_JMP_IMM(BPF_JNE, BPF_REG_2, dev_item->type, next_ins),
			};
			c_cgroups_dev_bpf_prog_append(prog, insn, 1);
			next_ins--;
		}

		if (dev_item->access != LEGACY_DEVCG_ACC_ALL) {
			struct bpf_insn insn[] = {
				BPF_MOV32_REG(BPF_REG_1, BPF_REG_3),
				BPF_ALU32_IMM(BPF_AND, BPF_REG_1, dev_item->access),
				// compare access (rwm)
				BPF_JMP_REG(BPF_JNE, BPF_REG_1, BPF_REG_3, next_ins - 2),
			};
			c_cgroups_dev_bpf_prog_append(prog, insn, 3);
			next_ins -= 3;
		}

		if (dev_item->major >= 0) {
			struct bpf_insn insn[] = {
				// compare major
				BPF_JMP_IMM(BPF_JNE, BPF_REG_4, dev_item->major, next_ins),
			};
			c_cgroups_dev_bpf_prog_append(prog, insn, 1);
			next_ins--;
		}

		if (dev_item->minor >= 0) {
			struct bpf_insn insn[] = {
				// compare minor
				BPF_JMP_IMM(BPF_JNE, BPF_REG_5, dev_item->minor, next_ins),
			};
			c_cgroups_dev_bpf_prog_append(prog, insn, 1);
			next_ins--;
		}

		struct bpf_insn allow_insn[] = {
			// set allow and exit
			BPF_MOV64_IMM(BPF_REG_0, 1),
			BPF_EXIT_INSN(),
		};
		c_cgroups_dev_bpf_prog_append(prog, allow_insn, 2);
	}
	struct bpf_insn deny_insn[] = {
		// set deny for everything else and exit
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_EXIT_INSN(),
	};
	c_cgroups_dev_bpf_prog_append(prog, deny_insn, 2);

	return prog;
}

static void
c_cgroups_dev_bpf_prog_deactivate(c_cgroups_dev_t *cgroups_dev)
{
	ASSERT(cgroups_dev);

	int cgroup_fd = open(cgroups_dev->path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);

	union bpf_attr detach_attr = {
		.attach_type = BPF_CGROUP_DEVICE,
		.target_fd = cgroup_fd,
		.attach_bpf_fd = cgroups_dev->bpf_prog->fd,
	};

	if (bpf(BPF_PROG_DETACH, &detach_attr, sizeof(detach_attr)))
		WARN_ERRNO("Failed to detach bpf program!");

	c_cgroups_dev_bpf_prog_free(cgroups_dev->bpf_prog);
}

#define BPF_LOG_SIZE 8 * 1024

static int
c_cgroups_dev_bpf_prog_activate(c_cgroups_dev_t *cgroups_dev, c_cgroups_bpf_prog_t *prog)
{
	ASSERT(cgroups_dev);
	ASSERT(prog);

	int cgroup_fd = -1;

	union bpf_attr load_attr = {
		.prog_type = BPF_PROG_TYPE_CGROUP_DEVICE,
		.insns = ptr_to_u64(prog->insn),
		.insn_cnt = prog->insn_n_structs,
		.license = ptr_to_u64("GPL"),
	};

	prog->fd = bpf(BPF_PROG_LOAD, &load_attr, sizeof(load_attr));
	if (prog->fd < 0) {
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

	cgroup_fd = open(cgroups_dev->path, O_DIRECTORY | O_RDONLY | O_CLOEXEC);

	IF_TRUE_RETVAL(cgroup_fd < 0, -COMPARTMENT_ERROR_CGROUPS);

	union bpf_attr attach_attr = {
		.attach_type = BPF_CGROUP_DEVICE,
		.target_fd = cgroup_fd,
		.attach_bpf_fd = prog->fd,
		.attach_flags = BPF_F_ALLOW_MULTI,
	};

	int ret = bpf(BPF_PROG_ATTACH, &attach_attr, sizeof(attach_attr));
	if (ret) {
		ERROR_ERRNO("Failed to attach bpf program!");
		goto error;
	}

	// if successfully attached, we can now savely detach the old program
	if (cgroups_dev->bpf_prog)
		c_cgroups_dev_bpf_prog_deactivate(cgroups_dev);

	cgroups_dev->bpf_prog = prog;

	return 0;
error:

	close(prog->fd);
	close(cgroup_fd);
	c_cgroups_dev_bpf_prog_free(prog);
	return -1;
}

static c_cgroups_dev_item_t *
c_cgroups_dev_list_match(const list_t *list, const c_cgroups_dev_item_t *dev_item)
{
	for (const list_t *l = list; l; l = l->next) {
		c_cgroups_dev_item_t *dev_elem = l->data;
		if ((dev_elem->major == -1) || (dev_item->major == -1))
			return dev_elem;
		if (dev_elem->major != dev_item->major)
			continue;
		if ((dev_item->minor == -1) || (dev_elem->minor == -1) ||
		    (dev_item->minor == dev_elem->minor))
			return dev_elem;
	}
	return NULL;
}

static void
c_cgroups_dev_list_add(list_t **list, const c_cgroups_dev_item_t *dev_item)
{
	c_cgroups_dev_item_t *dev_copy = mem_new0(c_cgroups_dev_item_t, 1);
	memcpy(dev_copy, dev_item, sizeof(c_cgroups_dev_item_t));
	*list = list_append(*list, dev_copy);
}

static void
c_cgroups_dev_list_remove(list_t **list, const c_cgroups_dev_item_t *dev_item)
{
	for (list_t *l = *list; l; l = l->next) {
		c_cgroups_dev_item_t *dev_elem = l->data;
		if ((dev_elem->major == dev_item->major) && (dev_elem->minor == dev_item->minor)) {
			c_cgroups_dev_item_free(dev_elem);
			*list = list_unlink(*list, l);
			break;
		}
	}
}

static void
c_cgroups_dev_add_allowed(c_cgroups_dev_t *cgroups_dev, const c_cgroups_dev_item_t *dev_item)
{
	c_cgroups_dev_list_add(&global_allowed_devs_list, dev_item);

	// only add items once to container internal list
	if (c_cgroups_dev_list_match(cgroups_dev->allowed_devs, dev_item))
		return;

	c_cgroups_dev_list_add(&cgroups_dev->allowed_devs, dev_item);
}

static void
c_cgroups_dev_add_assigned(c_cgroups_dev_t *cgroups_dev, const c_cgroups_dev_item_t *dev_item)
{
	c_cgroups_dev_list_add(&global_assigned_devs_list, dev_item);

	// only add items once to container internal list
	if (c_cgroups_dev_list_match(cgroups_dev->assigned_devs, dev_item))
		return;

	c_cgroups_dev_list_add(&cgroups_dev->assigned_devs, dev_item);
}

static int
c_cgroups_dev_allow(void *cgroups_devp, const char *rule)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);
	ASSERT(rule);

	c_cgroups_dev_item_t *dev_item = c_cgroups_dev_from_rule_new(rule);
	if (c_cgroups_dev_list_match(global_assigned_devs_list, dev_item)) {
		WARN("Unable to allow rule %s: device busy (already assigned to another container)",
		     rule);
		mem_free0(dev_item);
		return 0;
	}

	c_cgroups_dev_add_allowed(cgroups_dev, dev_item);
	mem_free0(dev_item);

	// regenerate bpf prog and update for running containers only
	compartment_state_t state = container_get_state(cgroups_dev->container);
	if (state != COMPARTMENT_STATE_BOOTING && state != COMPARTMENT_STATE_RUNNING)
		return 0;

	c_cgroups_bpf_prog_t *prog = c_cgroups_dev_bpf_prog_generate(cgroups_dev->allowed_devs);
	IF_NULL_RETVAL(prog, -1);

	return c_cgroups_dev_bpf_prog_activate(cgroups_dev, prog);
}

static int
c_cgroups_dev_assign(void *cgroups_devp, const char *rule)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);
	ASSERT(rule);

	c_cgroups_dev_item_t *dev_item = c_cgroups_dev_from_rule_new(rule);
	if (c_cgroups_dev_list_match(global_allowed_devs_list, dev_item)) {
		ERROR("Unable to exclusively assign device according to rule %s: device busy (already available to another container)",
		      rule);
		mem_free0(dev_item);
		return -1;
	}

	c_cgroups_dev_add_allowed(cgroups_dev, dev_item);
	c_cgroups_dev_add_assigned(cgroups_dev, dev_item);
	mem_free0(dev_item);

	// regenerate bpf prog and update for running containers only
	compartment_state_t state = container_get_state(cgroups_dev->container);
	if (state != COMPARTMENT_STATE_BOOTING && state != COMPARTMENT_STATE_RUNNING)
		return 0;

	c_cgroups_bpf_prog_t *prog = c_cgroups_dev_bpf_prog_generate(cgroups_dev->allowed_devs);
	IF_NULL_RETVAL(prog, -1);

	return c_cgroups_dev_bpf_prog_activate(cgroups_dev, prog);
}

static int
c_cgroups_dev_deny(void *cgroups_devp, const char *rule)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);
	ASSERT(rule);

	c_cgroups_dev_item_t *dev_item = c_cgroups_dev_from_rule_new(rule);
	c_cgroups_dev_item_t *matched_dev;

	// an entry for an allowed device should only be present once in the list
	if ((matched_dev = c_cgroups_dev_list_match(cgroups_dev->allowed_devs, dev_item)) == NULL) {
		// nothing to be done device not allowed anyway
		mem_free0(dev_item);
		return 0;
	}

	cgroups_dev->allowed_devs = list_remove(cgroups_dev->allowed_devs, matched_dev);

	// an entry for an assigned device should only be present once in the list
	if ((matched_dev = c_cgroups_dev_list_match(cgroups_dev->assigned_devs, dev_item)) !=
	    NULL) {
		cgroups_dev->assigned_devs = list_remove(cgroups_dev->assigned_devs, matched_dev);
	}

	mem_free0(dev_item);

	// regenerate bpf prog and update for running containers only
	compartment_state_t state = container_get_state(cgroups_dev->container);
	if (state != COMPARTMENT_STATE_BOOTING && state != COMPARTMENT_STATE_RUNNING)
		return 0;

	c_cgroups_bpf_prog_t *prog = c_cgroups_dev_bpf_prog_generate(cgroups_dev->allowed_devs);
	IF_NULL_RETVAL(prog, -1);

	return c_cgroups_dev_bpf_prog_activate(cgroups_dev, prog);
}

static int
c_cgroups_dev_allow_list(void *cgroups_devp, const char **list)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	/* if the list is null, do nothing */
	if (!list)
		return 0;

	/* iterate over list and allow entries */
	for (int i = 0; list[i]; i++) {
		if (c_cgroups_dev_allow(cgroups_dev, list[i]) < 0) {
			return -1;
		}
	}
	return 0;
}

static int
c_cgroups_dev_assign_list(c_cgroups_dev_t *cgroups_dev, const char **list)
{
	if (!list)
		return 0;

	for (int i = 0; list[i]; i++) {
		if (c_cgroups_dev_assign(cgroups_dev, list[i]) < 0) {
			return -1;
		}
	}
	return 0;
}

static void *
c_cgroups_dev_new(compartment_t *compartment)
{
	ASSERT(compartment);
	IF_NULL_RETVAL(compartment_get_extension_data(compartment), NULL);

	c_cgroups_dev_t *cgroups_dev = mem_new0(c_cgroups_dev_t, 1);
	cgroups_dev->container = compartment_get_extension_data(compartment);

	cgroups_dev->path = mem_printf("%s/%s", c_cgroups_subtree,
				       uuid_string(container_get_uuid(cgroups_dev->container)));

	cgroups_dev->assigned_devs = NULL;
	cgroups_dev->allowed_devs = NULL;

	return cgroups_dev;
}

static void
c_cgroups_dev_free(void *cgroups_devp)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	mem_free0(cgroups_dev);
}

static int
c_cgroups_dev_start_post_clone(void *cgroups_devp)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	/* allow generic base whitelist */
	if (c_cgroups_dev_allow_list(cgroups_dev, c_cgroups_dev_generic_whitelist) < 0) {
		ERROR("Could not initialize generic devices whitelist for container %s",
		      container_get_description(cgroups_dev->container));
		return -COMPARTMENT_ERROR_CGROUPS;
	}

	/* allow hardware specific base whitelist */
	if (c_cgroups_dev_allow_list(cgroups_dev, hardware_get_devices_whitelist_base()) < 0) {
		ERROR("Could not initialize hardware specific base devices whitelist for container %s",
		      container_get_description(cgroups_dev->container));
		return -COMPARTMENT_ERROR_CGROUPS;
	}

	if (container_is_privileged(cgroups_dev->container)) {
		/* allow hardware specific whitelist for privileged containers */
		if (c_cgroups_dev_allow_list(cgroups_dev, hardware_get_devices_whitelist_priv()) <
		    0) {
			ERROR("Could not initialize hardware specific privileged devices whitelist for container %s",
			      container_get_description(cgroups_dev->container));
			return -COMPARTMENT_ERROR_CGROUPS;
		}
	}

	/* allow to run a KVM VMM inside an unprivileged Namespace */
	if (container_get_type(cgroups_dev->container) == COMPARTMENT_TYPE_KVM) {
		if (c_cgroups_dev_allow(cgroups_dev, "c 10:232 rwm") < 0)
			return -COMPARTMENT_ERROR_CGROUPS;
		INFO("Allowing acces to /dev/kvm for lkvm inside new namespace");
	}

	/* allow container specific device whitelist */
	const char **container_dev_whitelist = container_get_dev_allow_list(cgroups_dev->container);
	if (c_cgroups_dev_allow_list(cgroups_dev, container_dev_whitelist) < 0) {
		ERROR("Could not initialize container specific device whitelist for container %s",
		      container_get_description(cgroups_dev->container));
		return -COMPARTMENT_ERROR_CGROUPS;
	}
	DEBUG("Applied containers whitelist");

	/* apply container specific exclusive device assignment */
	const char **container_dev_assignlist =
		container_get_dev_assign_list(cgroups_dev->container);
	if (c_cgroups_dev_assign_list(cgroups_dev, container_dev_assignlist) < 0) {
		ERROR("Could not initialize container specific device assignmet list for container %s",
		      container_get_description(cgroups_dev->container));
		return -COMPARTMENT_ERROR_CGROUPS;
	}
	DEBUG("Applied containers assign list");

	for (list_t *l = cgroups_dev->allowed_devs; l; l = l->next) {
		c_cgroups_dev_item_t *dl = l->data;
		DEBUG("device allowed: %c %d:%d %s%s%s",
		      (dl->type == BPF_DEVCG_DEV_CHAR) ? 'c' : 'b', dl->major, dl->minor,
		      (dl->access & BPF_DEVCG_ACC_READ) ? "r" : "",
		      (dl->access & BPF_DEVCG_ACC_WRITE) ? "w" : "",
		      (dl->access & BPF_DEVCG_ACC_MKNOD) ? "m" : "");
	}

	return 0;
}

static int
c_cgroups_dev_start_pre_exec(void *cgroups_devp)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	c_cgroups_bpf_prog_t *prog = c_cgroups_dev_bpf_prog_generate(cgroups_dev->allowed_devs);
	IF_NULL_RETVAL(prog, -COMPARTMENT_ERROR_CGROUPS);

	IF_TRUE_RETVAL(-1 == c_cgroups_dev_bpf_prog_activate(cgroups_dev, prog),
		       -COMPARTMENT_ERROR_CGROUPS);

	return 0;
}

static void
c_cgroups_dev_cleanup(void *cgroups_devp, UNUSED bool is_rebooting)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	/* detach and cleanup bpf prog */
	if (cgroups_dev->bpf_prog)
		c_cgroups_dev_bpf_prog_deactivate(cgroups_dev);

	cgroups_dev->bpf_prog = NULL;

	/* free assigned devices */
	for (list_t *elem = cgroups_dev->assigned_devs; elem != NULL; elem = elem->next) {
		c_cgroups_dev_item_t *dev_elem = elem->data;
		c_cgroups_dev_list_remove(&global_assigned_devs_list, dev_elem);
	}
	list_delete(cgroups_dev->assigned_devs);
	cgroups_dev->assigned_devs = NULL;

	/* free allowed devices */
	for (list_t *elem = cgroups_dev->allowed_devs; elem != NULL; elem = elem->next) {
		c_cgroups_dev_item_t *dev_elem = elem->data;
		c_cgroups_dev_list_remove(&global_allowed_devs_list, dev_elem);
	}
	list_delete(cgroups_dev->allowed_devs);
	cgroups_dev->allowed_devs = NULL;

	for (list_t *l = cgroups_dev->allowed_devs; l; l = l->next) {
		c_cgroups_dev_item_t *dev_item = l->data;
		c_cgroups_dev_item_free(dev_item);
	}
	list_delete(cgroups_dev->allowed_devs);
}

static bool
c_cgroups_dev_is_dev_allowed(void *cgroups_devp, char type, int major, int minor)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	short type_bpf;
	switch (type) {
	case 'b':
		type_bpf = BPF_DEVCG_DEV_BLOCK;
		break;
	case 'c':
		type_bpf = BPF_DEVCG_DEV_CHAR;
		break;
	default:
		type_bpf = 0;
	}
	IF_TRUE_RETVAL(type_bpf == 0, false);
	IF_TRUE_RETVAL_TRACE(major < 0 || minor < 0, false);

	for (list_t *l = cgroups_dev->allowed_devs; l; l = l->next) {
		c_cgroups_dev_item_t *dev_item = l->data;
		if (dev_item->type != type_bpf)
			continue;
		if (dev_item->major == major &&
		    ((dev_item->minor == minor) || dev_item->minor == -1))
			return true;
	}

	return false;
}

static int
c_cgroups_dev_device_allow(void *cgroups_devp, char type, int major, int minor, bool assign)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	int ret;

	IF_TRUE_RETVAL((type != 'c') && (type != 'b'), -1);

	char *rule = mem_printf("%c %d:%d rwm", type, major, minor);
	if (assign)
		ret = c_cgroups_dev_assign(cgroups_dev, rule);
	else
		ret = c_cgroups_dev_allow(cgroups_dev, rule);

	mem_free0(rule);
	return ret;
}

static int
c_cgroups_dev_device_deny(void *cgroups_devp, char type, int major, int minor)
{
	c_cgroups_dev_t *cgroups_dev = cgroups_devp;
	ASSERT(cgroups_dev);

	int ret;

	IF_TRUE_RETVAL((type != 'c') && (type != 'b'), -1);

	char *rule = mem_printf("%c %d:%d rwm", type, major, minor);
	ret = c_cgroups_dev_deny(cgroups_dev, rule);

	mem_free0(rule);
	return ret;
}

static compartment_module_t c_cgroups_dev_module = {
	.name = MOD_NAME,
	.compartment_new = c_cgroups_dev_new,
	.compartment_free = c_cgroups_dev_free,
	.compartment_destroy = NULL,
	.start_post_clone_early = NULL,
	.start_child_early = NULL,
	.start_pre_clone = NULL,
	.start_post_clone = c_cgroups_dev_start_post_clone,
	.start_pre_exec = c_cgroups_dev_start_pre_exec,
	.start_post_exec = NULL,
	.start_child = NULL,
	.start_pre_exec_child = NULL,
	.stop = NULL,
	.cleanup = c_cgroups_dev_cleanup,
	.join_ns = NULL,
};

static void INIT
c_cgroups_dev_init(void)
{
	// register this module in compartment.c
	compartment_register_module(&c_cgroups_dev_module);

	// register relevant handlers implemented by this module
	container_register_device_allow_handler(MOD_NAME, c_cgroups_dev_device_allow);
	container_register_device_deny_handler(MOD_NAME, c_cgroups_dev_device_deny);
	container_register_is_device_allowed_handler(MOD_NAME, c_cgroups_dev_is_dev_allowed);
}
