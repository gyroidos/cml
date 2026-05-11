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

#ifndef MOUNT_IDMAPPED_H
#define MOUNT_IDMAPPED_H

#include <fcntl.h>
#include <linux/types.h>
#include <stdint.h>
#include <sys/mount.h>
#include <unistd.h>

/**************************/
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY 0x00000001
#endif

#ifndef MOUNT_ATTR_NOSUID
#define MOUNT_ATTR_NOSUID 0x00000002
#endif

#ifndef MOUNT_ATTR_NOEXEC
#define MOUNT_ATTR_NOEXEC 0x00000008
#endif

#ifndef MOUNT_ATTR_NODIRATIME
#define MOUNT_ATTR_NODIRATIME 0x00000080
#endif

#ifndef MOUNT_ATTR__ATIME
#define MOUNT_ATTR__ATIME 0x00000070
#endif

#ifndef MOUNT_ATTR_RELATIME
#define MOUNT_ATTR_RELATIME 0x00000000
#endif

#ifndef MOUNT_ATTR_NOATIME
#define MOUNT_ATTR_NOATIME 0x00000010
#endif

#ifndef MOUNT_ATTR_STRICTATIME
#define MOUNT_ATTR_STRICTATIME 0x00000020
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};
#endif

#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif

// clang-format off
#ifndef __NR_mount_setattr
	#if defined __alpha__
		#define __NR_mount_setattr 552
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_mount_setattr (442 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_mount_setattr (442 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_mount_setattr (442 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_mount_setattr (442 + 1024)
	#else
		#define __NR_mount_setattr 442
	#endif
// clang-format on
#endif

#ifndef OPEN_TREE_CLONE
#define OPEN_TREE_CLONE 1
#endif

#ifndef OPEN_TREE_CLOEXEC
#define OPEN_TREE_CLOEXEC O_CLOEXEC
#endif

// clang-format off
#ifndef __NR_open_tree
	#if defined __alpha__
		#define __NR_open_tree 538
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_open_tree 4428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_open_tree 6428
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_open_tree 5428
		#endif
	#elif defined __ia64__
		#define __NR_open_tree (428 + 1024)
	#else
		#define __NR_open_tree 428
	#endif
#endif
// clang-format on

#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS 0x00000001
#endif

#ifndef MOVE_MOUNT_F_AUTOMOUNTS
#define MOVE_MOUNT_F_AUTOMOUNTS 0x00000002
#endif

#ifndef MOVE_MOUNT_F_EMPTY_PATH
#define MOVE_MOUNT_F_EMPTY_PATH 0x00000004
#endif

#ifndef MOVE_MOUNT_T_SYMLINKS
#define MOVE_MOUNT_T_SYMLINKS 0x00000010
#endif

#ifndef MOVE_MOUNT_T_AUTOMOUNTS
#define MOVE_MOUNT_T_AUTOMOUNTS 0x00000020
#endif

#ifndef MOVE_MOUNT_T_EMPTY_PATH
#define MOVE_MOUNT_T_EMPTY_PATH 0x00000040
#endif

#ifndef MOVE_MOUNT__MASK
#define MOVE_MOUNT__MASK 0x00000077
#endif

// clang-format off
#ifndef __NR_move_mount
	#if defined __alpha__
		#define __NR_move_mount 539
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32
			#define __NR_move_mount 4429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32
			#define __NR_move_mount 6429
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64
			#define __NR_move_mount 5429
		#endif
	#elif defined __ia64__
		#define __NR_move_mount (428 + 1024)
	#else
		#define __NR_move_mount 429
	#endif
#endif
// clang-format on

int
mount_setattr(int dirfd, const char *path, unsigned int flags, struct mount_attr *attr,
	      size_t size);

int
open_tree(int dirfd, const char *path, unsigned int flags);

int
move_mount(int from_dirfd, const char *from_path, int to_dirfd, const char *to_path,
	   unsigned int flags);

#endif /* MOUNT_IDMAPPED_H */
