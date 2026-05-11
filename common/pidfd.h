/*
 * This file is part of GyroidOS
 * Copyright(c) 2025 Fraunhofer AISEC
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
 * @file pidfd.h
 * This module provides wrappers for pidfd related syscalls
 */

#ifndef PIDFD_H
#define PIDFD_H

#include <sys/syscall.h>
#include <unistd.h>

// clang-format off
#ifndef __NR_pidfd_open
	#if defined __alpha__
		#define __NR_pidfd_open 544
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_pidfd_open (434 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_pidfd_open (434 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_pidfd_open (434 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_pidfd_open (434 + 1024)
	#else
		#define __NR_pidfd_open 434
	#endif
#endif
#ifndef __NR_pidfd_getfd
	#if defined __alpha__
		#define __NR_pidfd_getfd 548
	#elif defined _MIPS_SIM
		#if _MIPS_SIM == _MIPS_SIM_ABI32        /* o32 */
			#define __NR_pidfd_getfd (438 + 4000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_NABI32       /* n32 */
			#define __NR_pidfd_getfd (438 + 6000)
		#endif
		#if _MIPS_SIM == _MIPS_SIM_ABI64        /* n64 */
			#define __NR_pidfd_getfd (438 + 5000)
		#endif
	#elif defined __ia64__
		#define __NR_pidfd_getfd (438 + 1024)
	#else
		#define __NR_pidfd_getfd 438
	#endif
#endif
// clang-format on

inline int
pidfd_open(pid_t pid, unsigned int flags)
{
	return syscall(__NR_pidfd_open, pid, flags);
}

inline int
pidfd_getfd(int pidfd, int targetfd, unsigned int flags)
{
	return syscall(__NR_pidfd_getfd, pidfd, targetfd, flags);
}

#endif /* PIDFD_H */
