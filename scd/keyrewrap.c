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

#include "common/macro.h"
#include "common/logf.h"
#include "common/ssl_util.h"

#include "softtoken.h"

static softtoken_t *token_old = NULL;
static softtoken_t *token_new = NULL;

int
main(int argc, char **argv)
{
	ASSERT(argc >= 3);
	char *token_path_old = argv[1];
	char *token_path_new = argv[2];

	logf_register(&logf_file_write, stdout);

	token_old = softtoken_new_from_p12(token_path_old);
	token_new = softtoken_new_from_p12(token_path_new);

	return 0;
}
