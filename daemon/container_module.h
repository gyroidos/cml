/*
 * This file is part of trust|me
 * Copyright(c) 2013 - 2022 Fraunhofer AISEC
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

/**
 * @file container_module.h
 *
 * Module macro magic to avoid code duplication
 */

#ifndef CONTAINER_MODULE_H
#define CONTAINER_MODULE_H

// clang-format off
#define CONTAINER_MODULE_REGISTER_WRAPPER_IMPL(name, type, ...) \
	typedef struct { \
		const char *mod_name; \
		type (*handler_func)(__VA_ARGS__); \
	} container_## name ##_handler_t; \
	static container_## name ##_handler_t *container_## name ##_handler = NULL; \
	void container_register_## name ##_handler(const char *mod_name, type (*h)(__VA_ARGS__)) \
	{ \
		if (container_## name ##_handler) { \
			WARN("%s_handler allready registered, skip", #name); \
			return; \
		} \
		container_## name ##_handler = mem_new0(container_## name ##_handler_t, 1); \
		container_## name ##_handler->mod_name = mod_name; \
		container_## name ##_handler->handler_func = h; \
		INFO("%s_handler registerd by module '%s'.", #name, mod_name); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER_IMPL(name, type, unimpl) \
	type container_## name(const container_t *container) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER2_IMPL(name, type, unimpl, type_a1) \
	type container_## name(const container_t *container, type_a1 a1) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER3_IMPL(name, type, unimpl, type_a1, type_a2) \
	type container_## name(const container_t *container, type_a1 a1, type_a2 a2) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1, a2); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER3_1_IMPL(name, type, unimpl, type_a1, a1, type_a2, a2) \
	type container_## name(const container_t *container, type_a1, type_a2) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1, a2); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER4_IMPL(name, type, unimpl, type_a1, type_a2, type_a3) \
	type container_## name(const container_t *container, type_a1 a1, type_a2 a2, type_a3 a3) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1, a2, a3); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER5_IMPL(name, type, unimpl, type_a1, type_a2, type_a3, type_a4) \
	type container_## name(const container_t *container, type_a1 a1, type_a2 a2, type_a3 a3, type_a4 a4) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1, a2, a3, a4); \
	}

#define CONTAINER_MODULE_FUNCTION_WRAPPER6_IMPL(name, type, unimpl, type_a1, type_a2, type_a3, type_a4, type_a5) \
	type container_## name(const container_t *container, type_a1 a1, type_a2 a2, type_a3 a3, type_a4 a4, type_a5 a5) \
	{ \
		ASSERT(container); \
		if (!container_## name ##_handler) \
			return unimpl; \
		void *instance = container_module_get_instance_by_name( \
			container, container_## name ##_handler->mod_name); \
		/* no corresponding module registered and instantiated */ \
		if (!instance) \
			return unimpl; \
		return container_## name ##_handler->handler_func(instance, a1, a2, a3, a4, a5); \
	}
// clang-format on

#endif /* CONTAINER_MODULE_H */
