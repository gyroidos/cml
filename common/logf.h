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

/**
 * @file logf.h
 *
 * Provides functionality for logging to stdout, stderr, files, system logger (syslog),
 * Android's logging system (logcat), and to the kernel ring buffer (dmesg). All logging
 * should be done by the logging macros DEBUG, INFO, WARN, and ERROR (defined in macro.h).
 * Before using these logging macros, one or more logging writers should be registered.
 * Here are some examples on how to register various types of writers:
 *
 * @code
 * // Log to STDOUT:
 * logf_register(&logf_file_write, stdout);
 *
 * // Log to STDERR:
 * logf_register(&logf_file_write, stderr);
 *
 * // Append log messages to file `somefile.log':
 * logf_register(&logf_file_write, fopen("somefile.log", "a"));
 *
 * // Log messages to file `somefile.log':
 * logf_register(&logf_file_write, logf_file_new("somefile.log"));
 *
 * // Log to Android's logging system using tag `sometag' (may be viewed with Android's `logcat' command):
 * logf_register(&logf_android_write, logf_android_new("sometag"));
 *
 * // Log to the system logger (syslog) using tag `sometag'.
 * logf_register(&logf_syslog_write, logf_syslog_new("sometag"));
 *
 * // Log to the kernel ring buffer using tag `sometag' (may be viewed with the `dmesg' command):
 * logf_register(&logf_klog_write, logf_klog_new("sometag"));
 * @endcode
 */

#ifndef LOGF_H
#define LOGF_H

typedef enum {
	LOGF_PRIO_TRACE = 1,
	LOGF_PRIO_DEBUG,
	LOGF_PRIO_INFO,
	LOGF_PRIO_WARN,
	LOGF_PRIO_ERROR,
	LOGF_PRIO_FATAL,
	LOGF_PRIO_SILENT // define LOGF_LOG_MIN_PRIO to this value to disable all logging output
} logf_prio_t;

typedef struct logf_handler logf_handler_t;

/**
 * This function is only implicitly used by the logging macros defined in macro.h
 */
void logf_message(logf_prio_t prio, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
	;

/**
 * This function is only implicitly used by the logging macros defined in macro.h
 */
void logf_message_errno(logf_prio_t prio, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
	;

/**
 * This function is only implicitly used by the logging macros defined in macro.h
 */
void logf_message_file(logf_prio_t prio, const char *file, int line, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 4, 5)))
#endif
	;

/**
 * This function is only implicitly used by the logging macros defined in macro.h
 */
void logf_message_file_errno(logf_prio_t prio, const char *file, int line, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 4, 5)))
#endif
	;

#ifndef DEBUG_BUILD
// RELEASE BUILD: log INFO level and higher, include NEITHER file name NOR line number
#ifndef LOGF_LOG_MIN_PRIO
#define LOGF_LOG_MIN_PRIO LOGF_PRIO_INFO
#endif

#define logf_message_guard(level, ...)                                                                                 \
	do {                                                                                                           \
		if (level >= LOGF_LOG_MIN_PRIO)                                                                        \
			logf_message(level, __VA_ARGS__);                                                              \
	} while (0)
#define logf_message_errno_guard(level, ...)                                                                           \
	do {                                                                                                           \
		if (level >= LOGF_LOG_MIN_PRIO)                                                                        \
			logf_message_errno(level, __VA_ARGS__);                                                        \
	} while (0)

#else /* DEBUG_BUILD */
// DEBUG BUILD: log DEBUG level and higher, include BOTH file name AND line number
//
// To enable TRACE for a particular module:
// Define LOGF_LOG_MIN_PRIO before including logf.h (or macro.h):
//      #define LOGF_LOG_MIN_PRIO LOGF_PRIO_TRACE
//      #include <macro.h>
#ifndef LOGF_LOG_MIN_PRIO
#define LOGF_LOG_MIN_PRIO LOGF_PRIO_DEBUG
#endif

#define logf_message_guard(level, ...)                                                                                 \
	do {                                                                                                           \
		if (level >= LOGF_LOG_MIN_PRIO)                                                                        \
			logf_message_file(level, __FILE__, __LINE__, __VA_ARGS__);                                     \
	} while (0)
#define logf_message_errno_guard(level, ...)                                                                           \
	do {                                                                                                           \
		if (level >= LOGF_LOG_MIN_PRIO)                                                                        \
			logf_message_file_errno(level, __FILE__, __LINE__, __VA_ARGS__);                               \
	} while (0)

#endif /* DEBUG_BUILD */

#define logf_fatal(...) logf_message_guard(LOGF_PRIO_FATAL, __VA_ARGS__)
#define logf_fatal_errno(...) logf_message_errno_guard(LOGF_PRIO_FATAL, __VA_ARGS__)

#define logf_error(...) logf_message_guard(LOGF_PRIO_ERROR, __VA_ARGS__)
#define logf_error_errno(...) logf_message_errno_guard(LOGF_PRIO_ERROR, __VA_ARGS__)

#define logf_warn(...) logf_message_guard(LOGF_PRIO_WARN, __VA_ARGS__)
#define logf_warn_errno(...) logf_message_errno_guard(LOGF_PRIO_WARN, __VA_ARGS__)

#define logf_info(...) logf_message_guard(LOGF_PRIO_INFO, __VA_ARGS__)
#define logf_info_errno(...) logf_message_errno_guard(LOGF_PRIO_INFO, __VA_ARGS__)

#define logf_debug(...) logf_message_guard(LOGF_PRIO_DEBUG, __VA_ARGS__)
#define logf_debug_errno(...) logf_message_errno_guard(LOGF_PRIO_DEBUG, __VA_ARGS__)

#define logf_trace(...) logf_message_guard(LOGF_PRIO_TRACE, __VA_ARGS__)
#define logf_trace_errno(...) logf_message_errno_guard(LOGF_PRIO_TRACE, __VA_ARGS__)

/**
 * Logs to all registered log writers (logf_*_write).
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 */
void logf_write(logf_prio_t prio, const char *msg);

/**
 * Registers a log writer.
 *
 */
logf_handler_t *logf_register(void (*func)(logf_prio_t prio, const char *msg, void *data), void *data);

/**
 * Unregisters a log writer.
 *
 */
void logf_unregister(logf_handler_t *handler);

/**
 * Set the lowest priority for messages logged to this handler
 */
void logf_handler_set_prio(logf_handler_t *handler, logf_prio_t prio);

/**
 * Generates a logfile name by appending a unique timestamp to the filename.
 * The result is in RFC3339 format, e.g., `<name>.2014-05-23T21:29:11.150495+02:00'.
 *
 * @param name Name of the log file.
 * @return The new name with timestamp.
 */
char *logf_file_new_name(const char *name);

/**
 * Opens the log file for logf_file_write.
 * This will append a unique timestamp to the filename.
 * The result is in RFC3339 format, e.g., `<name>.2014-05-23T21:29:11.150495+02:00'.
 *
 * @param name Name of the log file.
 * @return A pointer to the log file.
 */
void *logf_file_new(const char *name);

/**
 * Logs to stdout/stderr or to a file.
 * Cannot be used in conjunction with unit tests; use logf_test_write instead.
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 * @param data stdout/stderr or a file.
 */
void logf_file_write(logf_prio_t prio, const char *msg, void *data);

/**
 *  Similar to logf_file_write but omits the (varying) timestamp and may thus
 *  be used for unit tests.
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 * @param data stdout/stderr or a file.
 */
void logf_test_write(logf_prio_t prio, const char *msg, void *data);

/**
 * Opens syslog for logf_syslog_write and sets the log tag.
 *
 * @param name The string to be prepended to every log message.
 * @return A pointer to the tag name.
 */
void *logf_syslog_new(const char *name);

/**
 * Logs to syslog.
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 * @param data The log name.
 */
void logf_syslog_write(logf_prio_t prio, const char *msg, void *data);

/**
 * Sets log tag for logf_android_write.
 *
 * @param name The tag name.
 * @return A pointer to the tag name.
 */
void *logf_android_new(const char *name);

/**
 * Logs to Android's logging system (logcat).
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 * @param data The log name.
 */
void logf_android_write(logf_prio_t prio, const char *msg, void *data);

/**
 * Sets log tag for logf_klog_write.
 *
 * @param name The tag name.
 * @return A pointer to the tag name.
 */
void *logf_klog_new(const char *name);

/**
 * Logs to kernel log.
 *
 * @param prio Priority of the log message.
 * @param msg The log message.
 * @param data The log name.
 */
void logf_klog_write(logf_prio_t prio, const char *msg, void *data);

#endif /* LOGF_H */
