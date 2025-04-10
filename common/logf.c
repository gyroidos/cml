/*
 * This file is part of GyroidOS
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
 * Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
 */

#include "dir.h"
#include "file.h"
#include "logf.h"
#include "list.h"
#include "macro.h"
#include "mem.h"

#ifdef ANDROID
#include <cutils/klog.h>
#include <android/log.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

// TODO: we should not include this in production builds...
#ifndef LOGF_FILE_STRIP
#define LOGF_FILE_STRIP "device/fraunhofer/common/cml/"
#endif

void
logf_message(logf_prio_t prio, const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	logf_write(prio, buf);
}

void
logf_message_errno(logf_prio_t prio, const char *fmt, ...)
{
	char buf[4096];
	int errno_backup = errno;
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	n += snprintf(buf + n, sizeof(buf) - n, " (%d: %s)", errno_backup, strerror(errno_backup));

	if (n < 0)
		return;

	logf_write(prio, buf);
}

void
logf_message_file(logf_prio_t prio, const char *file, int line, const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int n;

	if (file && strstr(file, LOGF_FILE_STRIP) == file)
		file += strlen(LOGF_FILE_STRIP);

	n = snprintf(buf, sizeof(buf), "%s+%d: ", file, line);

	if (n < 0)
		return;

	va_start(ap, fmt);
	n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	logf_write(prio, buf);
}

void
logf_message_file_errno(logf_prio_t prio, const char *file, int line, const char *fmt, ...)
{
	char buf[4096];
	int errno_backup = errno;
	va_list ap;
	int n;

	if (file && strstr(file, LOGF_FILE_STRIP) == file)
		file += strlen(LOGF_FILE_STRIP);

	n = snprintf(buf, sizeof(buf), "%s+%d: ", file, line);

	if (n < 0)
		return;

	va_start(ap, fmt);
	n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	n += snprintf(buf + n, sizeof(buf) - n, " (%d: %s)", errno_backup, strerror(errno_backup));

	if (n < 0)
		return;

	logf_write(prio, buf);
}

void
logf_message_hexdump(logf_prio_t prio, const void *b, size_t len, const char *fmt, ...)
{
	char buf[4096 * 4];
	va_list ap;
	size_t i;
	int n;

	if (len > 1024) {
		logf_write(prio, "Buffer too long for log");
		return;
	}

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	n += snprintf(buf + n, sizeof(buf) - n, "[%zu]", len);

	if (n < 0)
		return;

	for (i = 0; i < len; i++) {
		n += snprintf(buf + n, sizeof(buf) - n, " %02x", ((uint8_t *)b)[i]);
		if (n < 0)
			return;
	}

	logf_write(prio, buf);
}

void
logf_message_file_hexdump(logf_prio_t prio, const char *file, int line, const void *b, size_t len,
			  const char *fmt, ...)
{
	char buf[4096 * 4];
	va_list ap;
	size_t i;
	int n;

	if (len > 1024) {
		logf_write(prio, "Buffer too long for log");
		return;
	}

	n = snprintf(buf, sizeof(buf), "%s+%d: ", file, line);

	if (n < 0)
		return;

	va_start(ap, fmt);
	n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
	va_end(ap);

	if (n < 0)
		return;

	n += snprintf(buf + n, sizeof(buf) - n, "[%zu]", len);

	if (n < 0)
		return;

	for (i = 0; i < len; i++) {
		n += snprintf(buf + n, sizeof(buf) - n, " %02x", ((uint8_t *)b)[i]);
		if (n < 0)
			return;
	}

	logf_write(prio, buf);
}

/******************************************************************************/

static list_t *logf_handler_list = NULL;

struct logf_handler {
	void (*func)(logf_prio_t prio, const char *msg, void *data);
	void *data;
	logf_prio_t prio;
};

void
logf_write(logf_prio_t prio, const char *msg)
{
	for (list_t *l = logf_handler_list; l; l = l->next) {
		logf_handler_t *h = l->data;
		if (h && h->func && prio >= h->prio) {
			(h->func)(prio, msg, h->data);
		}
	}
}

logf_handler_t *
logf_register(void (*func)(logf_prio_t prio, const char *msg, void *data), void *data)
{
	logf_handler_t *handler = mem_new(logf_handler_t, 1);

	handler->func = func;
	handler->data = data;
	handler->prio = LOGF_PRIO_TRACE;

	logf_handler_list = list_append(logf_handler_list, handler);

	return handler;
}

void
logf_unregister(logf_handler_t *handler)
{
	IF_NULL_RETURN(handler);
	logf_handler_list = list_remove(logf_handler_list, handler);

	mem_free0(handler);
}

void
logf_handler_set_prio(logf_handler_t *handler, logf_prio_t prio)
{
	ASSERT(handler);
	handler->prio = prio;
}

void
logf_log_files_list_free(list_t *head)
{
	while (head) {
		list_t *next = head->next;
		mem_free0(head->data);
		mem_free0(head);
		head = next;
	}
}

static int
logf_current_log_cb(const char *path, const char *file, void *data)
{
	list_t **log_file_list = (list_t **)data;
	char *file_path = mem_printf("%s/%s", path, file);

	// only process .current symlinks.
	if ((!file_is_link(file_path)) || (strstr(file, ".current") == NULL)) {
		return 0;
	}

	char *buffer = mem_alloc0(PATH_MAX);
	ssize_t len = readlink(file_path, buffer, PATH_MAX);

	if (len < 0 || len > PATH_MAX - 1) {
		ERROR_ERRNO("readlink on %s returned %zd", file_path, len);
		return -1;
	} else {
		DEBUG("Adding currently used logfile to list %s", buffer);
		*log_file_list = list_append(*log_file_list, mem_strdup(buffer));
	}

	mem_free0(file_path);
	mem_free0(buffer);

	return 1;
}

list_t *
logf_get_current_log_files_new(const char *path)
{
	list_t *current_log_files = NULL;
	int dir_ret = dir_foreach(path, &logf_current_log_cb, &current_log_files);

	if (dir_ret < 0) {
		WARN("Something went wrong during traversal of %s", path);
	} else if (dir_ret > 0) {
		TRACE("%d logs have been analyzed.", dir_ret);
	}

	return current_log_files;
}

int
logf_lock_apply(const char *path)
{
	char *file_path = mem_printf("%s/%s", path, ".lock-delete-old");

	int lock_fd = open(file_path, O_RDONLY | O_CREAT, 0644);
	if (lock_fd < 0) {
		ERROR_ERRNO("Failed to open %s", file_path);
		lock_fd = -1;
		goto out;
	}
	if (flock(lock_fd, LOCK_EX) < 0) {
		ERROR_ERRNO("Failed to get lock on %s", file_path);
		close(lock_fd);
		lock_fd = -1;
		goto out;
	}

out:
	mem_free0(file_path);
	return lock_fd;
}

int
logf_lock_release(const char *path, int lock_fd)
{
	int result = 0;
	char *file_path = mem_printf("%s/%s", path, ".lock-delete-old");

	if (flock(lock_fd, LOCK_UN)) {
		ERROR_ERRNO("Failed to release lock on %s", file_path);
		result = -1;
	}

	close(lock_fd);
	mem_free0(file_path);

	return result;
}

/******************************************************************************/

char *
logf_file_new_name(const char *name)
{
	char buf1[64], buf2[64];
	struct timeval tv;
	struct tm *tm;
	char *n;

	if (gettimeofday(&tv, NULL) < 0)
		FATAL_ERRNO("Failed to get time of day. Aborting.\n");

	tm = localtime(&tv.tv_sec);
	if (tm == NULL)
		FATAL_ERRNO("Failed to get local time. Aborting.\n");

	if (!strftime(buf1, sizeof(buf1) - 1, "%Y-%m-%dT%H:%M:%S", tm))
		buf1[0] = '\0';

	if (!strftime(buf2, sizeof(buf2) - 1, "%z", tm))
		buf2[0] = '\0';

	// rfc3339 format: <name>.2014-05-23T21:29:11.150495+02:00
	n = mem_printf("%s.%s.%06u%s", name, buf1, (unsigned)tv.tv_usec, buf2);

	return n;
}

void *
logf_file_new(const char *name)
{
	char *current = mem_printf("%s%s", name, ".current");

	FILE *f;
	char *name_with_time_of_day = logf_file_new_name(name);
	f = fopen(name_with_time_of_day, "w");
	if (!f) {
		FATAL_ERRNO("Failed to open log file\n");
	}

	if (0 != setvbuf(f, NULL, _IOLBF, 0)) {
		fclose(f);
		f = NULL;
	}

	if (file_exists(current) && unlink(current)) {
		WARN_ERRNO("could not unlink %s", current);
	}

	if (symlink(name_with_time_of_day, current) < 0) {
		WARN_ERRNO("Could not create symlink %s to %s", name_with_time_of_day, current);
	}

	mem_free0(current);
	mem_free0(name_with_time_of_day);

	return f;
}

void
logf_file_close(void *file)
{
	FILE *f = file;
	fclose(f);
}

static void
logf_file_write_timestamp(FILE *stream)
{
	char buf1[64], buf2[64];
	struct timeval tv;
	struct tm *tm;

	IF_TRUE_RETURN_ERROR_ERRNO((gettimeofday(&tv, NULL) < 0));

	tm = localtime(&tv.tv_sec);
	IF_NULL_RETURN_ERROR_ERRNO(tm);

	if (!stream)
		return;

	if (!strftime(buf1, sizeof(buf1) - 1, "%Y-%m-%dT%H:%M:%S", tm))
		return;

	if (!strftime(buf2, sizeof(buf2) - 1, "%z", tm))
		return;

	// rfc3339 format: 2014-05-23T21:29:11.150495+02:00
	fprintf(stream, "%s.%06u%s ", buf1, (unsigned)tv.tv_usec, buf2);
}

static const char *
prio_str(logf_prio_t prio)
{
	switch (prio) {
	case LOGF_PRIO_FATAL:
		return "<FATAL>";
	case LOGF_PRIO_ERROR:
		return "<ERROR>";
	case LOGF_PRIO_WARN:
		return "<WARN> ";
	case LOGF_PRIO_INFO:
		return "<INFO> ";
	case LOGF_PRIO_DEBUG:
		return "<DEBUG>";
	case LOGF_PRIO_TRACE:
		return "<TRACE>";
	default:
		return "<?\?\?>"; // escaping needed because of C preprocessor trigraph clash
	}
}

void
logf_file_write(logf_prio_t prio, const char *msg, void *data)
{
	if (!data)
		return;

	logf_file_write_timestamp(data);
	fprintf(data, "[%u] %s %s\n", getpid(), prio_str(prio), msg);

	int res = -1;
	if (0 != (res = fflush(data))) {
		ERROR_ERRNO("Failed to flush log file for PID %d after message %s: %d", getpid(),
			    msg, res);
	}
}

void
logf_test_write(logf_prio_t prio, const char *msg, void *data)
{
	if (!data)
		return;

	fprintf(data, "[%u] %s %s\n", getpid(), prio_str(prio), msg);

	int res = -1;
	if (0 != (res = fflush(data))) {
		ERROR_ERRNO("Failed to flush log file for PID %d after message %s: %d", getpid(),
			    msg, res);
	}
}

void *
logf_syslog_new(const char *name)
{
	openlog(name, LOG_PID, LOG_USER);

	return mem_strdup(name);
}

void
logf_syslog_write(logf_prio_t prio, const char *msg, void *data)
{
	int prio_syslog;

	switch (prio) {
	case LOGF_PRIO_FATAL:
	case LOGF_PRIO_ERROR:
		prio_syslog = LOG_ERR;
		break;
	case LOGF_PRIO_WARN:
		prio_syslog = LOG_WARNING;
		break;
	case LOGF_PRIO_INFO:
		prio_syslog = LOG_INFO;
		break;
	case LOGF_PRIO_DEBUG:
	case LOGF_PRIO_TRACE:
		prio_syslog = LOG_DEBUG;
		break;
	default:
		prio_syslog = LOG_NOTICE;
		break;
	}

	syslog(prio_syslog, "%s %s %s\n", prio_str(prio), (char *)data, msg);
}

void *
logf_android_new(const char *name)
{
	return mem_strdup(name);
}

#ifdef ANDROID
void
logf_android_write(logf_prio_t prio, const char *msg, void *data)
{
	int prio_android;

	switch (prio) {
	case LOGF_PRIO_FATAL:
		prio_android = ANDROID_LOG_FATAL;
		break;
	case LOGF_PRIO_ERROR:
		prio_android = ANDROID_LOG_ERROR;
		break;
	case LOGF_PRIO_WARN:
		prio_android = ANDROID_LOG_WARN;
		break;
	case LOGF_PRIO_INFO:
		prio_android = ANDROID_LOG_INFO;
		break;
	case LOGF_PRIO_DEBUG:
		prio_android = ANDROID_LOG_DEBUG;
		break;
	case LOGF_PRIO_TRACE:
		prio_android = ANDROID_LOG_VERBOSE;
		break;
	default:
		prio_android = ANDROID_LOG_DEFAULT;
		break;
	}

	__android_log_write(prio_android, data, msg);
}
#else
void
logf_android_write(UNUSED logf_prio_t prio, UNUSED const char *msg, UNUSED void *data)
{
	return;
}
#endif

void *
logf_klog_new(const char *name)
{
#ifdef ANDROID
	klog_init();
	klog_set_level(7);
#endif
	return mem_strdup(name);
}

#ifdef ANDROID
void
logf_klog_write(logf_prio_t prio, const char *msg, void *data)
{
	int prio_klog;

	switch (prio) {
	case LOGF_PRIO_FATAL:
	case LOGF_PRIO_ERROR:
		prio_klog = 3;
		break;
	case LOGF_PRIO_WARN:
		prio_klog = 4;
		break;
	case LOGF_PRIO_INFO:
		prio_klog = 6;
		break;
	case LOGF_PRIO_DEBUG:
	case LOGF_PRIO_TRACE:
		prio_klog = 7;
		break;
	default:
		prio_klog = 5;
		break;
	}

	klog_write(prio_klog, "<%u>%s[%u] %s %s\n", prio_klog, (char *)data, getpid(),
		   prio_str(prio), msg);
}
#else
void
logf_klog_write(UNUSED logf_prio_t prio, UNUSED const char *msg, UNUSED void *data)
{
	return;
}
#endif
