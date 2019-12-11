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
#include "common/event.h"
#include "common/logf.h"
#include "common/file.h"
#include "common/mem.h"

#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define PIPE_READ 0
#define PIPE_WRITE 1
#define BUF_SIZE_KERNEL_LOG 1024 * 1024 * 64
#define LOGFILE_DIR "/data/logs/"
#define PATH_TO_KERNEL_LOG "/proc/kmsg"
#define BUF_SIZE_READ_KERNEL_LOG 1024
#define MAX_TRIES_TO_KILL_CHILD 10
#define MAX_LOGFILE_AGE_IN_DAYS 14
#define MAX_DAYS_IN_SECONDS MAX_LOGFILE_AGE_IN_DAYS * 24 * 60 * 60

UNUSED static int logcat_pid = 0;
static int kernel_log_pid = 0;
static int copied_kernel_log_fd = -1;
static int kernel_log_file_fd = -1;

UNUSED static void
panic_start_cml_logcat(void)
{
	DEBUG("Starting to read logcat");
	char *logfile_name = mem_printf("%s%s", LOGFILE_DIR, "logcat");
	FILE *logcat_fd = logf_file_new(logfile_name);
	mem_free(logfile_name);
	DEBUG("Writing logcat in file %s", logfile_name);
	dup2(fileno(logcat_fd), 1);
	dup2(fileno(logcat_fd), 2);
	fclose(logcat_fd);
	execl("/sbin/cml-logcat", "cml-logcat", "-A", "-b", "radio", "-b", "system", "-b", "main",
	      "-v", "time", NULL);
	ERROR_ERRNO("Could not exec cml-logcat");
}

static void
panic_read_kernel_log(void)
{
	if (copied_kernel_log_fd > 0) {
		close(copied_kernel_log_fd);
	}
	if (kernel_log_file_fd > 0) {
		close(kernel_log_file_fd);
	}
	char *logfile_name = mem_printf("%s%s", LOGFILE_DIR, "kmsg");
	char *copied_kernel_log = logf_file_new_name(logfile_name);
	mem_free(logfile_name);
	copied_kernel_log_fd = open(copied_kernel_log, O_WRONLY | O_CREAT | O_APPEND, 00666);
	if (copied_kernel_log_fd < 0) {
		ERROR_ERRNO("Could not open output file to copy kernel log to %s",
			    copied_kernel_log);
		mem_free(copied_kernel_log);
		return;
	}
	DEBUG("Writing kernel log to %s", copied_kernel_log);
	kernel_log_file_fd = open(PATH_TO_KERNEL_LOG, O_RDONLY);
	if (kernel_log_file_fd < 0) {
		ERROR_ERRNO("Could not open kernel log file %s", PATH_TO_KERNEL_LOG);
	}

	int bytes_read = 1;
	char *buf = mem_new(char, BUF_SIZE_READ_KERNEL_LOG);
	while (bytes_read > 0) {
		bytes_read = read(kernel_log_file_fd, buf, BUF_SIZE_READ_KERNEL_LOG);
		if (bytes_read == 0) {
			break;
		} else if (bytes_read < 0) {
			ERROR_ERRNO("Could not read from input file %s", PATH_TO_KERNEL_LOG);
			break;
		} else {
			int bytes_written = write(copied_kernel_log_fd, buf, bytes_read);
			if (bytes_written < 0) {
				ERROR_ERRNO("Could not copy kernel log to output file %s.",
					    copied_kernel_log);
				break;
			}
		}
	}
	mem_free(copied_kernel_log);
	close(copied_kernel_log_fd);
	close(kernel_log_file_fd);
}

static int
panic_restart_child(int pid, void (*func)(void))
{
	if (pid != 0) {
		int ret_val = kill(pid, SIGTERM);
		if (ret_val) {
			ERROR_ERRNO(
				"Could not send SIGTERM to %i. Child process could not be terminated.",
				pid);
			return -1;
		} else {
			DEBUG("Successfully sent SIGTERM to child process %i.", pid);
		}
	}

	int new_pid = fork();

	switch (new_pid) {
	case -1:
		ERROR_ERRNO("Could not fork");
		return new_pid;
	case 0:
		(func)();
		exit(0);
	default:
		for (int i = 0; i < MAX_TRIES_TO_KILL_CHILD; i++) {
			if (pid != 0) {
				if (kill(pid, 0)) {
					DEBUG("Child process still running, sending SIGKILL");
					int ret_val = kill(pid, SIGKILL);
					if (ret_val) {
						ERROR_ERRNO(
							"Could not send SIGKILL to %i. Child process could not be terminated.",
							pid);
					} else {
						DEBUG("Successfully sent SIGKILL to child process %i.",
						      pid);
					}
				} else {
					DEBUG("Child is killed");
					break;
				}
			}
		}
	}
	return new_pid;
}

static void
panic_logfile_rename_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	if (kernel_log_pid > 0) {
		DEBUG("Logfiles must be closed and new files opened");
	}

	//DEBUG("Forking process for logcat");
	//int pid = panic_restart_child(logcat_pid, panic_start_cml_logcat);
	//if (pid > 0) {
	//	logcat_pid = pid;
	//}
	//DEBUG("Started logcat with PID %d", logcat_pid);

	DEBUG("Forking process for kernel log");
	int pid = panic_restart_child(kernel_log_pid, panic_read_kernel_log);
	if (pid > 0) {
		kernel_log_pid = pid;
	}
	DEBUG("Started kernel log copy with PID %d", kernel_log_pid);
}

static void
panic_delete_old_logs_cb(UNUSED event_timer_t *timer, UNUSED void *data)
{
	DIR *directory = NULL;
	struct dirent *entry = NULL;
	struct stat stat_buf;

	DEBUG("Opening %s to look for logs older than %i (= %i seconds) days", LOGFILE_DIR,
	      MAX_LOGFILE_AGE_IN_DAYS, MAX_DAYS_IN_SECONDS);
	directory = opendir(LOGFILE_DIR);
	if (directory != NULL) {
		while ((entry = readdir(directory)) != NULL) {
			char *entry_name_with_path = mem_printf("%s%s", LOGFILE_DIR, entry->d_name);
			if (stat(entry_name_with_path, &stat_buf) == -1) {
				ERROR_ERRNO("Could not stat %s", entry->d_name);
				mem_free(entry_name_with_path);
				continue;
			}
			if (stat_buf.st_mtime) {
				double diff = difftime(time(0), stat_buf.st_mtime);
				if (diff > MAX_DAYS_IN_SECONDS) {
					DEBUG("Logfile %s was last modified more than %i days ago",
					      entry_name_with_path, MAX_LOGFILE_AGE_IN_DAYS);
					DEBUG("Deleting %s", entry_name_with_path);
					int ret = remove(entry_name_with_path);
					if (ret) {
						ERROR_ERRNO("%s could not be removed",
							    entry_name_with_path);
					}
				}
			}
			mem_free(entry_name_with_path);
		}
		closedir(directory);
	} else {
		ERROR_ERRNO("Couldn't open the directory %s", LOGFILE_DIR);
	}
}

char *
panic_find_last_kmsg(void)
{
	DIR *directory = NULL;
	struct dirent *entry = NULL;
	struct stat stat_buf;
	double smallest_diff = DBL_MAX;
	char *filename_of_latest_kmsg = NULL;

	DEBUG("Opening %s to look for last kmsg", LOGFILE_DIR);
	directory = opendir(LOGFILE_DIR);
	if (directory != NULL) {
		while ((entry = readdir(directory)) != NULL) {
			if (strstr(entry->d_name, "kmsg") != NULL) {
				char *entry_name_with_path =
					mem_printf("%s%s", LOGFILE_DIR, entry->d_name);
				if (stat(entry_name_with_path, &stat_buf) == -1) {
					ERROR_ERRNO("Could not stat %s", entry->d_name);
					mem_free(entry_name_with_path);
					continue;
				}
				if (stat_buf.st_mtime) {
					double diff = difftime(time(0), stat_buf.st_mtime);
					if (diff < smallest_diff) {
						smallest_diff = diff;
						filename_of_latest_kmsg =
							mem_strdup(entry_name_with_path);
					}
				}
				mem_free(entry_name_with_path);
			}
		}
		closedir(directory);
	} else {
		ERROR_ERRNO("Couldn't open the directory %s", LOGFILE_DIR);
	}
	return filename_of_latest_kmsg;
}

void
panic_search_for_kernel_panic_in_last_kmsg()
{
	FILE *f;
	char *buf;
	int n;

	char *filename_of_latest_kmsg = panic_find_last_kmsg();

	if (filename_of_latest_kmsg != NULL) {
		DEBUG("Trying to read last kmsg which is %s", filename_of_latest_kmsg);
		buf = file_read_new(filename_of_latest_kmsg, BUF_SIZE_KERNEL_LOG);
		if (!buf) {
			ERROR("Could not read last kmsg");
		} else {
			DEBUG("Searching for kernel panic in last kmsg...");
			if (!strstr(buf, "Kernel panic")) {
				DEBUG("No kernel panic found, exiting...");
			} else {
				DEBUG("Found a kernel panic in last kmsg");
				char *logfile_name = mem_printf("%s%s", LOGFILE_DIR, "panic");
				f = logf_file_new(logfile_name);
				if (f != NULL) {
					DEBUG("Dumping to file %s", logfile_name);
					n = fputs(buf, f);
					if (n >= 0) {
						ERROR("Could not dump to file %s", logfile_name);
					}
					fclose(f);
				} else {
					ERROR("Could not open %s", logfile_name);
				}
				mem_free(logfile_name);
			}
			mem_free(buf);
		}
		mem_free(filename_of_latest_kmsg);
	} else {
		WARN("Could not find kmsg file in %s", LOGFILE_DIR);
	}
}

int
main(UNUSED int argc, char **argv)
{
	struct stat stat_buf;

	if (stat(LOGFILE_DIR, &stat_buf) == -1) {
		mkdir(LOGFILE_DIR, 0700);
	}

	logf_register(&logf_android_write, logf_android_new(argv[0]));
	logf_register(&logf_file_write, stdout);

	panic_search_for_kernel_panic_in_last_kmsg();

	panic_logfile_rename_cb(NULL, NULL);
	event_init();
	event_timer_t *logfile_timer =
		event_timer_new(HOURS_TO_MILLISECONDS(2), EVENT_TIMER_REPEAT_FOREVER,
				panic_logfile_rename_cb, NULL);
	event_add_timer(logfile_timer);

	event_timer_t *delete_old_logs_timer =
		event_timer_new(HOURS_TO_MILLISECONDS(2), EVENT_TIMER_REPEAT_FOREVER,
				panic_delete_old_logs_cb, NULL);
	event_add_timer(delete_old_logs_timer);

	event_loop();
	return 0;
}
