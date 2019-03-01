#ifndef C_RUN_H
#define C_RUN_H

#include "container.h"


typedef struct c_run c_run_t;

c_run_t *
c_run_new(container_t *container);

void
c_run_free(c_run_t *run);

void
c_run_cleanup(c_run_t *run);

int
c_run_write_exec_input(c_run_t *run, char *exec_input);

int
c_run_exec_process(c_run_t *run, int create_pty, char *cmd, ssize_t argc, char **argv);

int
c_run_get_console_sock_cmld(const c_run_t * run);

int
c_run_get_active_exec_pid(const c_run_t * run);
#endif //end C_RUN_H
