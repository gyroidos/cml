#ifndef NS_H
#define NS_H

#include <unistd.h>

int
namespace_exec(pid_t ns_pid, const char *const *namespaces, const size_t ns_len,
	       int (*func)(void **), const void **data);

#endif //NS_H
