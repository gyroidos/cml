#include <stdbool.h>

/**
 * Checks if kernel version is at least the specified one.
 * Needed by submodules requiring kernel features available on newer kernels only.
 */
bool
kernel_version_check(char *version);
