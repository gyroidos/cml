#include <stdio.h>
#include <stdbool.h>
#include <sys/utsname.h>

#include "macro.h"

bool
kernel_version_check(char *version)
{
	struct utsname buf;
	char ignore[65];
	int _main, _major, main_to_check, major_to_check;

	uname(&buf);

	ASSERT(sscanf(version, "%d.%d%s", &main_to_check, &major_to_check, ignore) >= 2);
	ASSERT(sscanf(buf.release, "%d.%d.%s", &_main, &_major, ignore) == 3);

	return (_main == main_to_check) ? _major >= major_to_check : _main >= main_to_check;
}
