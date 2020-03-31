#include "munit.h"

extern MunitSuite mem_suite;

int
main(int argc, char *argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
	munit_suite_main(&mem_suite, NULL, argc, argv);
	return 0;
}
