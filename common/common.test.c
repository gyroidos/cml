#include "munit.h"

extern MunitSuite mem_suite;
extern MunitSuite macro_suite;
extern MunitSuite ssl_util_suite;

int
main(int argc, char *argv[MUNIT_ARRAY_PARAM(argc + 1)])
{
	int failed = 0;

	failed += munit_suite_main(&mem_suite, NULL, argc, argv);
	failed += munit_suite_main(&macro_suite, NULL, argc, argv);
	failed += munit_suite_main(&ssl_util_suite, NULL, argc, argv);

	return failed;
}
