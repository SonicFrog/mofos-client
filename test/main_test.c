#include <check.h>
#include <stdio.h>
#include <stdlib.h>

#include <debug.h>

#include "ssl_test.h"

int main(void)
{
    int number_failed = 0;
    Suite *s = NULL;
    SRunner *sr = NULL;

    s = suite_create("mofos");
    suite_add_tcase(s, ssl_tcase());
    sr = srunner_create(s);

    mofos_log_set_level(LOG_LEVEL_ERROR);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
