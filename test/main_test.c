#include <stdlib.h>
#include <stdio.h>

#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>
#include <CUnit/TestRun.h>

#include <config.h>
#include <ssl_test.h>

int main(int argc, char** argv)
{
    CU_ErrorCode err;
    CU_pSuite gnutls_suite, ssl_suite;
    int failures;

    err = CU_initialize_registry();

    if (err != CUE_SUCCESS)
    {
        fprintf(stderr, "Tests failed to run!\n");
        return EXIT_FAILURE;
    }

    ssl_suite = CU_add_suite("ssl_test_suite", ssl_test_suite_init,
                             ssl_test_suite_cleanup);

    CU_ADD_TEST(ssl_suite, ssl_test_server_setup);
    CU_ADD_TEST(ssl_suite, ssl_test_server_loop);
    CU_ADD_TEST(ssl_suite, ssl_test_client_connect);

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();

    failures = CU_get_number_of_tests_failed();

    CU_cleanup_registry();

    if (failures != 0)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
