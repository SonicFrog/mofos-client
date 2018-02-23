#include "request_test.h"

static void
setup(void)
{

}

static void
teardown(void)
{

}

TCase* request_tcase(void)
{
    TCase *tc;

    tc = tcase_create("Request");

    tcase_add_checked_fixture(tc, setup, teardown);

    // TODO: add tests

    return tc;
}
