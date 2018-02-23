#include "fuse_test.h"

static void
setup(void)
{
    // TODO: test init
}

static void
teardown(void)
{
    // TODO: test teardown
}

TCase* fuse_tcase(void)
{
    TCase *tc;

    tc = tcase_create("FUSE");

    tcase_add_checked_fixture(tc, setup, teardown);

    // TODO: add tests

    return tc;
}
