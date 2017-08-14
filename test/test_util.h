#ifndef __DEF_TEST_UTIL_H
#define  __DEF_TEST_UTIL_H

#include <CUnit/CUnit.h>

#include <debug.h>

#define ASSERT_MSG(actual, expected, msg)                       \
    if (actual != expected)                                     \
    {                                                           \
        debug("%s: %p != %p", msg, actual, expected);           \
    }                                                           \

#endif
