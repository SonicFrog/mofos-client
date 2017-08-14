#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "debug.h"

#include "proto/request.pb-c.h"


static FSMessage new_request()
{
    static uint32_t id = 0;

    unimplemented;
}

int read_request(const char* file, char* buf, size_t len)
{
    unimplemented;
    return -1;
}

int read_response(const char* file, char* buf, size_t len)
{
    unimplemented;
    return -1;
}

int attr_request(const char* file, struct stat *st)
{
    unimplemented;
    return -1;
}
