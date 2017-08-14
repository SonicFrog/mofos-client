#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <iconv.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "mofos.h"
#include "debug.h"

int mofos_open(const char *path, struct fuse_file_info* fi)
{
    debug("Opening file %s\n", path);
    assert(fi != NULL);

    if (strncmp(path, "/me", 4) == 0)
    {
        return 0;
    }

    return -ENOENT;
}

int mofos_read(const char* path, char* buf, size_t size, off_t offset,
               struct fuse_file_info* fi)
{
    const char* content = "Hello world!";
    debug("Read %zd bytes from %s at offset %ld\n", size, path, offset);
    assert(fi != NULL);

    strncpy(buf, content, strlen(content) + 1);

    return 1;
}


int mofos_readdir(const char* path, void* callback_data, fuse_fill_dir_t callback,
                  off_t offset, struct fuse_file_info* fi)
{
    struct stat curr;
    debug("Reading directory %s\n", path);

    assert(fi != NULL);

    if (strncmp(path, "/", 2) != 0)
    {
        return -ENOENT;
    }

    curr.st_mode = 0;
    callback(callback_data, "me", &curr, 0);

    return 0;
}

int mofos_write(const char* path, const char* buf, size_t size, off_t offset,
                struct fuse_file_info* fi)
{
    debug("Writing %zu bytes to file %s at offset %ld", size, path, offset);
    debug("Data written first byte: %c\n", buf[0]);
    assert(fi != NULL);

    return -1;
}

int mofos_getattr(const char* path, struct stat* st)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;

    debug("Getting file attribute for %s\n", path);

    st->st_uid = 1000;
    st->st_gid = 1000;

    if (strncmp(path, "/", 2) == 0)
    {
        st->st_mode = mode | S_IFDIR;
        return 0;
    }

    if (strncmp(path, "/me", 3) == 0)
    {
        st->st_mode = mode | S_IFREG;
        return 0;
    }


    return -ENOENT;
}

struct fuse_operations fops = {
    .open = mofos_open,
    .read = mofos_read,
    .write = mofos_write,
    .getattr = mofos_getattr,
    .readdir = mofos_readdir,
};
