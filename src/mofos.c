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

#include "config.h"
#include "request.h"
#include "mofos.h"
#include "debug.h"
#include "gnutls.h"

static int
mofos_open(const char *path, __attribute__((unused)) struct fuse_file_info* fi)
{
    debug("Opening file %s\n", path);

    if (strncmp(path, "/me", 4) == 0)
    {
        return 0;
    }

    return -ENOENT;
}

static int
mofos_read(const char* path, char* buf, size_t size, off_t offset,
	   __attribute__((unused)) struct fuse_file_info* fi)
{
    const char* content = "Hello world!";
    debug("Read %zd bytes from %s at offset %ld\n", size, path, offset);
    assert(fi != NULL);

    strncpy(buf, content, strlen(content) + 1);

    return 1;
}


static int
mofos_readdir(const char* path, void* callback_data, fuse_fill_dir_t callback,
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

static int
mofos_write(const char* path, const char* buf, size_t size, off_t offset,
	    __attribute__((unused)) struct fuse_file_info* fi)
{
    debug("Writing %zu bytes to file %s at offset %ld", size, path, offset);
    debug("Data written first byte: %c\n", buf[0]);

    int rc = 0;

    if (rc < 0) {
        fatal("failed to create write request: %s\n", strerror(errno));
    }

    return rc;
}

static int
mofos_getattr(const char* path, struct stat* st)
{
    mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;

    debug("Getting file attribute for %s\n", path);

    st->st_uid = geteuid();
    st->st_gid = getegid();

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

const struct fuse_operations fops = {
    .open = mofos_open,
    .read = mofos_read,
    .write = mofos_write,
    .getattr = mofos_getattr,
    .readdir = mofos_readdir,
};

int mofos_client_main_loop(struct mofos_config *config, int argc, char** argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
    const char* host = mofos_config_get_remote_host(config);
    struct mofos_dtls_client* client = NULL;

    if (fuse_opt_parse(&args, NULL, NULL, 0) != 0) {
        return EXIT_FAILURE;
    }

    client = mofos_dtls_client_new(host, "22");

    if (!client)
    {
        fatal("unable to connect to server: %s", strerror(errno));
        return -1;
    }

    return fuse_main(args.argc, args.argv, &fops, client);
}
