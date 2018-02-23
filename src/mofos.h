#pragma once

#define FUSE_USE_VERSION 26

#include <sys/time.h>

#include <fuse.h>

extern const struct fuse_operations fops;

int
mofos_client_main_loop(struct mofos_config *config, int argc, char** argv);
