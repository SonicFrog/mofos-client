#ifndef __MOFOS_CONFIG_H
#define __MOFOS_CONFIG_H 1

#include <stdbool.h>

#include "compiler.h"

struct mofos_config;

struct mofos_config*
mofos_config_new();

bool
mofos_config_from_args(struct mofos_config* cfg,
		       int argc,
		       char** argv) NON_NULL(1, 3);

const char*
mofos_config_get_mountpoint(const struct mofos_config* cfg) NON_NULL(1);

void
mofos_config_set_mountpoint(struct mofos_config *cfg, const char* mnt)
    NON_NULL(1, 2);

const char*
mofos_config_get_remote_host(const struct mofos_config *cfg) NON_NULL(1);

void
mofos_config_set_remote_host(struct mofos_config *cfg, const char* host)
    NON_NULL(1, 2);

int
mofos_config_get_port(const struct mofos_config *cfg) NON_NULL(1);

void
mofos_config_set_port(struct mofos_config *cfg, int port) NON_NULL(1);

bool
mofos_config_is_verbose(const struct mofos_config *cfg) NON_NULL(1);

void
mofos_config_set_verbose(struct mofos_config *cfg, bool verbose) NON_NULL(1);

bool
mofos_config_is_encrypted(const struct mofos_config *cfg) NON_NULL(1);

void
mofos_config_set_encrypted(struct mofos_config *cfg, bool enc) NON_NULL(1);

#endif // __MOFOS_CONFIG_H
