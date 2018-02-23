#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "config.h"

struct mofos_config {
    bool verbose;
    bool encryption;

    char *mountpoint;
    char *remote_host;
    int port;
};

struct mofos_config*
mofos_config_new() {
    return calloc(sizeof(struct mofos_config), 1);
}

bool
mofos_config_from_args(struct mofos_config* cfg, int argc, char** argv) {
    return true;
}

const char*
mofos_config_get_remote_host(const struct mofos_config *cfg) {
    return cfg->remote_host;
}

void
mofos_config_set_remote_host(struct mofos_config *cfg, const char* host) {
    cfg->remote_host = strdup(host);
}

const char*
mofos_config_get_mountpoint(const struct mofos_config *cfg) {
    return cfg->mountpoint;
}

void
mofos_config_set_mountpoint(struct mofos_config *cfg, const char* mnt) {
    cfg->mountpoint = strdup(mnt);
}

void
mofos_config_set_port(struct mofos_config *cfg, const int port) {
    cfg->port = port;
}

void
mofos_config_set_verbose(struct mofos_config *cfg, bool verbose) {
    cfg->verbose = verbose;
}

void
mofos_config_set_encrypted(struct mofos_config *cfg, bool enc) {
    cfg->encryption = enc;
}

int
mofos_config_get_port(const struct mofos_config *cfg) {
    return cfg->port;
}

bool
mofos_config_is_verbose(const struct mofos_config *cfg) {
    return cfg->verbose;
}

bool
mofos_config_is_encrypted(const struct mofos_config *cfg) {
    return cfg->encryption;
}
