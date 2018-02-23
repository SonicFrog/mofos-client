#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "config.h"
#include "debug.h"
#include "mofos.h"

#define CHECK(x) assert((x) >= 0)

#define MAX_BUF 1024

static const char* sig_name_str(int sig)
{
    switch (sig)
    {
#define CASE_RETURN_STRING(sig) case sig: return #sig
        CASE_RETURN_STRING(SIGTERM);
        CASE_RETURN_STRING(SIGINT);
        CASE_RETURN_STRING(SIGUSR1);
        CASE_RETURN_STRING(SIGHUP);
#undef CASE_RETURN_STRING
    }
    return NULL;
}


int parse_args(int *argc, char** argv, struct mofos_config* cfg);

static void
handle_signal(int sig)
{
    const char* sig_name = sig_name_str(sig);
    switch (sig)
    {
    case SIGTERM:
    case SIGINT:
        // TODO: handle clean exit
        break;

    case SIGUSR1:
        // TODO: stats print out
        break;

    default:
        fatal("Caught wrong signal: %s\n", sig_name);
    }

}

static void
signal_setup()
{

    int signals[] = {SIGINT, SIGTERM, SIGUSR1};
    struct sigaction sa;

    sa.sa_handler = &handle_signal;
    sa.sa_flags = SA_RESTART;

    sigfillset(&sa.sa_mask);

    for (unsigned i = 0; i < sizeof(signals) / sizeof(SIGINT); i++)
    {
	if (sigaction(signals[i], &sa, NULL) < 0)
	    fatal("Unable to setup %s handling: %s\n",
		  sig_name_str(signals[i]),
		  strerror(errno));
    }
}

static void
usage(const char *progname)
{
    fprintf(stderr, "usage: %s <target> <destintation>\n", progname);
}

static int
do_fuse(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
    struct mofos_config *cfg = mofos_config_new();

    if (parse_args(&argc, argv, cfg)) {
        return EXIT_FAILURE;
    }

    if (fuse_opt_parse(&args, NULL, NULL, 0) != 0)
    {
        fprintf(stderr, "Fuse couldn't parse arguments!\n");
        return EXIT_FAILURE;
    }

    return fuse_main(args.argc, args.argv, &fops, NULL);
}

int parse_args(int *argc, char** argv, struct mofos_config* out)
{
#define IS_OPT(str) (strncmp("--", str, 2) == 0)

    for (int i = 1; i < *argc; i++) {

        if (IS_OPT(argv[i])) {
            if (strcmp("--verbose", argv[i]) == 0) {
                // TODO: enable verbose mode
            }
            else if (strcmp("--foreground", argv[i]) == 0) {
                // TODO: enable nofork mode
            } else {
                error("unrecognized option: %s\n", argv[i]);
                usage(argv[0]);
                return EXIT_FAILURE;
            }
        } else {
            if (mofos_config_get_remote_host(out) == NULL)
                mofos_config_set_remote_host(out, argv[i]);
            else if (mofos_config_get_mountpoint(out) == NULL)
                mofos_config_set_mountpoint(out, argv[i]);
            else {
                error("useless positional arguments: %s\n", argv[i]);
                usage(argv[0]);
                return EXIT_FAILURE;
            }
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    signal_setup();

    if (argc < 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    return do_fuse(argc, argv);
}
