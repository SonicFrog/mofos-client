#include <stdio.h>
#include <stdlib.h>
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

void parse_args(int* argc, char** argv);
void signal_setup();
void handle_signal(int sig);

const char* sig_name_str(int sig)
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
}

void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s <target> <destintation>\n", progname);
}

int do_fuse(int argc, char **argv)
{
    struct fuse_args args = FUSE_ARGS_INIT(argc - 1, argv + 1);
    const char* host = argv[1];

    if (fuse_opt_parse(&args, NULL, NULL, 0) != 0)
    {
        fprintf(stderr, "Fuse couldn't parse arguments!\n");
        exit(1);
    }

    return fuse_main(args.argc, args.argv, &fops, NULL);
}

int main(int argc, char **argv)
{
    signal_setup();

    return do_fuse(argc, argv);
}

void parse_args(int* argc, char** argv)
{
    unimplemented;
    return;
}

void signal_setup()
{
    struct sigaction sa;

    sa.sa_handler = &handle_signal;
    sa.sa_flags = SA_RESTART;

    sigfillset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0)
    {
        fatal("Unable to setup SIGINT handling: %s\n", strerror(errno));
    }

    if (sigaction(SIGUSR1, &sa, NULL) < 0)
    {
        fatal("Unable to setup SIGUSR1 handling: %s\n", strerror(errno));
    }
}

void handle_signal(int sig)
{
    const char* sig_name = sig_name_str(sig);
    sigset_t pending;

    switch (sig)
    {
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
