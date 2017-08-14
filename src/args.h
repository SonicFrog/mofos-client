#ifndef __DEF_ARGS_H
#define __DEF_ARGS_H

enum verbosity {
    NONE, DEBUG, RAW
};

struct mofos_args {
    enum verbosity verbose;
};

#endif
