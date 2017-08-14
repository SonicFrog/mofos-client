#ifndef __DEF_DEBUG_H
#define __DEF_DEBUG_H

#include <errno.h>

#define print(level, fmt, ...) fprintf(stderr, level " %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define warn(fmt, ...) print("WARN", fmt, ##__VA_ARGS__)
#define fatal(fmt, ...) print("FATAL", fmt, ##__VA_ARGS__); exit(1)

#ifndef NDEBUG
#define debug(fmt, ...) print("DEBUG", fmt, ##__VA_ARGS__)
#define debug_multiprint(fmt, ...) print("", fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#define print_ip(ip) (ip) & 0xFF, ((ip) >> 8) & 0xFF, ((ip) >> 16) & 0xFF, ((ip) >> 24) & 0xFF

#define print_errno(fmt, ...) print("SYSCALL", fmt ": %s\n", ##__VA_ARGS__, strerror(errno))

#define unimplemented print("FATAL", "%s is unimplemented!", __FUNCTION__)

#define UNUSED __attribute__((unused))

#endif
