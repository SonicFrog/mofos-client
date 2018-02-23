#ifndef __MOFOS_DEBUG_H
#define __MOFOS_DEBUG_H

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>

#include "compiler.h"

enum log_level {
    LOG_LEVEL_MIN = 0,
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_WARN = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_FATAL = 4,
    LOG_LEVEL_MAX = 5,
};

typedef int (*mofos_printer) (int fd, const char* format, ...);

void mofos_log_msg(enum log_level level, const char* file,
		   const int line, const char* function,
		   const char* fmt, ...);

void mofos_log_msg_va(enum log_level level, const char* file,
                      const int line, const char* function,
                      const char* fmt, va_list ap);

void mofos_log_set_level(enum log_level lv);

#define mofos_strerror() "unknown error"


#define print(level, fmt, ...) mofos_log_msg(level, __FILE__, __LINE__, \
					     __FUNCTION__, fmt, ##__VA_ARGS__)

#define warn(fmt, ...) print(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define error(fmt, ...) print(LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)
#define fatal(fmt, ...) print(LOG_LEVEL_FATAL, fmt, ##__VA_ARGS__); abort()

#ifndef NDEBUG
#define debug(fmt, ...) print(LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#define pgnutls_error(func, rc) debug("error: %s: %s", func, gnutls_strerror(rc))
#define dtls_handle_error(ssl, rc) _dtls_handle_error(ssl, rc, __FUNCTION__, \
                                                      __LINE__)

#define unimplemented print(LOG_LEVEL_FATAL, "%s is unimplemented!", __FUNCTION__)

#endif
