#include <assert.h>

#include "debug.h"

#define FUNCTION_NAME_COLOR "\033[0;37m"

#define COLOR_DEBUG_MSG "\033[1;37m"

#define COLOR_DEBUG "\033[0;34m"
#define COLOR_WARN "\033[1;33m"
#define COLOR_ERROR "\033[0;31m"
#define COLOR_FATAL "\033[1;31m"
#define COLOR_DEFAULT "\033[1;37m"

static enum log_level global_level;
static const char* log_colors[] = {
    COLOR_DEFAULT,
    COLOR_DEBUG,
    COLOR_WARN,
    COLOR_ERROR,
    COLOR_FATAL,
};

void
mofos_log_set_level(enum log_level lv)
{
    global_level = lv;
}

void
mofos_log_msg_va(enum log_level level, const char* file,
		 const int line, const char* function,
		 const char* fmt, va_list ap)
{
    assert(LOG_LEVEL_MIN < level && level < LOG_LEVEL_MAX);

    const char* color = log_colors[level];
    if (level < global_level)
        return;

#ifndef NDEBUG
    /* more performance when not a debug build */
    if (level == LOG_LEVEL_DEBUG)
        fprintf(stderr, "%s%s:%d %s", COLOR_DEBUG,
		file, line, COLOR_DEBUG_MSG);
#endif

    fprintf(stderr, "%s%s: %s", FUNCTION_NAME_COLOR, function, color);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");

    fprintf(stderr, COLOR_DEFAULT);
}

void
mofos_log_msg(enum log_level level, const char* file,
	      const int line, const char* function,
	      const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    mofos_log_msg_va(level, file, line, function, fmt, ap);
    va_end(ap);
}
