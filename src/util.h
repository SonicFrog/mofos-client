/*
 * Copyright © 2008 Kristian Høgsberg
 * Copyright © 2013-2015 Red Hat, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting documentation, and
 * that the name of the copyright holders not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  The copyright holders make no representations
 * about the suitability of this software for any purpose.  It is provided "as
 * is" without express or implied warranty.
 *
 * THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
 * DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#ifndef __MOFOS_UTIL_H
#define __MOFOS_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * This list data structure is a verbatim copy from wayland-util.h from the
 * Wayland project; except that wl_ prefix has been removed.
 */

struct list {
    struct list *prev;
    struct list *next;
};

void list_init(struct list *list);
void list_insert(struct list *list, struct list *elm);
void list_remove(struct list *elm);
int list_empty(const struct list *list);

#ifdef __GNUC__
#define container_of(ptr, sample, member)                               \
    (__typeof__(sample))((char *)(ptr)  -                               \
                         ((char *)&(sample)->member - (char *)(sample)))
#else
#define container_of(ptr, sample, member)                       \
    (void *)((char *)(ptr)      -                               \
             ((char *)&(sample)->member - (char *)(sample)))
#endif


#define list_for_each(pos, head, member)                                \
    for (pos = 0, pos = container_of((head)->next, pos, member);        \
         &pos->member != (head);                                        \
         pos = container_of(pos->member.next, pos, member))

#define list_for_each_safe(pos, tmp, head, member)                      \
    for (pos = 0, tmp = 0,                                              \
             pos = container_of((head)->next, pos, member),             \
             tmp = container_of((pos)->member.next, tmp, member);       \
         &pos->member != (head);                                        \
         pos = tmp,                                                     \
             tmp = container_of(pos->member.next, tmp, member))

void closep(int *fd);

static inline char*
strncpy_safe(char *dest, const char *src, size_t n)
{
    strncpy(dest, src, n);
    dest[n - 1] = '\0';
    return dest;
}

static inline void *
zalloc(size_t size)
{
    void *p = calloc(1, size);

    if (!p)
        abort();
    return p;
}

/**
 * returns NULL if str is NULL, otherwise guarantees a successful strdup.
 */
static inline char *
strdup_safe(const char *str)
{
    char *s;

    if (!str)
        return NULL;

    s = strdup(str);
    if (!s)
        abort();

    return s;
}

bool
streq(const char* one, const char* two);

__attribute__((unused))
static void
freep(void** p)
{
    if (!p || !*p)
	return;

    free(*p);
    *p = NULL;
}

__attribute__((unused)) static inline int
snprintf_safe(char *buf, size_t n, const char *fmt, ...)
{
    va_list args;
    int rc;

    va_start(args, fmt);
    rc = vsnprintf(buf, n, fmt, args);
    va_end(args);

    if (rc < 0 || n < (size_t)rc)
        abort();

    return rc;
}

#define sprintf_safe(buf, fmt, ...)                             \
    snprintf_safe(buf, ARRAY_LENGTH(buf), fmt, __VA_ARGS__)

__attribute__((format(printf, 1, 2)))
static inline void *
asprintf_safe(const char *fmt, ...)
{
    va_list args;
    int rc;
    char *result;

    va_start(args, fmt);
    rc = vasprintf(&result, fmt, args);
    va_end(args);

    if (rc < 0)
        abort();

    return result;
}

__attribute__((format(printf, 2, 3)))
static inline int
xasprintf(char **strp, const char *fmt, ...)
{
    int rc = 0;
    va_list args;

    va_start(args, fmt);
    rc = vasprintf(strp, fmt, args);
    va_end(args);
    if ((rc == -1) && strp)
        *strp = NULL;

    return rc;
}

#endif /* __MOFOS_UTIL_H */
