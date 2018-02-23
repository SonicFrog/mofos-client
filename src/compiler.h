#ifndef __DEF_COMPILER_H
#define __DEF_COMPILER_H

#include "util.h"

/*
 * compiler compat layer
 */

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#if __has_attribute(nonnull)
#define NON_NULL(...) __attribute__((nonnull (__VA_ARGS__)))
#else
#define NON_NULL(...)
#endif

#if __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define ALWAYS_INLINE inline
#endif

#define _cleanup_(f) __attribute__((cleanup(f)))
#define _cleanup_free_ _cleanup_(free)
#define _cleanup_close_ _cleanup_(closep)
#define _deprecated_ __attribute__((deprecated))
#define _pure_ __attribute__((pure))
#define _const_ __attribute__((const))

#if __has_builtin(__sync_bool_compare_and_swap)

#define atomic_cmpswp_bool(ptr, old, new) __sync_bool_compare_and_swap(ptr, old, new)
#define atomic_cmpswp(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)

#elif __has_feature(__sync_swap) //This is for clang

#define atomic_cmp_swp(ptr, old, new) __sync_swap(ptr, old, new)
#define atomic_cmpswp_bool(ptr, old, new) (!!atomic_cmp_swp(ptr, old, new))

#else

#define atomic_cmpswp_bool(ptr, old, new) __sync_bool_compare_and_swap(ptr, old, new)
#define atomic_cmpswp(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)

#endif

#endif
