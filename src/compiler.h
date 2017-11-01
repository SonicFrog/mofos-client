#ifndef __DEF_COMPILER_H
#define __DEF_COMPILER_H

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

#if __has_attribute(unused)
// compiler will spit out a gazillion errors but well...
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif

#if __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#else
#define ALWAYS_INLINE inline
#endif

#if __has_builtin(__sync_bool_compare_and_swap)

#define atomic_cmpswp_bool(ptr, old, new) __sync_bool_compare_and_swap(ptr, old, new)
#define atomic_cmpswp(ptr, old, new) __sync_val_compare_and_swap(ptr, old, new)

#elif __has_feature(__sync_swap) //This is for clang

#define atomic_cmp_swp(ptr, old, new) __sync_swap(ptr, old, new)
#define atomic_cmpswp_bool(ptr, old, new) (!!atomic_cmp_swp(ptr, old, new))

#else
#error You compiler needs either __sync_swap or __sync_bool_compare_and_swap
#endif

#endif
