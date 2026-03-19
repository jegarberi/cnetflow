#ifndef CNETFLOW_LOG_H
#define CNETFLOW_LOG_H

#include <stdio.h>
#include <stdlib.h>

#if defined(__STDC_NO_THREADS__) || !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#if defined(__GNUC__) || defined(__clang__)
#define THREAD_LOCAL __thread
#elif defined(_MSC_VER)
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL
#endif
#else
#include <threads.h>
#define THREAD_LOCAL thread_local
#endif

// Debug logging macros - controlled by ENABLE_LOGGING (selectable via CMake)
#if defined(ENABLE_LOGGING)
    #define LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
    #define LOG_INFO(...)  fprintf(stderr, __VA_ARGS__)
    #define LOG_DEBUG(...) fprintf(stderr, __VA_ARGS__)
#else
    #define LOG_ERROR(...) do {} while(0)
    #define LOG_INFO(...)  do {} while(0)
    #define LOG_DEBUG(...) do {} while(0)
#endif

#define EXIT_WITH_MSG(code, ...) \
    do { \
        fprintf(stdout, "EXIT: " __VA_ARGS__); \
        fprintf(stderr, "EXIT: " __VA_ARGS__); \
        fflush(stdout); \
        fflush(stderr); \
        exit(code); \
    } while(0)

#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#endif // CNETFLOW_LOG_H
