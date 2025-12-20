#ifndef CNETFLOW_LOG_H
#define CNETFLOW_LOG_H

#include <stdio.h>

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
        exit(code); \
    } while(0)

#endif // CNETFLOW_LOG_H
