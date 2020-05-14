#pragma once

#include <stdlib.h>
#include <stdio.h>

#define E(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__), exit(1)
#define W(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)

#ifndef NDEBUG
#define L(fmt, ...) log_write("pid%5d %s:%d: " fmt "\n", getpid(), __func__, __LINE__, ##__VA_ARGS__)
void log_write(const char *format, ...);
#else
#define L(fmt, ...)
#endif
