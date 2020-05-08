#pragma once

#include <stdlib.h>
#include <stdio.h>

#define E(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__), exit(1)
#define W(fmt, ...) fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
