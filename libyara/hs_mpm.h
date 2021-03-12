#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx);

static char *readInputData(const char *inputFN, unsigned int *length);

void hs_mpm(const char* regex, char* file);


