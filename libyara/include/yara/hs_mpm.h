#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara/scanner.h>
#include <yara/rules.h>

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx);

static char *readInputData(const char *inputFN, unsigned int *length);

void hs_mpm(const char* regex, char* file, YR_SCANNER* scanner, YR_RULE* rule);


