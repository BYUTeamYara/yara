#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <ctype.h>
#include <yara/error.h>
#include <yara/globals.h>
#include <yara/libyara.h>
#include <yara/limits.h>
#include <yara/re.h>
#include <yara/rules.h>
#include <yara/scan.h>
#include <yara/stopwatch.h>
#include <yara/types.h>
#include <yara/utils.h>

#include <hs.h>


typedef struct YR_HS_SCAN_CONTEXT { YR_SCANNER* scanner; char* regex_match; } YR_HS_SCAN_CONTEXT; 
//YR_SCANNER* global_scanner;
//typedef unsigned long long uint64; 
/**
 * This is the function that will be called for each match that occurs. @a ctx
 * is to allow you to have some application-specific state that you will get
 * access to for each match. In this function  we're just going to use it
 * to pass in the pattern that was being searched for so we can print it out.
 */

static int eventHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
    YR_HS_SCAN_CONTEXT * context = (YR_HS_SCAN_CONTEXT *)ctx;
    printf("Match for pattern \"%s\" at offset %llu\n", context->regex_match, to);
    YR_MATCH* new_match=malloc(sizeof(YR_MATCH));
    new_match->base = from;
    new_match->offset = to;
    new_match->match_length = strlen(context->regex_match);
    new_match->data = context->regex_match;

    printf("$%s$\n", context->regex_match);

    
    // YR_SCANNER* scanner = ctx;
    // YR_RULE* tempRule;
    // YR_STRING* tempString;
    // yr_rules_foreach(scanner->rules, tempRule)
    //     {
    //       yr_rule_strings_foreach(tempRule, tempString)
    //       {
    //         printf("\n**%s**\n", tempString->string);
    //         printf("%i", flags);
    //       }
    //     }

    //uint64_t myBase = (uint64_t) from;
    //const uint64_t test = 0;
    int result = ERROR_SUCCESS;
    print_error(result);

    YR_MATCHES* matches_list = malloc(sizeof(YR_MATCH));

    return _yr_scan_add_match_to_list(new_match, matches_list, false);
}

/**
 * Fill a data buffer from the given filename, returning it and filling @a
 * length with its length. Returns NULL on failure.
 */

static char *readInputData(const char *inputFN, unsigned int *length) {
    FILE *f = fopen(inputFN, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: unable to open file \"%s\": %s\n", inputFN,
                strerror(errno));
        return NULL;
    }

    /* We use fseek/ftell to get our data length, in order to keep this example
     * code as portable as possible. */
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }
    long dataLen = ftell(f);
    if (dataLen < 0) {
        fprintf(stderr, "ERROR: ftell() failed: %s\n", strerror(errno));
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "ERROR: unable to seek file \"%s\": %s\n", inputFN,
                strerror(errno));
        fclose(f);
        return NULL;
    }

   /* Hyperscan's hs_scan function accepts length as an unsigned int, so we
     * limit the size of our buffer appropriately. */
    if ((unsigned long)dataLen > UINT_MAX) {
        dataLen = UINT_MAX;
        printf("WARNING: clipping data to %ld bytes\n", dataLen);
    } else if (dataLen == 0) {
        fprintf(stderr, "ERROR: input file \"%s\" is empty\n", inputFN);
        fclose(f);
        return NULL;
    }
    char *inputData = malloc(dataLen);
    if (!inputData) {
        fprintf(stderr, "ERROR: unable to malloc %ld bytes\n", dataLen);
        fclose(f);
        return NULL;
    }

    char *p = inputData;
    size_t bytesLeft = dataLen;
    while (bytesLeft) {
        size_t bytesRead = fread(p, 1, bytesLeft, f);
        bytesLeft -= bytesRead;
        p += bytesRead;
        if (ferror(f) != 0) {
            fprintf(stderr, "ERROR: fread() failed\n");
            free(inputData);
            fclose(f);
            return NULL;
        }
    }

    fclose(f);

    *length = (unsigned int)dataLen;
    return inputData;
}
    


void hs_mpm(const char* regex, char* file, YR_SCANNER* scanner)
{ 
    //Compile the database from regex
    
    struct YR_HS_SCAN_CONTEXT *context=malloc(sizeof(struct YR_HS_SCAN_CONTEXT));
    context->scanner = scanner;
    context->regex_match = regex;

    hs_database_t *database;
    hs_compile_error_t *compile_err;
    if (hs_compile(regex, HS_FLAG_DOTALL, HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to compile pattern \"%s\": %s\n",
                regex, compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }
/* Next, we read the input data file into a buffer. */
    unsigned int length;
    char *inputData = readInputData(file, &length);
    if (!inputData) {
        hs_free_database(database);
        return -1;
    }
    
    //allocate scratch space
    hs_scratch_t *scratch = NULL;
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        fprintf(stderr, "ERROR: Unable to allocate scratch space. Exiting.\n");
        free(inputData);
        hs_free_database(database);
        return -1;
    }

    printf("Scanning %u bytes with Hyperscan\n", length);
    
    //Scan the input using the database
    
    if (hs_scan(database, inputData, length, 0, scratch, eventHandler, context) != HS_SUCCESS) {
    //pass in pointer to pointer for scanner within hs_scan()
        fprintf(stderr, "ERROR: Unable to scan input buffer. Exiting.\n");
        hs_free_scratch(scratch);
        free(inputData);
        hs_free_database(database);
        return -1;
    }

    /* Scanning is complete, any matches have been handled, so now we just
     * clean up and exit.
     */
    hs_free_scratch;
    free(inputData);
    hs_free_database(database);
    return;
}


