// freshness_constants.h

#ifndef FRESHNESS_CONSTANTS_H
#define FRESHNESS_CONSTANTS_H

#include <stdatomic.h>
#include <stdbool.h>

/* sizes & defaults */
#define BLOCK_SIZE                     4096
#define METADATA_SIZE                  64
#define INTEGRITY_LENGTH               16
#define IV_LENGTH                      8
#define HASH_LENGTH                    16
#define MAX_IO_SIZE                    64

#define EVENTUAL_CONSISTENCY           true
#define KEEP_METADATA_FRESH            false
#define FRESHNESS_PROBABILISTIC_CHECK  false
#define FRESHNESS_CHECK_RATIO          0.5f

struct freshness_config {
    bool keep_metadata_fresh;
    bool eventual_consistency;
    int  freshness_check_ratio;
    bool freshness_probabilistic_check;
    int  hashing_cores;
    bool initialized;
    bool ipsec;
};
extern struct freshness_config global_freshness_config;

/* must be called to initialize the freshness per-thread context */
void initialize_global_constants(void);

#endif /* FRESHNESS_CONSTANTS_H */
