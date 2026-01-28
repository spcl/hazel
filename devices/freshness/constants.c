#include <stdatomic.h>
#include <stdbool.h>
#include <spdk/log.h>
#include "constants.h"
#include "hashing.h"

struct freshness_config global_freshness_config = {
    .keep_metadata_fresh = KEEP_METADATA_FRESH,
    .eventual_consistency = EVENTUAL_CONSISTENCY,
    .freshness_check_ratio = FRESHNESS_CHECK_RATIO,
    .freshness_probabilistic_check = FRESHNESS_PROBABILISTIC_CHECK,
    .hashing_cores = HASHER_CORES,
    .initialized = false
};

/* must be called to initialize the freshness global context */
void initialize_global_constants(void)
{
    // Set the random seed for reproducibility
    srand(42); // time(NULL)

    // Parse environment variables to set the freshness configuration
    const char *env;

    if (global_freshness_config.initialized) {
        return; // Already initialized
    }

    /* MARK AS INITIALIZED */
    global_freshness_config.initialized = true;

    /* ENABLE IPSEC */
    global_freshness_config.ipsec = true; // Default to true

    /* FRESHNESS_CHECK_RATIO */
    // env = getenv("FRESHNESS_CHECK_RATIO");
    // if (env) {
    //     char *end;
    //     float v = strtof(env, &end);
    //     if (end != env && v >= -1.0f && v <= 100.0f) {
    //         global_freshness_config.freshness_check_ratio = v;
    //     } else {
    //         SPDK_ERRLOG("Invalid FRESHNESS_CHECK_RATIO '%s', using %f\n",
    //                     env, FRESHNESS_CHECK_RATIO);
    //     }
    // }

    /* KEEP_METADATA_FRESH */
    env = getenv("KEEP_METADATA_FRESH");
    if (env) {
        if (!strcasecmp(env, "1") || !strcasecmp(env, "true")) {
            global_freshness_config.keep_metadata_fresh = true;
        } else if (!strcasecmp(env, "0") || !strcasecmp(env, "false")) {
            global_freshness_config.keep_metadata_fresh = false;
        } else {
            SPDK_ERRLOG("Invalid KEEP_METADATA_FRESH '%s', using %d\n",
                        env, KEEP_METADATA_FRESH);
        }
    }

    /* EVENTUAL_CONSISTENCY */
    env = getenv("EVENTUAL_CONSISTENCY");
    if (env) {
        if (!strcasecmp(env, "1") || !strcasecmp(env, "true")) {
            global_freshness_config.eventual_consistency = true;
        } else if (!strcasecmp(env, "0") || !strcasecmp(env, "false")) {
            global_freshness_config.eventual_consistency = false;
        } else {
            SPDK_ERRLOG("Invalid EVENTUAL_CONSISTENCY '%s', using %d\n",
                        env, EVENTUAL_CONSISTENCY);
        }
    }

    /* FRESHNESS_PROBABILISTIC_CHECK */
    env = getenv("FRESHNESS_PROBABILISTIC_CHECK");
    if (env) {
        if (!strcasecmp(env, "1") || !strcasecmp(env, "true")) {
            global_freshness_config.freshness_probabilistic_check = true;
        } else if (!strcasecmp(env, "0") || !strcasecmp(env, "false")) {
            global_freshness_config.freshness_probabilistic_check = false;
        } else {
            SPDK_ERRLOG("Invalid FRESHNESS_PROBABILISTIC_CHECK '%s', using %d\n",
                        env, FRESHNESS_PROBABILISTIC_CHECK);
        }
    }

    /* HASHER_CORES */
    // env = getenv("HASHER_CORES");
    // if (env) {
    //     char *end;
    //     int v = strtol(env, &end);
    //     if (end != env && v >= 1 && v <= MAX_HASHER_THREADS) {
    //         global_freshness_config.hashing_cores = v;
    //     } else {
    //         SPDK_ERRLOG("Invalid HASHER_CORES '%s', using %d\n",
    //                     env, HASHER_CORES);
    //     }
    // }

    SPDK_NOTICELOG("Freshness constants initialized:\n"
                   "  FRESHNESS_CHECK_RATIO: %d\n"
                   "  KEEP_METADATA_FRESH: %s\n"
                   "  EVENTUAL_CONSISTENCY: %s\n"
                   "  FRESHNESS_PROBABILISTIC_CHECK: %s\n"
                   "  HASHER_CORES: %d\n",
                   global_freshness_config.freshness_check_ratio,
                   global_freshness_config.keep_metadata_fresh ? "true" : "false",
                   global_freshness_config.eventual_consistency ? "true" : "false",
                   global_freshness_config.freshness_probabilistic_check ? "true" : "false",
                   global_freshness_config.hashing_cores);
}