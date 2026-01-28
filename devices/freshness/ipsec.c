/*
NOTE: THIS IS MEANT TO SIMULATE IPSEC FUNCTIONALITY AND IS NOT A COMPLETE IMPLEMENTATION.

This code is not a complete implementation of IPsec but provides a basic structure for handling windowed
send and receive counters, which can be used in an IPsec-like context to estimate the performance cost!

Key refreshment, initialization, and counters per connection are not implemented here.
Note that per connection counters have negligible O(1) lookup overhead as they don't need to be atomic.
*/

#include <stdio.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <spdk/log.h>
#include "ipsec.h"
#include "hashing.h"
#include "spdk/event.h"

_Atomic uint64_t ipsec_send_counter = 0;
_Atomic uint64_t ipsec_recv_counter = 0;

uint64_t ipsec_get_send_counter(void) {
    return atomic_fetch_add(&ipsec_send_counter, 1);
}

void ipsec_authenticate_send(uint8_t *source) {
    uint8_t computed_hash[NETWORK_FRESHNESS_TAG_SIZE];
    hash(source, computed_hash, IV_LENGTH + NETWORK_FRESHNESS_PACKET_SIZE);
    memcpy(source + IV_LENGTH + NETWORK_FRESHNESS_PACKET_SIZE, computed_hash, NETWORK_FRESHNESS_TAG_SIZE);
}

uint64_t atomic_max(_Atomic uint64_t *counter, uint64_t value) {
    uint64_t current = atomic_load(counter);
    while (value > current) {
        if (atomic_compare_exchange_weak(counter, &current, value)) {
            return value;
        }
    }
    return current;
}

bool ipsec_verify_recv_hash(uint8_t *source) {
    uint8_t computed_hash[NETWORK_FRESHNESS_TAG_SIZE];
    uint64_t packet_count;
    memcpy(&packet_count, source + IV_LENGTH, NETWORK_FRESHNESS_PACKET_SIZE);
    hash(source, computed_hash, IV_LENGTH + NETWORK_FRESHNESS_PACKET_SIZE);
    bool result = memcmp(computed_hash, source + IV_LENGTH + NETWORK_FRESHNESS_PACKET_SIZE, NETWORK_FRESHNESS_TAG_SIZE) == 0;
    if (!result) {
        SPDK_ERRLOG("IPsec hash verification failed!\n");
        spdk_app_stop(-1);
    }
    return result;
}

bool ipsec_verify_recv_counter(uint64_t value) {
    uint64_t current = atomic_load(&ipsec_recv_counter);
    if (value < current - IPSEC_MAX_WINDOW_SIZE || value > current + IPSEC_MAX_WINDOW_SIZE) {
        // NOTE: in theory we should fail here but for that we need initial sync with the remote host to exchange the initial counters; for simplicity we will just ignore the out-of-window values
        // SPDK_NOTICELOG("IPsec received out of window counter, got %zu, with window %zu-%zu\n", value, current - IPSEC_MAX_WINDOW_SIZE, current + IPSEC_MAX_WINDOW_SIZE);
        // spdk_app_stop(-1);
        // return false;
    }
    atomic_max(&ipsec_recv_counter, value);
    return true;
}