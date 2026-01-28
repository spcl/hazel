#include "hashing.h"
#include "blake3.h"

void hash(const void *input, void *output, size_t length) {
    // Hash using blake3
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, length);
    blake3_hasher_finalize(&hasher, output, HASH_LENGTH);
}