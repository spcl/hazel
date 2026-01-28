#ifndef HASHING_H
#define HASHING_H

#include <stddef.h>

#define HASH_LENGTH 16 // Length of the hash output in bytes
#define IV_LENGTH 8

/*
* Hashes legth B at location loc.
*/
void hash(const void *input, void *output, size_t length);

#endif