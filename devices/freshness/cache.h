#ifndef CACHING_H
#define CACHING_H

#include "hashing.h"
#include "vbdev_freshness.h"
#include "spdk/thread.h"
#include "list.h"
#include "spdk/barrier.h"

#define CACHE_MAP_LENGTH 10000
#define CACHE_SIZE 5000 // note this is the total number of entries (BLOCK sized ones) the cache holds
#define NUMBER_OF_RETRIES 3

#define structinit(type, name) type *name = (type *)calloc(1, sizeof(type));

extern void schedule_final_write(void *arg);

enum status {
    INVALID,
    FETCHING,
    FETCHED,
    WRITEBACK,
    PROCESSED
};

struct cache {
    struct vbdev_freshness *device; // Needed to be able to initialize and schedule the reads/writes from/to device
    struct list_head LRU;
    struct list_head hash_map[CACHE_MAP_LENGTH];
    struct list_head writeback_hash_map[CACHE_MAP_LENGTH];
    struct spdk_spinlock lock;
};
void initialize_cache_registry(struct cache *, struct vbdev_freshness *);

struct metadata {
	uint8_t		auth_tag[INTEGRITY_LENGTH];
	uint64_t	IV;
    uint8_t     freshness[HASH_LENGTH]; // Either network or storage freshness hash
    uint8_t     MAC[HASH_LENGTH]; // The MAC hash of the freshness hash
    uint8_t     padding[METADATA_SIZE - INTEGRITY_LENGTH - sizeof(uint64_t) - 2*HASH_LENGTH]; // Padding to align the IVs and hashes to METADATA_SIZE
};
_Static_assert(sizeof(struct metadata) == METADATA_SIZE, "struct metadata must be exactly METADATA_SIZE bytes");

struct cache_entry {
    uint8_t *data;
    struct iovec IV;
    size_t block_index; // Note hash index is exactly the same
    size_t writeback_block_index; // Used during the writeback to know which block to write next
    struct spdk_io_channel *ch; // The channel used for reading and writing for this entry

    // After fetching we call all the requests in the request list
    enum status status;
    struct list_head requests;
    struct list_head writeback_requests;
    size_t remaining_requests;

    // For the navigation in the hash map and LRU lists
    struct list_head entries; 
    struct list_head writeback_entries; // Used to keep the previous block index in the writeback
    struct list_head LRU;
    struct cache     *cache;
    size_t block_IVs;    // number of IVs in the block being updated

    // For the hashing
    bool needs_hashing; // indicates whether the entry needs to be hashed
    bool hashing; // indicates whether the entry is being hashed currently
    bool dirty; // indicates whether the entry has been modified and needs to be hashed and written back
};

struct cache_request {
    struct list_head list;
    request_t *request;
    size_t block_index;
    spdk_msg_fn callback;
    struct cache_entry *cache_entry;
};

// Finds an entry in the cache.
// If the entry is present and not processed, calls the callback with the provided argument.
// If the entry is present and processed, it enqueues the request to serialize the accesses such that locking is not necessary.
// Else fetches the entry and adds it to the scheduling entry list such that on the completion of read, the message can be sent.
void find_or_schedule_entry(void *cb_arg);

struct cache_entry *find_element_entries(struct list_head *list, size_t index);
struct cache_entry *find_writeback_element_entries(struct list_head *list, size_t index);
void refresh_entry_LRU(struct list_head *list, struct cache_entry *entry);
enum status fetch_entry(struct cache *cache, size_t block_address, struct cache_entry **new_entry);
void schedule_writeback(void *cb_arg);
void finish_writeback_remote(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
void finish_writeback(void *cb_arg);
void schedule_fetch_read(void *cb_arg);
void complete_fetch_entry_remote(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
void complete_fetch_entry(void *cb_arg);
void request_cache_block(size_t block_index, request_t *request, spdk_msg_fn callback);
void complete_cache_request(struct cache_request *request);
void complete_cache_entry(void *cb_arg);
void complete_hashing(void *cb_arg);

#endif