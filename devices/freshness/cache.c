#include "cache.h"
#include "spdk/log.h"
#include "spdk/event.h"
#include "spdk/env.h"
#include "spdk/thread.h"
#include "pthread.h"

static struct spdk_mempool *cache_request_pool;
struct spdk_thread *cache_registry;

void initialize_cache_registry(struct cache *cache, struct vbdev_freshness *device) {
    // Allocates and initilializes all the necessary structures
    cache->device = device;
    cache_request_pool = spdk_mempool_create("cache_request_pool",
                        MAX_REQUESTS,
                        sizeof(struct cache_request),
                        SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                        0);

    // Initialize LRU
    INIT_LIST_HEAD(&cache->LRU);
    for (int i = 0; i < CACHE_SIZE; i++) {
        structinit(struct cache_entry, entry);
        entry->data = spdk_zmalloc(BLOCK_SIZE + METADATA_SIZE, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
        entry->IV.iov_base = entry->data;
        entry->IV.iov_len = BLOCK_SIZE + METADATA_SIZE;
        entry->status = INVALID;
        entry->remaining_requests = 0;
        INIT_LIST_HEAD(&entry->entries);
        INIT_LIST_HEAD(&entry->writeback_entries);
        INIT_LIST_HEAD(&entry->requests);
        INIT_LIST_HEAD(&entry->writeback_requests);
        list_add_tail(&entry->LRU, &cache->LRU);
        entry->cache = cache;
        entry->hashing = false;
        entry->dirty = false;
        entry->needs_hashing = false;
    }
    
    // Initialize hash maps
    for (int i = 0; i < CACHE_MAP_LENGTH; i++) {
        INIT_LIST_HEAD(&cache->hash_map[i]);
        INIT_LIST_HEAD(&cache->writeback_hash_map[i]);
    }

    // Initialize the cache registry thread
    struct spdk_cpuset cache_cpuset;
    spdk_cpuset_zero(&cache_cpuset);
    spdk_cpuset_set_cpu(&cache_cpuset, 3, true);
    cache_registry = spdk_thread_create("cache_registry", &cache_cpuset);
}   

struct cache_entry *find_element_entries(struct list_head *list, size_t index) {
    // Finds an entry in a double linked list of main cache entries
    struct cache_entry *current;

    // Check existing entries in the list
    list_for_each_entry(current, list, entries) {
        if (current->block_index == index)
            return current;
    }
    
    return NULL; // Not found
}

struct cache_entry *find_writeback_element_entries(struct list_head *list, size_t index) {
    // Finds an entry in a double linked list of writeback entries
    struct cache_entry *current;

    // Check existing entries in the list
    list_for_each_entry(current, list, writeback_entries) {
        if (current->writeback_block_index == index)
            return current;
    }

    return NULL; // Not found
}

void refresh_entry_LRU(struct list_head *list, struct cache_entry *entry) {
    // Pushed the entry to the beginning of the LRU
    list_move(&entry->LRU, list);
}

enum status fetch_entry(struct cache *cache, size_t block_address, struct cache_entry **new_entry) {
    struct cache_entry *entry;
    enum status status;
    while (1) {
        // Pick the LRU tail
        entry = list_entry(cache->LRU.prev, struct cache_entry, LRU);
        status = entry->status; 

        // Check if this entry is evictable
        if (status != PROCESSED && status != INVALID) {
            // Rotate this entry to the front so we don't keep hitting it
            refresh_entry_LRU(&cache->LRU, entry);
        } else {
            break;
        }
    }

    if (!list_empty(&entry->requests)) {
        // This shouldn't happen for PROCESSED/INVALID entries
        SPDK_ERRLOG("Victim entry has pending requests!\n");
        spdk_app_stop(-1);
    }

    // Detach from old hash bucket if it was in use
    *new_entry = entry;
    if (status != INVALID) {
        list_del(&entry->entries);
    }
    
    // Attach to a new hash bucket
    entry->status = FETCHING;
    struct list_head *new_list = &cache->hash_map[block_address % CACHE_MAP_LENGTH];
    list_add(&entry->entries, new_list);

    // Bump to MRU
    refresh_entry_LRU(&cache->LRU, entry);

    return status;
}

// Finds an entry in the cache.
// If the entry is present and not processed, calls the callback with the provided argument.
// If the entry is present and processed, it enqueues the request to serialize the accesses such that locking is not necessary.
// Else fetches the entry and adds it to the scheduling entry list such that on the completion of read, the message can be sent.
void find_or_schedule_entry(void *cb_arg) {
    // Deserialize arguments from the context
    struct cache_request *ctx = (struct cache_request *)cb_arg;
    size_t block_index = ctx->block_index;
    spdk_msg_fn callback = ctx->callback;
    struct cache *cache = ctx->request->bdev->cache;

    // Obtain the cache entry
    struct list_head *list = &cache->hash_map[block_index % CACHE_MAP_LENGTH];
    struct cache_entry *entry = find_element_entries(list, block_index);
    if (entry == NULL) { // Check writeback if entry is not found
        list = &cache->writeback_hash_map[block_index % CACHE_MAP_LENGTH];
        entry = find_writeback_element_entries(list, block_index); 
    }

    if (entry != NULL) {
        // Refresh the entry if found and assign the entry
        refresh_entry_LRU(&cache->LRU, entry);
        ctx->cache_entry = entry;

        // Make sure the entry is still valid
        enum status status = entry->status;
        if ((status != WRITEBACK && entry->block_index != block_index) || 
            (status == WRITEBACK && entry->writeback_block_index != block_index && entry->block_index != block_index)) {
            SPDK_ERRLOG("The entry changed in the middle!\n");
            spdk_app_stop(-1);
        }

        if (status == PROCESSED) {
            // The cache entry is ready, update its status and call the callback
            entry->status = FETCHED;
            spdk_thread_send_msg(ctx->request->thread, callback, ctx);
            return;
        } else if (status == FETCHED) {
            // The cache entry is ready, but someone is currently working on it
            list_add_tail(&ctx->list, &entry->requests);
            return;
        } else if (status == FETCHING || status == WRITEBACK) {
            // The cache is either being fetched or written back
            if (entry->block_index == block_index) {
                // Entry is being fetched so just add to the request list
                list_add_tail(&ctx->list, &entry->requests);
            } else {
                // Entry is being written back, we need to reschedule the write to the current block
                list_add_tail(&ctx->list, &entry->writeback_requests);
            }

            return;
        } else {
            // If you ever hit status = INVALID in the hash-table (which shouldn't happen), bail out
            SPDK_ERRLOG("Unexpected status %d in find_or_schedule_entry()\n", entry->status);
            spdk_app_stop(-1);
        }
    } else {
        // The entry is not found, we need to fetch it
        // First, in the case of eventual consistency, we need to check if we need to do the write of the request
        if (global_freshness_config.eventual_consistency && ctx->request->type == 1) {
            ctx->request->superblocks_to_be_preprocessed--;
            if (ctx->request->superblocks_to_be_preprocessed == 0) {
                // All superblocks have been preprocessed (or are not in the cache), we can schedule the final write
                spdk_thread_send_msg(ctx->request->thread, schedule_final_write, ctx->request->bdev_io);
            }
        }

        // Then, we fetch an evictable entry
        enum status status = fetch_entry(cache, block_index, &entry);
        bool needs_writeback = status != INVALID && entry->dirty;

        // If the entry is not freshly new, we are writing it back
        if (needs_writeback) {
            entry->status = WRITEBACK;
            entry->writeback_block_index = entry->block_index; // Set the previous block index to the current one
            struct list_head *new_list = &cache->writeback_hash_map[entry->writeback_block_index % CACHE_MAP_LENGTH]; 
            list_add(&entry->writeback_entries, new_list); // we add the entry to the writeback list
        }
        
        // Push the request to the new entry
        entry->ch = ctx->request->base_ch;
        entry->block_index = block_index;
        list_add_tail(&ctx->list, &entry->requests);
        ctx->cache_entry = entry;

        if (needs_writeback) {
            // Writeback the entry in case it is not new on the IO thread
            spdk_thread_send_msg(ctx->request->thread, schedule_writeback, entry);
        } else {
            // Call the callback directly
            spdk_thread_send_msg(ctx->request->thread, schedule_fetch_read, entry);
        }
    }
}

void schedule_writeback(void *cb_arg) {
    // Conduct the writeback on the IO thread
    struct cache_entry *entry = (struct cache_entry *)cb_arg;
    int rc = spdk_bdev_writev_blocks(entry->cache->device->base_desc, entry->ch,
                                     &entry->IV, 1,
                                     entry->writeback_block_index, 1,
                                     finish_writeback_remote, entry);
    if (rc != 0) {
        SPDK_ERRLOG("Unable to writeback the cache!\n");
        spdk_app_stop(-1);
    }
}

void finish_writeback_remote(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    // Complete the writeback on the IO thread
    if (!success) {
        SPDK_ERRLOG("Unable to writeback the cache!\n");
        spdk_app_stop(-1);
    }
    if (bdev_io != NULL) {
        spdk_bdev_free_io(bdev_io);
    }

    // Let the cache thread finish setting up the entry
    spdk_thread_send_msg(cache_registry, finish_writeback, cb_arg);
}

void finish_writeback(void *cb_arg) {
    struct cache_entry *entry = (struct cache_entry *)cb_arg;

    // Modify the entry to be used for fetching
    entry->writeback_block_index = entry->block_index; // Reset the previous block index
    entry->status = FETCHING; // The entry is now fetching

    // Remove the writeback entry from the writeback hash map
    list_del(&entry->writeback_entries);

    // Reschedule potential writeback requests
    struct cache_request *request, *temp;
    list_for_each_entry_safe(request, temp, &entry->writeback_requests, list) {
        list_del(&request->list);
        find_or_schedule_entry(request);
    }

    // Continue to the read on the IO thread
    request = list_entry(entry->requests.next, struct cache_request, list);
    spdk_thread_send_msg(request->request->thread, schedule_fetch_read, entry);
}

void schedule_fetch_read(void *cb_arg) {
    // Conduct the read on the IO thread
    struct cache_entry *entry = (struct cache_entry *)cb_arg;
    int rc = spdk_bdev_readv_blocks(entry->cache->device->base_desc, entry->ch,
                                    &entry->IV, 1,
                                    entry->block_index, 1,
                                    complete_fetch_entry_remote, entry);
    if (rc != 0) {
        SPDK_ERRLOG("Unable to read IVs!\n");
        spdk_app_stop(-1);
    }
}

void complete_fetch_entry_remote(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    // Complete the read on the IO thread
    if (!success) {
        SPDK_ERRLOG("Unable to writeback the cache!\n");
        spdk_app_stop(-1);
    }
    if (bdev_io != NULL) {
        spdk_bdev_free_io(bdev_io);
    }
    
    // Let the cache thread complete the fetch in the cache
    spdk_thread_send_msg(cache_registry, complete_fetch_entry, cb_arg);
}

void complete_fetch_entry(void *cb_arg) {
    struct cache_entry *new_entry = (struct cache_entry *)cb_arg;

    // Verify the contents of the block
    size_t length = IV_LENGTH * MIN(new_entry->cache->device->hashing_tree.elements_per_level[0] - new_entry->block_index * LEAF_BRANCHING_FACTOR, LEAF_BRANCHING_FACTOR);
    hash(new_entry->data, new_entry->data + BLOCK_SIZE + INTEGRITY_LENGTH, length); 
    if (memcmp(new_entry->data + BLOCK_SIZE + INTEGRITY_LENGTH, new_entry->cache->device->hashing_tree.hashes + new_entry->block_index, HASH_LENGTH)) {
        // The hash does not match
        SPDK_ERRLOG("Unable to verify the fetched hash at %ld!\n", new_entry->block_index);
        spdk_app_stop(-1);
    }

    // Change status of the block and schedule the last request as a callback
    new_entry->status = FETCHED;
    new_entry->block_IVs = length / IV_LENGTH;
    new_entry->dirty = false;
    struct cache_request *cache_request = list_entry(new_entry->requests.next, struct cache_request, list);
    list_del(&cache_request->list);
    spdk_thread_send_msg(cache_request->request->thread, cache_request->callback, cache_request);
}

void request_cache_block(size_t block_index, request_t *request, spdk_msg_fn callback) {
    // Allocates the cache request for the given IO thread
    struct cache_request *cache_request;
    cache_request = spdk_mempool_get(cache_request_pool);
    if (!cache_request) {
        SPDK_ERRLOG("cache_request_pool exhausted\n");
        spdk_app_stop(-1);
    }
    cache_request->block_index = block_index;
    cache_request->callback = callback;
    cache_request->request = request;
    spdk_thread_send_msg(cache_registry, find_or_schedule_entry, cache_request);
}

void complete_cache_request(struct cache_request *request) {
    // Completes the cache request by calling the cache thread to finish it
    spdk_thread_send_msg(cache_registry, complete_cache_entry, request); 
}

void complete_cache_entry(void *cb_arg) {
    // Completes the cache request by deallocating it and scheduling the next one in the queue if there's one (otherwise scheduling the hashing)
    struct cache_request *request = (struct cache_request *)cb_arg;
    struct cache_entry *entry = request->cache_entry;
    spdk_mempool_put(cache_request_pool, request);
    if (request->request->type == 1) {
        entry->dirty = true;
        entry->needs_hashing = true;
    }

    if (list_empty(&entry->requests)) {
        if (!entry->needs_hashing) {
            // Mark the entry as processed if not dirty
            entry->status = PROCESSED;
        } else {
            // Schedule hashing
            entry->hashing = true;
            schedule_hashing_task(entry);
        }
    } else {
        struct cache_request *next_request = list_entry(entry->requests.next, struct cache_request, list);
        list_del(&next_request->list);
        spdk_thread_send_msg(next_request->request->thread, next_request->callback, next_request);
    }
}

void complete_hashing(void *cb_arg) {
    // Completes the hashing of the cache entry and schedules the next request if there's one
    struct cache_entry *entry = (struct cache_entry *)cb_arg;
    entry->hashing = false;
    entry->needs_hashing = false;

    if (list_empty(&entry->requests)) {
        entry->status = PROCESSED;
    } else {
        struct cache_request *next_request = list_entry(entry->requests.next, struct cache_request, list);
        list_del(&next_request->list);
        spdk_thread_send_msg(next_request->request->thread, next_request->callback, next_request);
    }
}