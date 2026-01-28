// Deals with the synchronization of write sector_requests and delayed writes
#include "request.h"
#include "spdk/log.h"
#include "spdk/env.h"
#include "vbdev_freshness.h"
#include "spdk/event.h"
#include "stdlib.h"

static request_map_t sector_requests;
static struct spdk_mempool *request_pool;
static struct spdk_mempool *req_list_pool;
struct spdk_thread *request_registry;

void 
initialize_request_registry(void)
{
    if (pthread_spin_init(&sector_requests.lock, PTHREAD_PROCESS_PRIVATE) != 0) goto pool_fail;
    // spdk_spin_init(&sector_requests.lock);
    sector_requests.head = NULL;

    request_pool = spdk_mempool_create("request_pool",
                                       MAX_REQUESTS,
                                       sizeof(request_t),
                                       SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                                       0);
    if (!request_pool) goto pool_fail;

    req_list_pool = spdk_mempool_create("req_list_pool",
                                        MAX_SECTOR_ENTRIES,
                                        sizeof(request_list_t),
                                        SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                                        0);
    if (!req_list_pool) goto pool_fail;

    // Initialize the request registry thread
    struct spdk_cpuset request_cpuset;
    spdk_cpuset_zero(&request_cpuset);
    spdk_cpuset_set_cpu(&request_cpuset, 2, true);
    request_registry = spdk_thread_create("request_registry", &request_cpuset);

    return;

pool_fail:
    // If we reach here, it means we failed to allocate memory for the pools
    SPDK_ERRLOG("Failed to create memory pools.\n");
    spdk_app_stop(-1);
    return; // unreachable, but added to avoid compiler warnings
}

bool
register_request(spdk_msg_fn callback, struct spdk_bdev_io *bdev_io, request_t **request)
{
    // Check if the request is correctly sized
    if (bdev_io->u.bdev.num_blocks > MAX_IO_SIZE) {
        SPDK_ERRLOG("Request size exceeds maximum allowed (%d blocks).\n", MAX_IO_SIZE);
        spdk_app_stop(-1);
        //return false; // unreachable, but added to avoid compiler warnings
    }
    // printf("%p - %ld\n", spdk_get_thread(), spdk_mempool_count(request_pool));
    
    // printf("%ld\n", spdk_mempool_count(request_pool));

    // Create and populate the new request
    request_t *current_request = spdk_mempool_get(request_pool);
    if (!current_request) {
        SPDK_ERRLOG("Failed to allocate memory for sector_requests.\n");
        //return false;
    }
    // if (!current_request) goto memory_fail;
    memset(current_request, 0, sizeof(*current_request));
    *request = current_request; // set the output pointer to the new request

    current_request->bdev_io = bdev_io;
    current_request->callback = callback;
    current_request->thread = spdk_get_thread();
    current_request->start = bdev_io->u.bdev.offset_blocks;
    current_request->end = bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1;
    current_request->num_sectors = bdev_io->u.bdev.num_blocks;
    atomic_store_explicit(&current_request->superblocks, 0, memory_order_relaxed); // initially no superblocks
    current_request->retries = 0; // no retries yet
    current_request->failed = false; // initially not failed
    atomic_store_explicit(&current_request->preprocessed, false, memory_order_relaxed);
    current_request->remaining_checks = 0; 
    current_request->bdev = NULL;
    current_request->ch = NULL;
    current_request->base_ch = NULL;
    current_request->hasher_id = -1;
    current_request->front_sectors = 0;
    current_request->type = (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) ? 1 : 0;
    current_request->superblocks_to_be_preprocessed = 0;
    
    return true;

// memory_fail:
//     // If we reach here, it means we failed to allocate memory for sector_requests or entries
//     SPDK_ERRLOG("Failed to allocate memory for sector_requests.\n");
//     spdk_app_stop(-1);
//     return false; // unreachable, but added to avoid compiler warnings
}

void //bool
schedule_request(void *cb_arg)
{
    // Create and populate the request list entries 
    request_t *request = (request_t *)cb_arg;
    bool appended_to_existing = false; // assume we will append the request
    request_list_t *entries[MAX_IO_SIZE];
    if (spdk_mempool_get_bulk(req_list_pool, (void **)entries, request->num_sectors)) goto memory_fail;

    for (size_t i = 0; i < request->num_sectors; i++) {
        entries[i]->sector = request->start + i;
        entries[i]->head = NULL;
        request->sector_requests[i].request = request;
        request->sector_requests[i].request_data.sector = entries[i]->sector;
    }

    // pthread_spin_lock(&sector_requests.lock);
    // spdk_spin_lock(&sector_requests.lock);
    for (size_t i = 0; i < request->num_sectors; i++) {
        uint64_t sector = entries[i]->sector;
        request_list_t *entry = NULL;

        // find or create the sector entry in the hash
        HASH_FIND(hh, sector_requests.head, &sector, sizeof(sector), entry);
        if (entry == NULL) {
            entry = entries[i]; // use the new entry
            HASH_ADD(hh, sector_requests.head, sector, sizeof(entry->sector), entry);
        } else {
            spdk_mempool_put(req_list_pool, entries[i]); // return the unused entry to the pool
            appended_to_existing = true; // we are appending to an existing request
        }

        // push the new request onto the list
        DL_APPEND(entry->head, &request->sector_requests[i]);
        request->sector_requests[i].bucket_entry = entry; 

        // If we are now at the head for this sector, bump counter
        if (entry->head == &request->sector_requests[i]) {
            request->front_sectors++;
        }
    }
    // pthread_spin_unlock(&sector_requests.lock);
    // spdk_spin_unlock(&sector_requests.lock);
    
    if (!appended_to_existing) {
        // If we are the first request, schedule it immediately
        spdk_thread_send_msg(request->thread, request->callback, request->bdev_io);
    }
    return;// appended_to_existing; // return true if appended, false otherwise

memory_fail:
    // If we reach here, it means we failed to allocate memory for sector_requests or entries
    SPDK_ERRLOG("Failed to allocate memory for sector_requests.\n");
    spdk_app_stop(-1);
    //return false; // unreachable, but added to avoid compiler warnings
}

void
complete_request(void *cb_arg)
{
    request_t *request = (request_t *)cb_arg;
    request_list_t *entry;
    sector_request_t *sector_req = NULL;
    request_t *next_req = NULL;
    scheduling_set_entry_t *scheduling_set = NULL, *scheduling_entry, *tmp;

    scheduling_set_entry_t scheduling_entries[MAX_IO_SIZE];
    request_list_t         *entries_to_free[MAX_IO_SIZE] = {0};
    // pthread_spin_lock(&sector_requests.lock);
    size_t sched_idx = 0;
    // spdk_spin_lock(&sector_requests.lock);

    for (size_t i = 0; i < request->num_sectors; i++) {
        // uint64_t sector = request->start + i;

        // look up the sector
        // HASH_FIND(hh, sector_requests.head, &sector, sizeof(sector), entry);
        // if (entry == NULL) goto search_fail; // not found
        entry = request->sector_requests[i].bucket_entry;
        if (entry == NULL) goto search_fail;

        // find the matching request in the doubly‐linked list; not needed because we only schedule once we are at the beginning of the list!
        // DL_SEARCH_SCALAR(entry->head, sector_req, request, request);
        // if (sector_req == NULL) goto search_fail; // not found
        sector_req = entry->head;
        if (sector_req == NULL) goto search_fail;

        // unlink from list
        if (request != entry->head->request) goto search_fail;
        DL_DELETE(entry->head, sector_req);

        // if that was the last request, remove the hash entry
        if (entry->head == NULL) {
            HASH_DEL(sector_requests.head, entry);
            entries_to_free[i] = entry; // mark for deletion
        } else {
            // there is a new head request for this sector
            next_req = entry->head->request;
            next_req->front_sectors++;

            // add to the scheduling set if the next request is ready, need to only do once
            if (next_req->front_sectors == next_req->num_sectors) {
                scheduling_entries[sched_idx].request = next_req;
                HASH_ADD_PTR(scheduling_set, request, &scheduling_entries[sched_idx]);
                sched_idx++;
            }
        }
    }

    // go throught the scheduling set and schedule the sector_requests
    // HASH_ITER(hh, scheduling_set, scheduling_entry, tmp) {
    //     tmp_request = scheduling_entry->request;
    //     for (size_t i = 0; i < tmp_request->num_sectors; i++) {
    //         uint64_t sector = tmp_request->start + i;
    //         HASH_FIND(hh, sector_requests.head, &sector, sizeof(sector), entry);
    //         if (entry == NULL) goto search_fail;
    //         if (entry->head->request != tmp_request) {
    //             HASH_DEL(scheduling_set, scheduling_entry); // remove from the scheduling set if not the first request
    //             break;
    //         }
    //     }
    // }

    // pthread_spin_unlock(&sector_requests.lock);
    // spdk_spin_unlock(&sector_requests.lock);

    // schedule, and free the request and the entries outside to minimize the lock time
    HASH_ITER(hh, scheduling_set, scheduling_entry, tmp) {
        // printf("[%ld] Scheduling request %p with start %ld and end %ld\n", spdk_get_ticks(), scheduling_entry->request, scheduling_entry->request->start, scheduling_entry->request->end);
        // scheduling_entry->request->thread = request->thread; // set the thread to the original request's thread
        // scheduling_entry->request->base_ch = request->base_ch; // set the base channel to the original request's base channel
        spdk_thread_send_msg(scheduling_entry->request->thread, scheduling_entry->request->callback, scheduling_entry->request->bdev_io);
    }
    for (size_t i = 0; i < request->num_sectors; i++) {
        if (entries_to_free[i]) spdk_mempool_put(req_list_pool, entries_to_free[i]); // return the entry, note this is safe because entry is no longer in the hash map
    }

    delete_request(request);

    return;

search_fail:
    //pthread_spin_unlock(&sector_requests.lock);
    //spdk_spin_unlock(&sector_requests.lock);
    SPDK_ERRLOG("Failed to find request %p in the request map.\n", request);
    spdk_app_stop(-1); // stop the app on error
    return;
}

void
delete_request(request_t *request)
{
    // Put back the request and its associated data
    if (request) {
        spdk_mempool_put(request_pool, request);
    }
}


// TODO: implement the below

// // Initializes the sector_requests map
// void initialize_sector_requests(struct vbdev_freshness *device) {
//     struct request_map *map = (struct request_map *)malloc(sizeof(struct request_map));
//     spdk_spin_init(&map->lock);
//     map->address = 0;
//     device->sector_requests = map;
// }

// // Completes the IO with success
// static void
// instant_complete_io(void *cb_arg)
// {
// 	struct spdk_bdev_io *orig_io = cb_arg;
// 	spdk_bdev_io_complete(orig_io, SPDK_BDEV_IO_STATUS_SUCCESS);
// }

// // Returns if the request was the first one
// bool add_request(struct vbdev_freshness *device, uint64_t address, struct spdk_bdev_io *bdev_io, uint64_t new_IV) {
//     // Prepare all structs
//     struct request_map *map = device->sector_requests;
//     struct request_map *req_map = NULL;
//     struct request_wrapper *req = (struct request *)malloc(sizeof(struct request));
//     req->request = (struct write_request *)malloc(sizeof(struct write_request));
//     req->thread = spdk_get_thread();
//     req->request->address = address;
//     req->request->status = WRITING;
//     req->request->old_IV = 0; // need to fetch from the cache
//     req->request->new_IV = new_IV;
//     req->bdev_io = NULL;

//     // Lock and find the element
//     spdk_spin_lock(&map->lock);
//     HASH_FIND(hh, map, &address, sizeof(uint64_t), req_map);
//     if (!req_map) {
//         req_map = (struct request_map *)malloc(sizeof(struct request_map));
//         req_map->address = address;
//         req_map->current = req;
//         req_map->staged = NULL;
//         HASH_ADD(hh, map, address, sizeof(uint64_t), req_map);
//     } else {
//         req->request->old_IV = req_map->current->request->new_IV;
//         if (req_map->current->request->status == WRITING) {
//             if (req_map->staged) spdk_thread_send_msg(req_map->staged->thread, instant_complete_io, req_map->staged->bdev_io);
//             req_map->staged = req;
//         } else { // Assume WRITTEN = COMPLETED
//             req_map->current = req;
//         }
//     }
//     spdk_spin_unlock(&map->lock);
//     return req_map == NULL;
// }

// void complete_request(struct vbdev_freshness *device, uint64_t address) {
//     struct request_map *map = device->sector_requests;
//     struct request_map *req_map = NULL;
//     spdk_spin_lock(&map->lock);
//     HASH_FIND(hh, map, &address, sizeof(uint64_t), req_map);
//     if (req_map) {
//         req_map->current->request->status = WRITTEN;
//         if (req_map->staged) {
//             if (req_map->current->request->old_IV) req_map->staged->request->old_IV = req_map->current->request->old_IV;
//             free(req_map->current->request);
//             free(req_map->current);
//             req_map->current = req_map->staged;
//             spdk_thread_send_msg(req_map->staged->thread, schedule_write, req_map->staged->bdev_io);
//             req_map->staged = NULL;
//         }
//     } else SPDK_ERRLOG("Request not found\n");
//     spdk_spin_unlock(&map->lock);
// }

// void delete_request(struct vbdev_freshness *device, uint64_t address) {
//     struct request_map *map = device->sector_requests;
//     struct request_map *req_map = NULL;
//     spdk_spin_lock(&map->lock);
//     HASH_FIND(hh, map, &address, sizeof(uint64_t), req_map);
//     if (req_map) {
//         struct request *req, *tmp;
//         list_for_each_entry_safe(req, tmp, &req_map->head, writes) {
//             list_del(&req->writes);
//             free(req);
//         }
//         HASH_DEL(map, req_map);
//         free(req_map);
//     } else SPDK_ERRLOG("Request not found\n");
//     spdk_spin_unlock(&map->lock);
//     // Once completes we need to schedule others that might be in line now and just mark ourselves as done
// }

