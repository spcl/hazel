#include "hashing.h"
#include "spdk/stdinc.h"
#include "spdk/log.h"
#include "spdk/thread.h"
#include "spdk/event.h"
#include "spdk/bdev.h"
#include "spdk/env.h"
#include "spdk/string.h"
#include "math.h"
#include "spdk/bdev_module.h"
#include "blake3.h"
#include "numa.h"
#include <sys/time.h>
#include "cache.h"

static hasher_arg_t hasher_args[MAX_HASHER_THREADS];
static pthread_t hasher_threads[MAX_HASHER_THREADS];
static struct spdk_mempool *task_pools[MAX_HASHER_THREADS];
static struct spdk_ring *rings[MAX_HASHER_THREADS];
static struct spdk_mempool *node_update_pool;
static atomic_int scheduled_thread;

size_t create_hash_tree(struct tree *tree, size_t number_leaves) {
    SPDK_NOTICELOG("Initializing Tree\n");
    SPDK_NOTICELOG("Registered tree for %ld blocks\n", number_leaves);

    // Figure out how much free space without the IV cache we have
    tree->elements_per_level = (uint64_t *)calloc(100, sizeof(uint64_t));
    tree->elements_per_level[0] = number_leaves - ceil(number_leaves / ((double)LEAF_BRANCHING_FACTOR + 1)); // Total = x + x/512 as total is split between the cache and data
    tree->elements_per_level[1] = ceil(tree->elements_per_level[0] / (double)LEAF_BRANCHING_FACTOR);
    SPDK_NOTICELOG("IV cache takes %ld blocks\n", tree->elements_per_level[1]);

    // Initialize the structure of the tree and count elements
    tree->number_levels = ceil(log(tree->elements_per_level[1]) / log(TREE_BRANCHING_FACTOR)) + 2;
    SPDK_NOTICELOG("-> %ld levels\n", tree->number_levels);
    SPDK_NOTICELOG("-> 0: %ld\n", tree->elements_per_level[0]);
    uint64_t total_size = 0;
    SPDK_NOTICELOG("-> 1: %ld\n", tree->elements_per_level[1]);
    total_size += tree->elements_per_level[1];
    for (size_t i = 2; i < tree->number_levels; i++) {
        tree->elements_per_level[i] = ceil(tree->elements_per_level[i-1] / (double)TREE_BRANCHING_FACTOR);
        SPDK_NOTICELOG("-> %ld: %ld\n", i, tree->elements_per_level[i]);
        total_size += tree->elements_per_level[i];
    }
    SPDK_NOTICELOG("Total size of the tree: %ld (~%.4f MB)\n", total_size, total_size * HASH_LENGTH / pow(10, 6));
    tree->data_start = number_leaves - tree->elements_per_level[0];
    SPDK_NOTICELOG("Data starting at: %ld\n", tree->data_start);

    // Allocate the hash space, the locks, and the request updates
    tree->hashes = spdk_zmalloc(sizeof(struct hash) * total_size, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
    if (tree->hashes == NULL) {
        SPDK_ERRLOG("spdk_zmalloc(tree->hashes) failed: %s\n", spdk_strerror(errno));
        exit(1);
    }
    tree->locks = spdk_zmalloc(sizeof(atomic_flag) * total_size, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
    if (tree->locks == NULL) {
        SPDK_ERRLOG("spdk_zmalloc(tree->locks) failed: %s\n", spdk_strerror(errno));
        exit(1);
    }
    tree->updates = spdk_zmalloc(sizeof(struct node_update *) * total_size, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
    if (tree->updates == NULL) {
        SPDK_ERRLOG("spdk_zmalloc(tree->updates) failed: %s\n", spdk_strerror(errno));
        exit(1);
    }

    // Initialize all of the locks
    for (size_t i = 0; i < total_size; i++) {
        atomic_flag_clear_explicit(tree->locks + i, memory_order_release);
    }

    // Initialize the next sequence number
    atomic_store_explicit(&tree->next_sequence_number, 1, memory_order_relaxed); // TODO: would need to actually read from memory

    // Check for allocation failure
    if (tree->locks == NULL || tree->hashes == NULL) {
        SPDK_ERRLOG("Failed to allocate the tree or semaphors.\n");
        spdk_app_stop(-1);
    }

    return tree->elements_per_level[1];
}

void initialize_tree(struct tree *tree, struct spdk_bdev_desc *base_desc, struct spdk_io_channel *channel) {
    // Schedule the first reads that will fill in the hash tree
    struct device *dev = (struct device *)malloc(sizeof(struct device));
    struct hash_task *task = (struct hash_task *)malloc(sizeof(struct hash_task));
    dev->desc = base_desc;
    dev->tree = tree;
    dev->initialization_ch = channel;
    task->data = (struct iovec *)malloc(sizeof(struct iovec));
    task->data->iov_base = (struct hash *)spdk_malloc(BLOCK_SIZE + METADATA_SIZE, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
    task->data->iov_len = BLOCK_SIZE + METADATA_SIZE;
    task->dev = dev;
    int rc = spdk_bdev_readv_blocks_ext(dev->desc, dev->initialization_ch,
                                        task->data, 1,
                                        0, 1,
                                        check_initialized, task,
                                        NULL);
    if (rc != 0) {
        SPDK_ERRLOG("Failed to submit initialization reads.\n");
        spdk_app_stop(-1);
    }
    SPDK_NOTICELOG("Started initialization read sequence\n");
}

void check_initialized(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    struct hash_task *h_task = (struct hash_task *)cb_arg;
    if (!success) {
        SPDK_ERRLOG("Failed with checking the initilization.\n");
        spdk_app_stop(-1);
    }

    // Check if zeroth buffer is empty
    struct task *task = (struct task*)malloc(sizeof(struct task));
    // if (!memcmp(h_task->data->iov_base, h_task->data->iov_base + 1, BLOCK_SIZE - sizeof(struct hash))) {
        // Schedule leaf initialization if buffer is zero
        task->number_tasks = h_task->dev->tree->elements_per_level[1];
        SPDK_NOTICELOG("Detected uninitialized tree; initializing %d leaf hashes\n", task->number_tasks);

        // Read data with multiple running subtasks
        for (int i = 0; i < PARALLEL_INITILIZATION_TASKS; i++) {
            struct hash_task *subtask = (struct hash_task *)malloc(sizeof(struct hash_task));
            subtask->data = (struct iovec *)malloc(sizeof(struct iovec));
            subtask->data->iov_len = (BLOCK_SIZE + METADATA_SIZE) * LEAF_BRANCHING_FACTOR;
            subtask->data->iov_base = (struct uint8_t *)spdk_malloc(subtask->data->iov_len, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
            subtask->IVs = (struct iovec *)malloc(sizeof(struct iovec));
            subtask->IVs->iov_len = LEAF_BRANCHING_FACTOR * IV_LENGTH + METADATA_SIZE;
            subtask->IVs->iov_base = (struct uint8_t *)spdk_malloc(subtask->IVs->iov_len, 0, NULL, 0, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
            subtask->offset = i;
            subtask->overall_task = task;
            subtask->dev = h_task->dev;

            // Check if you are at the end and should read less than LEAF_BRANCHING_FACTOR
            uint64_t offset = i * LEAF_BRANCHING_FACTOR + subtask->dev->tree->data_start;
            if (offset >= subtask->dev->tree->elements_per_level[0] + subtask->dev->tree->data_start) {
                free_task(subtask);
                break;
            }

            uint64_t length = MIN(subtask->dev->tree->elements_per_level[0] + subtask->dev->tree->data_start - offset, LEAF_BRANCHING_FACTOR);
            subtask->length = length;
            // printf("Using channel %p and desc %p\n", h_task->dev->initialization_ch, h_task->dev->desc);
            int rc = spdk_bdev_readv_blocks_ext(h_task->dev->desc, h_task->dev->initialization_ch,
                                                subtask->data, 1,
                                                offset, length,
                                                progress_leaf_initialization, subtask,
                                                NULL);
            if (rc != 0) {
                SPDK_ERRLOG("Failed to submit initialization reads.\n");
                spdk_app_stop(-1);
            }
        }
    // } else {
    //     SPDK_NOTICELOG("Detected existing freshness setup\n");
        // Read the remainder of the IV SSD to memory and initialize the tree as a callback
        // TODO: FINISH reading and hashing the device
        // uint64_t block = ceil(h_task->dev->tree->elements_per_level[1] / PARALLEL_INITILIZATION_TASKS);
        // for (int i = 0; i < PARALLEL_INITILIZATION_TASKS; i++) {
        //     struct hash_task *subtask = (struct hash_task *)malloc(sizeof(struct hash_task));
        //     subtask->overall_task = task;
        //     subtask->dev = h_task->dev;
        //     subtask->data = (struct iovec *)malloc(sizeof(struct iovec));
        //     subtask->data->iov_len = block * (BLOCK_SIZE + METADATA_SIZE);
        //     subtask->data->iov_base = subtask->dev->tree->hashes + i * block;

        //     // Check if you are at the end and should read less than LEAF_BRANCHING_FACTOR
        //     uint64_t offset = i * LEAF_BRANCHING_FACTOR + subtask->dev->tree->data_start;
        //     uint64_t length = MIN(subtask->dev->tree->elements_per_level[0] - offset, LEAF_BRANCHING_FACTOR);
        //     int rc = spdk_bdev_readv_blocks_ext(h_task->dev->desc, h_task->dev->initialization_ch,
        //                                         subtask->data, 1,
        //                                         offset, length,
        //                                         progress_leaf_initialization, subtask,
        //                                         NULL);
        //     if (rc != 0) {
        //         SPDK_ERRLOG("Failed to submit initialization reads.\n");
        //         spdk_app_stop(-1);
        //     }
        // }
        // As callback for the whole task use tree initilization

    // }

    spdk_free(h_task->data->iov_base);
    free(h_task->data);
    free(h_task);
    spdk_bdev_free_io(bdev_io);
}

void progress_leaf_initialization(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    struct hash_task *task = (struct hash_task *)cb_arg;
    spdk_bdev_free_io(bdev_io);
    if (!success) {
        SPDK_ERRLOG("Failed with initilization reads.\n");
        spdk_app_stop(-1);
    }
    
    // Otherwise copy the IVs to a temporary buffer, hash the buffer, output the hash to the tree, write the temporary buffer to the SSD cache, and checks if more tasks should be done
    for (size_t i = 0; i < task->length; i++) {
        // SPDK_NOTICELOG("Read metadata: %s\n", hexdump(task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE, METADATA_SIZE));
        memcpy(task->IVs->iov_base + i * IV_LENGTH, task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH, IV_LENGTH);
        // SPDK_NOTICELOG("Copied to: %s\n", hexdump(task->IVs->iov_base + i * IV_LENGTH, IV_LENGTH));
    }
    // memcpy(task->data->iov_base + BLOCK_SIZE, &task->length, sizeof(task->length)); // save also task length for later, is it really needed????

    hash(task->IVs->iov_base, task->dev->tree->hashes + task->offset, task->length * IV_LENGTH);
    // SPDK_NOTICELOG("Hashing task with offset %d and length %d: %s", task->offset, task->length, hexdump(task->dev->tree->hashes + task->offset, HASH_LENGTH));

    // Write back the read IVs to the SSD cache once all are initialized
    // SPDK_NOTICELOG("Writing back the IVs: %s\n", hexdump(task->IVs->iov_base, task->length * IV_LENGTH));
    int rc = spdk_bdev_writev_blocks_ext(task->dev->desc, task->dev->initialization_ch,
                                         task->IVs, 1,
                                         task->offset, 1,
                                         update_metadata_cache, task,
                                         NULL);
    if (rc != 0) {
        SPDK_ERRLOG("Failed with writing back IVs %d.\n", rc);
        spdk_app_stop(-1);
    }
}

void update_metadata_cache(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    struct hash_task *task = (struct hash_task *)cb_arg;
    spdk_bdev_free_io(bdev_io);
    if (!success) {
        SPDK_ERRLOG("Failed with writing back IVs %d.\n", success);
        spdk_app_stop(-1);
    }

    // Update the metadata cache of all the blocks and authenticate them
    for (size_t i = 0; i < task->length; i++) {
        // SPDK_NOTICELOG("Copying to %d: %s", i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH, hexdump(task->dev->tree->hashes + task->offset, HASH_LENGTH));
        memcpy(task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH, task->dev->tree->hashes + task->offset, HASH_LENGTH);
        hash(task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH, task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH + HASH_LENGTH, IV_LENGTH + HASH_LENGTH);
        // SPDK_NOTICELOG("Cached the parent as: %s\n", hexdump(task->data->iov_base + i * (BLOCK_SIZE + METADATA_SIZE) + BLOCK_SIZE + INTEGRITY_LENGTH, IV_LENGTH + 2 * HASH_LENGTH));
    }
    // SPDK_NOTICELOG("Writing back %d blocks at offset %d: %s", task->length, task->offset * LEAF_BRANCHING_FACTOR + task->dev->tree->data_start, hexdump(task->data->iov_base, task->data->iov_len));
    int rc = spdk_bdev_writev_blocks_ext(task->dev->desc, task->dev->initialization_ch,
                                     task->data, 1,
                                     task->offset * LEAF_BRANCHING_FACTOR + task->dev->tree->data_start, task->length,
                                     reschedule_leaf_initialization, task,
                                     NULL);
    if (rc != 0) {
        SPDK_ERRLOG("Failed with writing back updated metadata %d %ld %ld.\n", rc, task->offset * LEAF_BRANCHING_FACTOR + task->dev->tree->data_start, task->length);
        spdk_app_stop(-1);
    }
}

void reschedule_leaf_initialization(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
    struct hash_task *task = (struct hash_task *)cb_arg;
    spdk_bdev_free_io(bdev_io);
    if (!success) {
        SPDK_ERRLOG("Failed with writing back metadata %d.\n", success);
        spdk_app_stop(-1);
    }

    // If all of the tasks have been completed
    int atomic = atomic_fetch_sub(&task->overall_task->number_tasks, 1);
    if (atomic == 1) {
        SPDK_NOTICELOG("Completed all leaf initialization tasks\n");
        hash_entire_tree(task->dev);
        free(task->overall_task);
        free_task(task);
    } else {
        if (!(atomic % 100)) SPDK_NOTICELOG("Completed %d initialization tasks\n", atomic);
        // Check if you are at the end and should read less than LEAF_BRANCHING_FACTOR
        uint64_t offset = task->offset * LEAF_BRANCHING_FACTOR + task->dev->tree->data_start + PARALLEL_INITILIZATION_TASKS * LEAF_BRANCHING_FACTOR;
        task->offset += PARALLEL_INITILIZATION_TASKS;
        if (offset >= task->dev->tree->elements_per_level[0] + task->dev->tree->data_start) {
            free_task(task);
            return;
        }

        uint64_t length = MIN(task->dev->tree->elements_per_level[0] + task->dev->tree->data_start - offset, LEAF_BRANCHING_FACTOR);
        task->length = length;
        int rc = spdk_bdev_readv_blocks_ext(task->dev->desc, task->dev->initialization_ch,
                                            task->data, 1,
                                            offset, length,
                                            progress_leaf_initialization, task,
                                            NULL);
        if (rc != 0) {
            SPDK_ERRLOG("Failed to submit initialization reads.\n");
            spdk_app_stop(-1);
        }
    }
}

void free_task(struct hash_task *task) {
    spdk_free(task->data->iov_base);
    free(task->data);
    spdk_free(task->IVs->iov_base);
    free(task->IVs);
    free(task);
}

char* hexdump(void *x, size_t l) {
    static __thread char buffers[10][20000];
    static __thread int which = 0;

    if (!x || l == 0) {
        return "";  // Return an empty string for invalid input
    }

    which = (which + 1) % 10;  // Alternate between the two static buffers
    char *buf = buffers[which];
    unsigned char *p = (unsigned char*)x;
    size_t pos = 0;

    size_t bits = 0;
    for (size_t i = 0; i < l && pos < sizeof(buffers[0]) - 4; i++) { // -4 for safety (2 chars + space + '\0')
        pos += snprintf(buf + pos, sizeof(buffers[0]) - pos, "%02x", p[i]);
        bits += 8;
        if (bits == 64 && i != l - 1) {
            buf[pos++] = ' ';
            bits = 0;
        }
    }

    if (pos >= sizeof(buffers[0]) - 3) {
        // Truncate the output if the buffer is full
        snprintf(buf + pos, sizeof(buffers[0]) - pos, "...");
    } else {
        buf[pos] = '\0';
    }

    return buf;
}

void hash_entire_tree(struct device *dev) {
    size_t output_offset = dev->tree->elements_per_level[1];
    size_t input_offset = 0;
    for (size_t level = 2; level < dev->tree->number_levels; level++) {
        for (size_t block = 0; block < dev->tree->elements_per_level[level]; block++) {
            uint64_t length = MIN(dev->tree->elements_per_level[level - 1] - block * TREE_BRANCHING_FACTOR, TREE_BRANCHING_FACTOR);
            hash(dev->tree->hashes + input_offset + block * TREE_BRANCHING_FACTOR, dev->tree->hashes + output_offset + block, length * HASH_LENGTH);
        }
        output_offset += dev->tree->elements_per_level[level];
        input_offset += dev->tree->elements_per_level[level - 1];
    }

    SPDK_NOTICELOG("Root hash: %s\n", hexdump(dev->tree->hashes + input_offset, HASH_LENGTH));
    // Check if the root agrees with stored value
    if (!verify_tree(dev->tree)) {
        SPDK_ERRLOG("Unable to verify the tree correctly.\n");
        spdk_app_stop(-1);
    }

    // Mark the initialization as done
    atomic_store_explicit(&dev->tree->initialized, 2, memory_order_release);
    SPDK_NOTICELOG("Value of initialized %p: %d\n", &dev->tree->initialized, dev->tree->initialized);
    free(dev);
}

void update_tree(struct tree *tree, struct hasher_task_t *task) {
    // Initialize variables from the hashing task
    struct cache_entry *entry = task->cache_entry;
    size_t start_node_index = task->parent;
    size_t cumulative_elements = 0, node_index = start_node_index;
    struct node_update *combined = NULL, *temp = NULL, *temp2 = NULL;
    uint8_t parent_hash[HASH_LENGTH];

    for (size_t i = 1; i < tree->number_levels - 1; i++) {
        size_t start = ((node_index - cumulative_elements) / TREE_BRANCHING_FACTOR) * TREE_BRANCHING_FACTOR + cumulative_elements;
        node_index = cumulative_elements + tree->elements_per_level[i] + (node_index - cumulative_elements) / TREE_BRANCHING_FACTOR;
        size_t n_children = MIN(cumulative_elements + tree->elements_per_level[i] - start, TREE_BRANCHING_FACTOR);
        cumulative_elements += tree->elements_per_level[i];

        if (i == 1) {
            // For the leaves we have a different pattern
            // We first hash the cache entry
            hash(entry->data, parent_hash, entry->block_IVs * IV_LENGTH);
            
            // We then gather the updates but only from the current node (not other children)
            DL_CONCAT(combined, tree->updates[start_node_index]);
            if (!combined) {
                SPDK_ERRLOG("No updates found for leaf node %ld!\n", start_node_index);
                spdk_app_stop(-1);
            }
            tree->updates[start_node_index] = NULL;
            memcpy(combined->new_hash.hash, parent_hash, HASH_LENGTH);

            // Lock the children updating the correct hash
            for (size_t j = start; j < start + n_children; j++) {
                while (atomic_flag_test_and_set_explicit(&tree->locks[j], memory_order_acquire)) {}
                if (j == start_node_index) {
                    memcpy(&tree->hashes[j], parent_hash, HASH_LENGTH);
                }
            }

            // And we then return the entry to the cache
            // Note we need to do this after locking / before unlocking the child to ensure order
            spdk_thread_send_msg(cache_registry, complete_hashing, entry);
        } else {
            // Lock all of the children updating the hashes and gather their updates
            for (size_t j = start; j < start + n_children; j++) {
                while (atomic_flag_test_and_set_explicit(&tree->locks[j], memory_order_acquire)) {}
                if (tree->updates[j] != NULL) {
                    memcpy(&tree->hashes[j], tree->updates[j]->new_hash.hash, HASH_LENGTH); // Copy the head hash to the correct location
                    DL_CONCAT(combined, tree->updates[j]);
                    tree->updates[j] = NULL;
                }
            }
        }

        // If there's no updates, unlock and break; doesn't happen for leaves as we always have an update
        if (combined == NULL) {
            for (size_t j = start; j < start + n_children; j++) {
                atomic_flag_clear_explicit(&tree->locks[j], memory_order_release);
            }
            return;
        }

        // Hash the children, and if not at the root, change the hash of the top update
        void *children = tree->hashes + start;      // first child bytes
        hash(children, parent_hash, n_children * HASH_LENGTH);
        if (i != tree->number_levels - 2) memcpy(&combined->new_hash.hash, parent_hash, sizeof(struct hash));

        // Lock the parent and unlock the children
        while (atomic_flag_test_and_set_explicit(&tree->locks[node_index], memory_order_acquire)) {}
        for (size_t j = start; j < start + n_children; j++) {
            atomic_flag_clear_explicit(&tree->locks[j], memory_order_release);
        }
        
        if (i != tree->number_levels - 2) {
            // If not at the root, prepend the combined updates to the parent's update list
            DL_CONCAT(combined, tree->updates[node_index]);
            tree->updates[node_index] = combined;
            combined = NULL;
        } else { // If at the root mark the request as pre-committed
            // Assign a new sequence number for this root commit
            uint64_t seq = atomic_fetch_add_explicit(&tree->next_sequence_number, 1, memory_order_relaxed);
            DL_FOREACH(combined, temp) {
                // Determine the sectors affected by this commit
                request_t *request = temp->request;
                size_t real_address = request->start - tree->data_start;
                size_t original_node_index = temp->parent;
                size_t within_block_index, end;
                if (original_node_index == real_address / LEAF_BRANCHING_FACTOR) {
                    within_block_index = 0;
                    end = MIN((original_node_index + 1) * LEAF_BRANCHING_FACTOR - real_address, request->num_sectors);
                } else {
                    within_block_index = original_node_index * LEAF_BRANCHING_FACTOR - real_address;
                    end = request->num_sectors;
                }
                
                // Tag all affected sectors in this commit
                for (size_t idx = within_block_index; idx < end; idx++) {
                    request->sector_requests[idx].request_data.sequence_number = seq;
                }
            }            
        }

        void *parent = tree->hashes + node_index; // parent bytes
        memcpy(parent, parent_hash, HASH_LENGTH); // copy the hash to the parent

        // Unlock all the parent
        atomic_flag_clear_explicit(&tree->locks[node_index], memory_order_release);
    }

    // Clear all the requests and tasks
    if (combined) {
        DL_FOREACH_SAFE(combined, temp, temp2) {
            temp->callback(temp->arg);
            DL_DELETE(combined, temp);
            spdk_mempool_put(node_update_pool, temp);
        }     
    }
}

bool verify_tree(struct tree *tree) {
    // TODO - implement checking with some prestored value
    return true;
} 

void hash(const void *input, void *output, size_t length) {
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, input, length);
    blake3_hasher_finalize(&hasher, output, HASH_LENGTH);
}

void hash_empty(const void *input, void *output, size_t length) {
    memset(output, 0, HASH_LENGTH);
}

// Allocates a node update
void allocate_node_update(void *arg, spdk_msg_fn callback, request_t *request, size_t parent, struct node_update **node_update) {
    *node_update = spdk_mempool_get(node_update_pool);
    struct node_update *u = *node_update;
    if (!u) {
        SPDK_ERRLOG("node_update_pool exhausted\n");
        spdk_app_stop(-1);
    }
    u->prev     = NULL;
    u->next     = NULL;
    u->arg      = arg;
    u->callback = callback;
    u->request  = request;
    u->parent   = parent;
}

// Append a node update to the linked list for this node
bool append(uint64_t parent, struct node_update *u) {
    // Note, we can do this without a lock as only one person can access the list at a time (due to cache serialization)
    bool new = false;
    if (hasher_args[0].tree->updates[parent] == NULL) new = true;
    DL_PREPEND(hasher_args[0].tree->updates[parent], u);   // utlist, newest at the head
    return new;
}

// Creates and appends a node update
void schedule_node_update(void *arg, spdk_msg_fn callback, request_t *request, uint64_t parent) {
    struct node_update *u;
    allocate_node_update(arg, callback, request, parent, &u);
    append(parent, u);
}

// Allocates a hashing task
void allocate_hashing_task(struct cache_entry *cache_entry, hasher_task_t **outer_task) {
    // Try to get a task from this hasher's pool 
    int hasher_id = atomic_fetch_add(&scheduled_thread, 1) % global_freshness_config.hashing_cores;
    *outer_task = spdk_mempool_get(task_pools[hasher_id]);
    hasher_task_t *task = *outer_task;
    if (!task) {
        // No task available: fallback to synchronous hashing on caller thread
        SPDK_NOTICELOG("Run out of tasks in the pool\n");
        spdk_app_stop(-1);
    }

    // Set the task fields
    task->cache_entry = cache_entry;
    task->parent = cache_entry->block_index;
    task->hasher_id = hasher_id;
}

// Enqueue the task to a hasher thread ring
void enqueue(hasher_task_t *task) {   
    if (spdk_ring_enqueue(rings[task->hasher_id], (void **)&task, 1, NULL) == 0) {
        // Ring full
        SPDK_NOTICELOG("Run out of space in thread %ld task rings\n", task->hasher_id);
        spdk_app_stop(-1);
    }
}

// Creates and enqueues a hashing task
void schedule_hashing_task(struct cache_entry *cache_entry) {
    hasher_task_t *task;
    allocate_hashing_task(cache_entry, &task);
    enqueue(task);
}

// Hasher thread: pin to its core, then loop on dequeue
static void *hasher_loop(void *arg) {
    hasher_arg_t *ha = arg;

    // Set the thread affinity to the specified core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(ha->lcore, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    // Start the hashing loop
    hasher_task_t *tasks[BURST_SIZE];
    printf("Hasher thread started on core %d\n", ha->lcore);
    for (;;) {
        if (global_freshness_config.hashing_cores > ha->ID) {
            int n = spdk_ring_dequeue(rings[ha->ID], (void **)tasks, BURST_SIZE);
            if (n > 0) {
                // do all the hashing first (note we also now complete inside)
                for (int i = 0; i < n; i++) {
                    // batch all the requests in the same parent
                    update_tree(ha->tree, tasks[i]);
                    spdk_mempool_put(task_pools[ha->ID], tasks[i]);
                }
            } else {
                spdk_pause();
            }
        } else {
            usleep(1000); // Sleep for 1ms if this thread is not needed
        }
    }
    return NULL;
}

// Launch hasher threads on consecutive cores starting at START_HASHER_CORE
void launch_hashing_threads(struct tree *tree) {
    // Initialize the node update pool
    node_update_pool = spdk_mempool_create("node_update_pool",
                                           MAX_REQUESTS * MAX_HASHER_THREADS,
                                           sizeof(struct node_update),
                                           SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                                           0);
    if (!node_update_pool) goto err;

    // Initialize the hasher threads
    atomic_store(&scheduled_thread, 0);
    for (int i = 0; i < MAX_HASHER_THREADS; i++) {
        hasher_args[i].ID = i;
        hasher_args[i].lcore = START_HASHER_CORE + i;
        hasher_args[i].tree = tree;
        char pool_name[32];
        snprintf(pool_name, sizeof(pool_name), "hasher_pool_%d", i);
        task_pools[i] = spdk_mempool_create(pool_name,
                                            MAX_REQUESTS,
                                            sizeof(hasher_task_t),
                                            SPDK_MEMPOOL_DEFAULT_CACHE_SIZE,
                                            0);
        if (!task_pools[i]) goto err;

        rings[i] = spdk_ring_create(SPDK_RING_TYPE_MP_SC, MAX_REQUESTS, 0);
        if (!rings[i]) goto err;

        if (pthread_create(&hasher_threads[i],
                           NULL,
                           hasher_loop,
                           &hasher_args[i]) == 0) {
            pthread_detach(hasher_threads[i]);
        } else goto err;
    }
    printf("Launched %d background hasher threads starting at core %d\n", MAX_HASHER_THREADS, START_HASHER_CORE);

    return;

err:
    SPDK_ERRLOG("Failed to create hasher threads.\n");
    spdk_app_stop(-1);
    return;
}