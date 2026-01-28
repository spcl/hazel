#ifndef HASHING_H
#define HASHING_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include "spdk/bdev.h"
#include "request.h"
#include "constants.h"

#define HASHING_OFFLOAD

#define LEAF_BRANCHING_FACTOR 512 // the last layer branching factor such that 512 * IV length (8 bytes) = 4096 fits the disk cache
#define TREE_BRANCHING_FACTOR 16 // the upper layers of the tree such that 256 * hash length (16) = 4096
#define PARALLEL_INITILIZATION_TASKS 64

#define MAX_REQUESTS 10000 /* Maximum number of tasks in the tree hashing queue */
#define MAX_HASHER_THREADS 16    /* Maximum number of hashing (background) threads processing the hashing tree (you can control the actual number with config)*/
#define HASHER_CORES 4    /* Number of cores used for hashing threads as default */
#define START_HASHER_CORE  17    /* The core on which the hashing threads start, this is used to avoid the interference with the main SPDK thread */
#define BURST_SIZE      5

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

typedef struct hasher_task_t hasher_task_t; // forward declaration
struct cache_entry; // forward declaration
extern struct spdk_thread *cache_registry; // forward declaration

/*
* A generic task used for tracking of hashing.
*/
struct task {
    atomic_int  current_level; // the current level in the tree; for reads always the most bottom layer (e.g., 5)
    atomic_int  number_tasks; // the number of tasks remaining to be processed
    void        (*callback)(void *); // the callback that is called when number_tasks = 0 with the first argument provided here.
    void        *arg; // the argument provieded to the callback
};

/*
* A generic task used for the underlying hashing. It reads LEAF_BRANCHING_FACTOR to a temporary buffer, and hashes the IVs.
*/
struct hash_task {
    struct task     *overall_task;
    struct device   *dev;
    struct iovec    *data;
    struct iovec    *IVs;
    size_t          offset;
    size_t          length;
};

/*
* Internal representation of the hash. Can be replaced, for example, using Blake.
*/
struct hash {
    uint8_t hash[HASH_LENGTH];
};

/*
* The representation of the tree.
*/
struct tree {
    atomic_char             initialized; // indicates the status of the tree and allows multiple threads to synchronize to make sure it is not reinitialized
    struct hash             *hashes; // store the actual hashes of the tree, these are stored from lowest levels to highest such that the parent of the bottom layers can be obtained easily
    size_t                  number_levels; // how many levels does the tree have
    size_t                  *elements_per_level; // for each level stores how many elements there are in the level
    size_t                  data_start; // at which block does the SSD cache end and does the actual data start
    atomic_flag             *locks; // used to implement a lock per tree element and a waiting flag state
                                    // (old version) indicate who is accessing the data now. Our implementation allows for 256 concurrent threads and is implemented per last level of hashing
                                    // tree granularity; if = 0, a writer is working on the data, if = 1, it is free, if = N (where N > 1), N - 1 readers access the data.
    _Atomic uint64_t        next_sequence_number; // the sequence number of the latest commit (one per a sequence of requests - either all are in or none is in)
    struct node_update      **updates; // per node, the head of the linked list of pending updates
};

/*
* For the state of the tree nodes and workers.
*/
// typedef enum {
//     IDLE               = 0u,
//     LOCKED             = 1u << 0,
//     WAITING            = 1u << 1,
//     LOCKED_AND_WAITING = LOCKED | WAITING,
// } node_state_t;

// typedef enum {
//     WORKER,
//     SPINNER,
//     SKIP,
// } role_t;

/*
* Used during the initilization process to pass the bdev details.
*/
struct device {
    struct spdk_io_channel  *initialization_ch;
    struct spdk_bdev_desc   *desc;
    struct tree             *tree;
};

/*
* A task used to compute the hash of a parent node in the tree.
*/
struct hasher_task_t {
    size_t parent; // the parent of the task, used to compute the parent hash
    struct cache_entry *cache_entry; // the cache entry being processed
    size_t hasher_id; // the id of the hasher processing this task
};

/*
* Internal representation of a node update in the tree.
*/
struct node_update {
    struct node_update  *prev, *next;  // doubly-linked list
    struct hash         new_hash;      // 16-byte hash for this node and update
    void *arg;  // argument provided to the callback
    spdk_msg_fn callback; // the callback that is called when the task is completed
    request_t  *request; // the request that is being processed
    size_t    parent;  // the parent node being updated
};

/*
* A work queue used to schedule the tasks that are used for background hashing the tree, i.e., eventual consistency.
*/
typedef struct {
    hasher_task_t *buf[MAX_REQUESTS];
    int      head, tail, count;
    pthread_mutex_t    lock;
    pthread_cond_t     not_full, not_empty;
} work_queue_t;

/*
* A structure used to pass the work queue and the lcore to the hasher threads.
*/
typedef struct {
    int           ID;    // ID of the thread
    int           lcore; // on which core the thread should run
    struct tree   *tree; // the tree that is being processed
} hasher_arg_t;

/*
* Launches the hashing threads that are used to process the tree in the background.
*/
void launch_hashing_threads(struct tree *tree);

void allocate_node_update(void *arg, spdk_msg_fn callback, request_t *request, size_t parent, struct node_update **node_update);
bool append(uint64_t parent, struct node_update *u);
void schedule_node_update(void *arg, spdk_msg_fn callback, request_t *request, uint64_t parent);
void allocate_hashing_task(struct cache_entry *cache_entry, hasher_task_t **outer_task);
void enqueue(hasher_task_t *task);
void schedule_hashing_task(struct cache_entry *cache_entry);

/*
* Dequeues one sector (uint64_t), blocking if empty.
*/
// hasher_task_t * dequeue(void);

/*
* Creates the tree by initilizing the corresponding structures and scheduling the initial necessary read requests.
*/
size_t create_hash_tree(struct tree *, size_t);

/*
* Initializes the tree creation routine.
*/
void initialize_tree(struct tree *, struct spdk_bdev_desc *, struct spdk_io_channel *);

/*
* Computes the hash at a given index in the hash array.
*/
void hash_index(struct tree *, size_t index, struct hash *);

/*
* Computes the location of the parent of a given node in the hash array. It should only be used with the tree nodes, not leaves.
*/
void parent_location(struct tree *, size_t index);

/*
* Used to configure the hashing algorithm running in the background.
*/
void configure_hashing(void); 

/*
* Hashes legth B at location loc.
*/
void hash(const void *input, void *output, size_t length);
void hash_empty(const void *input, void *output, size_t length);

/* 
* Updates the tree with change at lowest level location loc.
*/
void update_tree(struct tree *tree, struct hasher_task_t *task);

void check_initialized(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
void free_task(struct hash_task *task);
void progress_leaf_initialization(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
void write_leaf_initilization(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
bool verify_tree(struct tree *tree);
void hash_entire_tree(struct device *dev);
void update_metadata_cache(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
void reschedule_leaf_initialization(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg);
char* hexdump(void *x, size_t l);

#endif