#ifndef REQUEST_H
#define REQUEST_H

#include "spdk/thread.h"
#include "uthash.h"
#include "utlist.h"
#include "constants.h"
#include "pthread.h"

#define MAX_SECTOR_ENTRIES   (MAX_REQUESTS * MAX_IO_SIZE)
#define MAX_SCHED_ENTRIES    MAX_REQUESTS

// The request data structure that holds the old and new IVs, and the sector number and is persistently stored in SRAM
typedef struct {
    uint8_t old_IV[IV_LENGTH]; // 0 is invalid (i.e., fetch from disk cache)
    uint8_t new_IV[IV_LENGTH];
    uint64_t sector      : 62;
    uint64_t is_hashed   : 1;
    uint64_t is_commited : 1;
    uint64_t sequence_number; // the sequence number of the commit to the tree
} request_data_t;

// A double linked list of requests at a given sector
typedef struct request_t request_t; // forward declaration
typedef struct request_list_t request_list_t; // forward declaration
typedef struct sector_request {
    // Metadata
    request_t *request; // pointer to the request that this sector request belongs to
    struct sector_request *next;
    struct sector_request *prev;
    request_list_t *bucket_entry; // pointer to the hash map entry for this sector request

    // The actual request data stored in the SRAM
    request_data_t request_data; // the request data structure
} sector_request_t;

// A general request structure that holds the request information
struct request_t {
    struct spdk_bdev_io *bdev_io;
    spdk_msg_fn callback; // function to call when the request is completed
    struct spdk_thread *thread; // thread that created the request
    uint64_t start; // the start sector of the request
    uint64_t end; // the end sector of the request
    uint64_t num_sectors; // the number of sectors in the request
    atomic_int superblocks; // the number of superblocks that this request spans
    bool written; // indicates if the request has been written to disk
	struct vbdev_freshness *bdev; // the bdev to which this bdev_io belongs
	struct spdk_io_channel *ch; // for submitting requests to the base bdev
	struct spdk_io_channel *base_ch;
    atomic_bool preprocessed; // marks whether the request has been hashed/written (always needs to be true to complete the request)
	int retries; /* retries in case of non-fresh reads */
	atomic_int remaining_checks; /* how many more checks do we need to complete */
	bool failed; /* indicates whether the checks have failed */
    uint8_t IVs[MAX_IO_SIZE * IV_LENGTH]; /* we gather the IVs as we go through them to then be able to easily compare */
    sector_request_t sector_requests[MAX_IO_SIZE]; // array of sector requests, one for each sector in the IO
    int hasher_id; // the id of the hasher that is currently processing this request (i.e., to which we send all of sector requests), -1 if none
    uint64_t front_sectors; // number of sectors at the front; used to know whether a given request needs to be scheduled already or not
    int type; // type of the request (READ - 0 or WRITE - 1)
    int superblocks_to_be_preprocessed; // number of superblock IVs copied so far (needed for eventual consistency)
};

// A hash map pointing to a doubly linked list of requests for a given sector
struct request_list_t {
    uint64_t sector;
    sector_request_t *head; // linked list of requests for this sector
    UT_hash_handle hh; // hash handle for uthash
};

// A dummy structure to hold the request map and a lock for it
typedef struct {
    request_list_t *head;
    pthread_spinlock_t lock;
    // struct spdk_spinlock lock; // spinlock for the request map
} request_map_t;

// A structure to hold temporary scheduling information
typedef struct scheduling_set_entry {
    request_t *request; // pointer to the request   
    UT_hash_handle hh;
} scheduling_set_entry_t;


void initialize_request_registry(void);
bool register_request(spdk_msg_fn callback, struct spdk_bdev_io *bdev_io, request_t **request);
void schedule_request(void *cb_arg);
void complete_request(void *cb_arg);
void delete_request(request_t *request);


// TODO: finish the below

// struct superblock_map_element {
//     uint64_t superblock_address;
//     struct spdk_spinlock lock;
//     UT_hash_handle hash_requests;
//     UT_hash_handle superblocks;
//     bool is_hashed; // indicates if the superblock is being hashed 
// };

// struct hash_request_head {
//     uint64_t address;
//     UT_hash_handle hash_requests;
//     struct list_head write_requests;
// };

// struct write_request {
//     struct sram_backed_request request;
//     struct list_head write_requests;
//     struct spdk_thread *thread;
//     struct spdk_bdev_io *bdev_io;
//     u_int64_t hasher_id; // the id of the hasher that is currently processing this request, 0 if none
// };

// struct sram_backed_request {
//     uint64_t address: 63;
//     enum write_status status: 1;
//     uint64_t old_IV; // 0 is invalid (i.e., fetch from disk cache)
//     uint64_t new_IV;
// };

// enum write_status {
//     WRITING, // the block has not yet been written to disk
//     WRITTEN, // the block has been written to disk
// };

// leave the requests until a thread picks it up and conducts the tree update
// essentially its the hashers who erase, and write requests who add / update

#endif // REQUEST_H