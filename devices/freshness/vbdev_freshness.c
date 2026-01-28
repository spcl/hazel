/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 *   Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

/*
 * This is a simple example of a virtual block device module that passes IO
 * down to a bdev (or bdevs) that its configured to attach to.
 */

#include "spdk/stdinc.h"

#include "vbdev_freshness.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/event.h"

#include "hashing.h"
#include "cache.h"
#include "ipsec.h"

#include "spdk/bdev_module.h"
#include "spdk/log.h"
#include "spdk/barrier.h"

/* This namespace UUID was generated using uuid_generate() method. */
#define BDEV_freshness_NAMESPACE_UUID "7e25812e-c8c0-4d3f-8599-16d790555b75"

static int vbdev_freshness_init(void);
static int vbdev_freshness_get_ctx_size(void);
static void vbdev_freshness_examine(struct spdk_bdev *bdev);
static void vbdev_freshness_finish(void);
static int vbdev_freshness_config_json(struct spdk_json_write_ctx *w);
static void vbdev_freshness_resubmit_io(void *arg);
void freshness_update_IVs(void *cb_arg);
void hasher_callback(void *arg);
void schedule_final_write(void *arg);
static void pt_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success);

extern struct spdk_thread *request_registry;
extern struct spdk_thread *cache_registry;

static struct spdk_bdev_module freshness_if = {
	.name = "freshness",
	.module_init = vbdev_freshness_init,
	.get_ctx_size = vbdev_freshness_get_ctx_size,
	.examine_config = vbdev_freshness_examine,
	.module_fini = vbdev_freshness_finish,
	.config_json = vbdev_freshness_config_json
};

SPDK_BDEV_MODULE_REGISTER(freshness, &freshness_if)

/* List of pt_bdev names and their base bdevs via configuration file.
 * Used so we can parse the conf once at init and use this list in examine().
 */
struct bdev_names {
	char			*vbdev_name;
	char			*bdev_name;
	struct spdk_uuid	uuid;
	TAILQ_ENTRY(bdev_names)	link;
};
static TAILQ_HEAD(, bdev_names) g_bdev_names = TAILQ_HEAD_INITIALIZER(g_bdev_names);

/* List of virtual bdevs and associated info for each. */
static TAILQ_HEAD(, vbdev_freshness) g_pt_nodes = TAILQ_HEAD_INITIALIZER(g_pt_nodes);

/* The pt vbdev channel struct. It is allocated and freed on my behalf by the io channel code.
 * If this vbdev needed to implement a poller or a queue for IO, this is where those things
 * would be defined. This freshness bdev doesn't actually need to allocate a channel, it could
 * simply pass back the channel of the bdev underneath it but for example purposes we will
 * present its own to the upper layers.
 */
struct pt_io_channel {
	struct spdk_io_channel	*base_ch; /* IO channel of base device */
	struct freshness_config *config; /* Configuration for this channel that includes the global variables */
};

/* Just for fun, this pt_bdev module doesn't need it but this is essentially a per IO
 * context that we get handed by the bdev layer.
 */
struct freshness_bdev_io {
	/* used for hashing requests */
	request_t *request;
	bool hashed; // indicates if the request has been hashed
	uint64_t cycles;

	struct spdk_io_channel *ch;

	/* for bdev_io_wait */
	struct spdk_bdev_io_wait_entry bdev_io_wait;
};

static void vbdev_freshness_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io);

/* Callback for unregistering the IO device. */
static void
_device_unregister_cb(void *io_device)
{
	struct vbdev_freshness *pt_node  = io_device;

	/* Done with this pt_node. */
	spdk_put_io_channel(pt_node->initialization_ch);
	free(pt_node->pt_bdev.name);
	free(pt_node);
}

/* Wrapper for the bdev close operation. */
static void
_vbdev_freshness_destruct(void *ctx)
{
	struct spdk_bdev_desc *desc = ctx;

	spdk_bdev_close(desc);
}

/* Called after we've unregistered following a hot remove callback.
 * Our finish entry point will be called next.
 */
static int
vbdev_freshness_destruct(void *ctx)
{
	struct vbdev_freshness *pt_node = (struct vbdev_freshness *)ctx;

	/* It is important to follow this exact sequence of steps for destroying
	 * a vbdev...
	 */

	TAILQ_REMOVE(&g_pt_nodes, pt_node, link);

	/* Unclaim the underlying bdev. */
	spdk_bdev_module_release_bdev(pt_node->base_bdev);

	/* Close the underlying bdev on its same opened thread. */
	if (pt_node->thread && pt_node->thread != spdk_get_thread()) {
		spdk_thread_send_msg(pt_node->thread, _vbdev_freshness_destruct, pt_node->base_desc);
	} else {
		spdk_bdev_close(pt_node->base_desc);
	}

	/* Unregister the io_device. */
	spdk_io_device_unregister(pt_node, _device_unregister_cb);

	return 0;
}

/* Completion callback for IO that were issued from this bdev. The original bdev_io
 * is passed in as an arg so we'll complete that one with the appropriate status
 * and then free the one that this module issued.
 */
static void
_pt_complete_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)orig_io->driver_ctx;
	// struct vbdev_freshness *pt_node = SPDK_CONTAINEROF(orig_io->bdev, struct vbdev_freshness, pt_bdev);

	/* Complete the original IO and then free the one that we created here
	 * as a result of issuing an IO via submit_request.
	 */
	// printf("%s\n", hexdump(orig_io->u.bdev.iovs->iov_base, BLOCK_SIZE + METADATA_SIZE));
	// fflush(stdout);

	if (orig_io->type == SPDK_BDEV_IO_TYPE_READ) {
		delete_request(io_ctx->request);
	} else if (orig_io->type == SPDK_BDEV_IO_TYPE_WRITE) {
		bool expected = false;
		bool modified = atomic_compare_exchange_strong_explicit(
					&io_ctx->request->preprocessed, // compare “preprocessed” (true) …
					&expected,                    // compare “expected” (false) ...
					true,                         // … with new value = true
					memory_order_acquire,         // if success: acquire‐fence
					memory_order_relaxed          // if failure: no ordering guarantees needed
				);
		if (!global_freshness_config.eventual_consistency || (global_freshness_config.eventual_consistency && !modified)) {
			// we either don't use eventual consistency (and then need to close the request as we are the last point)
			// or this means hashing was first and we should complete the request and delete it
			spdk_thread_send_msg(request_registry, complete_request, io_ctx->request); // also deletes the request
			// delete_request(io_ctx->request);
		}
	}

	if (((spdk_get_ticks() - io_ctx->cycles)/(double)spdk_get_ticks_hz()) > 1) {
		SPDK_ERRLOG("%.3f\n", (spdk_get_ticks() - io_ctx->cycles)/(double)spdk_get_ticks_hz());
	}
	spdk_bdev_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

// static void
// pt_init_ext_io_opts(struct spdk_bdev_io *bdev_io, struct spdk_bdev_ext_io_opts *opts)
// {
// 	memset(opts, 0, sizeof(*opts));
// 	opts->size = sizeof(*opts);
// 	opts->memory_domain = bdev_io->u.bdev.memory_domain;
// 	opts->memory_domain_ctx = bdev_io->u.bdev.memory_domain_ctx;
// 	opts->metadata = bdev_io->u.bdev.md_buf;
// }

void
schedule_final_write(void *arg)
{
	struct spdk_bdev_io *orig_io = arg;
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)orig_io->driver_ctx;

	if (io_ctx->request->failed) {
		SPDK_ERRLOG("Failed writing\n");
		spdk_bdev_io_complete(orig_io, SPDK_BDEV_IO_STATUS_FAILED);
	} else {
		// struct spdk_bdev_ext_io_opts io_opts;
		// pt_init_ext_io_opts(orig_io, &io_opts);
		int rc = spdk_bdev_writev_blocks(io_ctx->request->bdev->base_desc, io_ctx->request->base_ch,
										 orig_io->u.bdev.iovs, orig_io->u.bdev.iovcnt, 
										 orig_io->u.bdev.offset_blocks, orig_io->u.bdev.num_blocks, 
										 _pt_complete_io, orig_io); // _ext , &io_opts);

		if (rc != 0) {
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(orig_io, SPDK_BDEV_IO_STATUS_FAILED);
			return;
		}
	}
}

void 
hasher_callback(void *arg) 
{
	struct request_t *request = (struct request_t *)arg;
	if (atomic_fetch_sub_explicit(&request->superblocks, 1, memory_order_acq_rel) == 1) {
		if (!global_freshness_config.eventual_consistency) {
			spdk_thread_send_msg(request->thread, schedule_final_write, request->bdev_io);
		} else {
			bool expected = false;
			bool modified = atomic_compare_exchange_strong_explicit(
						&request->preprocessed, // compare “preprocessed” (true) …
						&expected,                    // compare “expected” (false) ...
						true,                         // … with new value = true
						memory_order_acquire,         // if success: acquire‐fence
						memory_order_relaxed          // if failure: no ordering guarantees needed
					);
			if (!modified) {
				spdk_thread_send_msg(request_registry, complete_request, request); // also deletes the request
				// delete_request(request);
			}
		}
	}
	// printf("[%ld] Finished request %p [%s] with start %ld and end %ld with IVs %s\n", 
	// 	spdk_get_ticks(), request, hexdump(request->bdev_io->u.bdev.iovs->iov_base, 2), request->start, request->end, hexdump(request->IVs, request->num_sectors * IV_LENGTH));
}

/*
* Checks the IV cache hash with the parent, locks the parent and updates the tree. Finally, writes the original bdev_io into the device.
*/
void freshness_update_IVs(void *cb_arg) {
	struct cache_request *cache_request = cb_arg;
	request_t *request = cache_request->request;
	struct cache_entry *entry = cache_request->cache_entry;

	size_t real_block_address = request->start - request->bdev->hashing_tree.data_start;
	size_t superblock_start_index = real_block_address / LEAF_BRANCHING_FACTOR;
	size_t superblock_end_index = (real_block_address + request->num_sectors - 1) / LEAF_BRANCHING_FACTOR;
	if (superblock_end_index - superblock_start_index >= 2) SPDK_ERRLOG("The access spans more than two blocks (%ld-%ld)!\n", superblock_start_index, superblock_end_index); // we assume that we only can be within two superblocks
	size_t offset = 0, within_IV_index = 0, length = 0;
	uint8_t block_hash[HASH_LENGTH];
	uint64_t index = entry->block_index;

	if (!request->failed) {
		// Get the correct indexes
		if (entry->block_index != superblock_start_index && entry->block_index != superblock_end_index) SPDK_ERRLOG("Mismatch (%p) of block (%p, %ld) and superblock addresses (%ld-%ld)\n", request, entry, entry->block_index, superblock_start_index, superblock_end_index);
		if (superblock_start_index == superblock_end_index) {
			length = request->num_sectors;
			offset = real_block_address - superblock_start_index * LEAF_BRANCHING_FACTOR;
			within_IV_index = 0;
		} else if (entry->block_index == superblock_start_index) {
			length = superblock_end_index * LEAF_BRANCHING_FACTOR - real_block_address;
			offset = real_block_address - superblock_start_index * LEAF_BRANCHING_FACTOR;
			within_IV_index = 0;
		} else if (entry->block_index == superblock_end_index) {
			length = real_block_address + request->num_sectors - superblock_end_index * LEAF_BRANCHING_FACTOR; 
			offset = 0;
			within_IV_index = superblock_end_index * LEAF_BRANCHING_FACTOR - real_block_address;
		} else {
			SPDK_ERRLOG("Mismatch of block and superblock addresses\n");
		}
		if (length == 0) {
			SPDK_ERRLOG("Length is zero with %ld %ld %ld %ld %ld\n", real_block_address, superblock_start_index, superblock_end_index, request->num_sectors, entry->block_index);
		}

		// In case of eventual consistency, update the old IVs in the request and schedule the final write if needed
		if (global_freshness_config.eventual_consistency) {
			for (size_t current_block_index = 0; current_block_index < length; current_block_index++) {
				memcpy(request->sector_requests[within_IV_index + current_block_index].request_data.old_IV, entry->data + (offset + current_block_index) * IV_LENGTH, IV_LENGTH);
			}
			request->superblocks_to_be_preprocessed--;
			if (request->superblocks_to_be_preprocessed == 0) {
				// All superblocks have been preprocessed (or are not in the cache), we can schedule the final write
				schedule_final_write(request->bdev_io);
			}
		}

		// Copy the IVs into the cache entry
		memcpy(entry->data + offset * IV_LENGTH, request->IVs + within_IV_index * IV_LENGTH, length * IV_LENGTH);

		// Schedule the node update in the tree
		entry->block_IVs = MIN(request->bdev->hashing_tree.elements_per_level[0] - entry->block_index * LEAF_BRANCHING_FACTOR, LEAF_BRANCHING_FACTOR);
		schedule_node_update((void *)request, hasher_callback, request, index);

		// printf("Updated %ld from %s: %ld with old hash %s and new hash @%p %s\n",
		// 	entry->block_index,
		// 	hexdump(entry->data + offset * IV_LENGTH, IV_LENGTH), 
		// 	*(uint64_t *)(entry->data + offset * IV_LENGTH),
		// 	hexdump(entry->data + BLOCK_SIZE + INTEGRITY_LENGTH, HASH_LENGTH),
		// 	request->bdev->hashing_tree.hashes + entry->block_index,
		// 	hexdump(request->bdev->hashing_tree.hashes + entry->block_index, HASH_LENGTH));

		//memcpy(request->bdev->hashing_tree.hashes + entry->block_index, block_hash, HASH_LENGTH); // only one writer (we lock the entry, hashers are readers), so that's fine 
		 																					      // entry->data + BLOCK_SIZE + INTEGRITY_LENGTH
		
		// printf("Updated 2 %ld from %s: %ld with old hash %s and new hash @%p %s\n",
		// 	entry->block_index,
		// 	hexdump(entry->data + offset * IV_LENGTH, IV_LENGTH), 
		// 	*(uint64_t *)(entry->data + offset * IV_LENGTH),
		// 	hexdump(entry->data + BLOCK_SIZE + INTEGRITY_LENGTH, HASH_LENGTH),
		// 	request->bdev->hashing_tree.hashes + entry->block_index,
		// 	hexdump(request->bdev->hashing_tree.hashes + entry->block_index, HASH_LENGTH));
		//SPDK_NOTICELOG("memcpy to %p\n", io_ctx->request->bdev->hashing_tree.hashes + entry->block_index);

		complete_cache_request(cache_request);

		if (global_freshness_config.keep_metadata_fresh) {
			// Update the metadata cache in the block with the new parent
			struct iovec *current_iov;
			size_t current_block_index = 0;
			uint8_t *current_start, *current_address, *current_end;
			size_t remaining_bytes = BLOCK_SIZE;
			for (int iov_index = 0; iov_index < request->bdev_io->u.bdev.iovcnt; iov_index++) {
				// printf("[%ld] %p IOV %d: %p %zu %s\n", spdk_get_ticks(), io_ctx->request, iov_index, bdev_io->u.bdev.iovs[iov_index].iov_base, bdev_io->u.bdev.iovs[iov_index].iov_len,);
				current_iov = request->bdev_io->u.bdev.iovs + iov_index;
				current_start = current_iov->iov_base;
				current_end = current_iov->iov_base + current_iov->iov_len;
				current_address = current_start + remaining_bytes;
				remaining_bytes = 0;

				while (current_address < current_end) {
					if (current_block_index >= within_IV_index && current_block_index < within_IV_index + length) {
						// Copy the hash to the block so that it's fresh
						memcpy(current_address + INTEGRITY_LENGTH + IV_LENGTH, block_hash, HASH_LENGTH);
						hash(current_address + INTEGRITY_LENGTH, current_address + INTEGRITY_LENGTH + IV_LENGTH + HASH_LENGTH, IV_LENGTH + HASH_LENGTH);
					}

					// Move around because of interleaving of block and metadata
					current_block_index++;
					current_address += METADATA_SIZE + BLOCK_SIZE;
					if (current_address >= current_end) {
						remaining_bytes = current_address - current_end;
						break;
					}
				}
			}
			// Would require remapping the hashes to the correct blocks back
			// memcpy(orig_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH, io_ctx->request->bdev->hashing_tree.hashes + superblock_index, HASH_LENGTH);
			if (atomic_fetch_sub_explicit(&request->remaining_checks, 1, memory_order_acq_rel) == 1) schedule_final_write(request->bdev_io);
		}

		// printf("Wrote %ld @ %ld\n", real_block_address, superblock_start_index);

		// Schedule the tree update
		// printf("Scheduling update of the tree for %ld@%ld\n", real_block_address, index);
		//enqueue(index, (void *)request, hasher_callback, request, block_hash);
		// Can memcpy and enqueue after unlocking
		// task->cache_entry = entry;
		// if (new) enqueue(task); // need to enqueue before unlocking to ensure there's order
		//update_tree(&io_ctx->request->bdev->hashing_tree, index);
	}
	// SPDK_NOTICELOG("Spent %ld %ld %.9lf updating tree\n", spdk_get_ticks_hz(), spdk_get_ticks() - time0, (spdk_get_ticks() - time0)/(double)spdk_get_ticks_hz());

	// Update the metadata cache in the block with the new parent
	// Would require remapping the hashes to the correct blocks back
	// memcpy(orig_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH, io_ctx->request->bdev->hashing_tree.hashes + superblock_index, HASH_LENGTH);
	// hash(orig_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH, orig_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH + IV_LENGTH + HASH_LENGTH, IV_LENGTH + HASH_LENGTH);
}

static void freshness_verify_IVs(void *cb_arg) {
	struct cache_request *cache_request = cb_arg;
	request_t *request = cache_request->request;
	struct cache_entry *entry = cache_request->cache_entry;

	size_t real_block_address = request->start - request->bdev->hashing_tree.data_start;
	size_t superblock_start_index = real_block_address / LEAF_BRANCHING_FACTOR;
	size_t superblock_end_index = (real_block_address + request->num_sectors - 1) / LEAF_BRANCHING_FACTOR;
	if (superblock_end_index - superblock_start_index >= 2) SPDK_ERRLOG("The access spans more than two blocks!\n"); // we assume that we only can be within two superblocks
	size_t offset = 0, within_IV_index = 0, length = 0;

	if (!request->failed) {
		if (entry->block_index != superblock_start_index && entry->block_index != superblock_end_index) SPDK_ERRLOG("Mismatch of block and superblock addresses\n");
		if (superblock_start_index == superblock_end_index) {
			length = request->num_sectors;
			offset = real_block_address - superblock_start_index * LEAF_BRANCHING_FACTOR;
			within_IV_index = 0;
		} else if (entry->block_index == superblock_start_index) {
			length = superblock_end_index * LEAF_BRANCHING_FACTOR - real_block_address;
			offset = real_block_address - superblock_start_index * LEAF_BRANCHING_FACTOR;
			within_IV_index = 0;
		} else if (entry->block_index == superblock_end_index) {
			length = real_block_address + request->num_sectors - superblock_end_index * LEAF_BRANCHING_FACTOR; 
			offset = 0;
			within_IV_index = superblock_end_index * LEAF_BRANCHING_FACTOR - real_block_address;
		} else {
			SPDK_ERRLOG("Mismatch of block and superblock addresses\n");
		}
		if (length == 0) SPDK_ERRLOG("Length is zero\n");
		if (memcmp(request->IVs + within_IV_index * IV_LENGTH, entry->data + offset * IV_LENGTH, length * IV_LENGTH)) {
			request->failed = true;
			SPDK_ERRLOG("The block %ld %ld %ld %ld %ld %ld (%s) and cache entry (%s) IVs do not agree!\n", request->start, superblock_start_index, superblock_end_index, length, offset, within_IV_index, hexdump(request->IVs + within_IV_index * IV_LENGTH, IV_LENGTH), hexdump(entry->data + offset * IV_LENGTH, IV_LENGTH));
			printf("%s %s\n", hexdump(request->IVs + within_IV_index * IV_LENGTH, length * IV_LENGTH), hexdump(entry->data + (offset - 2) * IV_LENGTH, (length + 4) * IV_LENGTH));
			fflush(stdout);
		}
	}
	complete_cache_request(cache_request);

	if (atomic_fetch_sub_explicit(&request->remaining_checks, 1, memory_order_acq_rel) == 1) {
		if (request->failed) {
			if (++request->retries > NUMBER_OF_RETRIES) {
				SPDK_ERRLOG("Run out of retries after broken freshness\n");
				spdk_bdev_io_complete(request->bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
				delete_request(request);
			} else {
				SPDK_ERRLOG("Retrying after wrong IVs for the %d time\n", request->retries);
				request->failed = false;
				spdk_bdev_io_get_buf(request->bdev_io, pt_read_get_buf_cb, request->num_sectors * request->bdev_io->bdev->blocklen);
			}
		} else {
			spdk_bdev_io_complete(request->bdev_io, SPDK_BDEV_IO_STATUS_SUCCESS);
			delete_request(request);
		}
	}
	// TODO: Cron job to update the blocks to make sure that the cache in the metadata is always fresh
}

// Gather all of the IVs from the IO and schedule the updates
static void
gather_write_IVs(void *arg)
{
	struct spdk_bdev_io *bdev_io = arg;
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)bdev_io->driver_ctx;
	// printf("[%ld] Gathering %p with start %ld and end %ld and IOVcntc %d\n", spdk_get_ticks(), io_ctx->request, bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1, bdev_io->u.bdev.iovcnt);
	struct iovec *current_iov;
	size_t current_block_index = 0;
	void *current_start, *current_address, *current_end;
	size_t remaining_bytes = BLOCK_SIZE;
	for (int iov_index = 0; iov_index < bdev_io->u.bdev.iovcnt; iov_index++) {
		// printf("[%ld] %p IOV %d: %p %zu %s\n", spdk_get_ticks(), io_ctx->request, iov_index, bdev_io->u.bdev.iovs[iov_index].iov_base, bdev_io->u.bdev.iovs[iov_index].iov_len,);
		current_iov = bdev_io->u.bdev.iovs + iov_index;
		current_start = current_iov->iov_base;
		current_end = current_iov->iov_base + current_iov->iov_len;
		current_address = current_start + remaining_bytes;
		remaining_bytes = 0;

		while (current_address < current_end) {
			// Copy IV to the temporary buffer
			memcpy(io_ctx->request->IVs + current_block_index * IV_LENGTH, current_address + INTEGRITY_LENGTH, IV_LENGTH);

			// Copy it also to the corresponding sector request data and set the request information
			if (global_freshness_config.eventual_consistency) {
				memcpy(io_ctx->request->sector_requests[current_block_index].request_data.new_IV, io_ctx->request->IVs + current_block_index * IV_LENGTH, IV_LENGTH);
				memset(io_ctx->request->sector_requests[current_block_index].request_data.old_IV, 0, IV_LENGTH); // old IV will be filled later from the cache
				io_ctx->request->sector_requests[current_block_index].request_data.sector = bdev_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start;
				// io_ctx->request->sector_requests[current_block_index].request_data.is_hashed = 0;
				// io_ctx->request->sector_requests[current_block_index].request_data.is_commited = 0;
				io_ctx->request->sector_requests[current_block_index].request_data.sequence_number = 0; // 0 is uncommited sequence number
			}

			// Verify IPsec
			if (global_freshness_config.ipsec) {
				ipsec_verify_recv_hash(current_address + INTEGRITY_LENGTH);
				uint64_t counter;
				memcpy(&counter, current_address + INTEGRITY_LENGTH + IV_LENGTH, NETWORK_FRESHNESS_PACKET_SIZE);
				ipsec_verify_recv_counter(counter);
			}

			// Move around because of interleaving of block and metadata
			current_block_index++;
			current_address += METADATA_SIZE + BLOCK_SIZE;
			if (current_address >= current_end) {
				remaining_bytes = current_address - current_end;
				break;
			}
		}
	}
	if (current_block_index != bdev_io->u.bdev.num_blocks) SPDK_ERRLOG("Mismatch of block numbers %ld %ld\n", current_block_index, bdev_io->u.bdev.num_blocks);
	
	// With the current IOV sizes, we assume the blocks should not span more than two superblocks
	size_t real_start_block_address = bdev_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start;
	size_t real_end_block_address = real_start_block_address + bdev_io->u.bdev.num_blocks - 1;
	size_t start_superblock = real_start_block_address / LEAF_BRANCHING_FACTOR;
	size_t end_superblock = real_end_block_address / LEAF_BRANCHING_FACTOR;
	atomic_store_explicit(&io_ctx->request->superblocks, end_superblock - start_superblock + 1, memory_order_relaxed);
	if (atomic_load_explicit(&io_ctx->request->superblocks, memory_order_relaxed) > 2) SPDK_ERRLOG("There are more than two superblocks to check!\n");

	if (global_freshness_config.eventual_consistency) { // && !KEEP_METADATA_FRESH
		io_ctx->request->superblocks_to_be_preprocessed = end_superblock - start_superblock + 1;
		atomic_store_explicit(&io_ctx->request->remaining_checks, end_superblock - start_superblock + 1, memory_order_relaxed);

		// Check the cache for the previous IVs and add them in case they are there
		// size_t within_request_index = 0;
		// for (size_t current_superblock = start_superblock; current_superblock <= end_superblock; current_superblock++) {
		// 	struct list_head *list = &cache->hash_map[current_superblock % CACHE_MAP_LENGTH];
		// 	spdk_spin_lock(&cache->lock);
		// 	struct cache_entry *entry = find_element_entries(list, current_superblock); // Note this returns locked so we need to unlock it later
		// 	if (entry == NULL) { // Check writeback if entry is not found
		// 		list = &cache->writeback_hash_map[current_superblock % CACHE_MAP_LENGTH];
		// 		entry = find_writeback_element_entries(list, current_superblock); 
		// 	}
	    //     if (entry)
	    //         //spdk_spin_lock(&entry->lock);
		// 		pthread_spin_lock(&entry->lock);

	    //     spdk_spin_unlock(&cache->lock);
			
		// 	// Offset within the superblocks
		// 	size_t start;
		// 	size_t end = MIN(real_end_block_address - current_superblock * LEAF_BRANCHING_FACTOR + 1, LEAF_BRANCHING_FACTOR);
		// 	if (current_superblock == start_superblock) {
		// 		start = real_start_block_address - current_superblock * LEAF_BRANCHING_FACTOR;
		// 	} else {
		// 		start = 0;
		// 	}

		// 	// Get the status of the entry
		// 	enum status status;
		// 	if (entry) status = entry->status;

		// Iterate over the elements in the superblock
		// for (size_t i = start; i < end; i++) {
		// 	if (within_request_index >= io_ctx->request->num_sectors) break;
		// 	void *current_location = io_ctx->request->sector_requests[within_request_index].request_data.old_IV;
		// 	if (entry && (status == PROCESSED || status == WRITEBACK || status == FETCHED)) {
		// 		memcpy(current_location, entry->data + i * IV_LENGTH, IV_LENGTH);
		// 	} else {
		// 		memset(current_location, 0, IV_LENGTH); // If the entry is not there, we fill it with 0 to indicate that we don't have the IV
		// 	}
		// 	within_request_index++;
		// }
		// 	if (entry) pthread_spin_unlock(&entry->lock); //spdk_spin_unlock(&entry->lock);
		// }
		// if (within_request_index != io_ctx->request->num_sectors) {
		// 	SPDK_ERRLOG("Mismatch of IVs gathered %zu %zu\n", within_request_index, io_ctx->request->num_sectors);
		// }
		// if (!global_freshness_config.keep_metadata_fresh) schedule_final_write(bdev_io);
		// else atomic_store_explicit(&io_ctx->request->remaining_checks, end_superblock - start_superblock + 1, memory_order_relaxed);
		// printf("copied %s: %ld\n", hexdump(io_ctx->request->IVs, sizeof(uint64_t)), *(uint64_t *)io_ctx->request->IVs);

		// printf("[%ld] %p: %ld gathered IVs: %s\n", spdk_get_ticks(), io_ctx->request, current_block_index, hexdump(io_ctx->request->IVs, current_block_index * IV_LENGTH));
	}
	for (size_t current_superblock = start_superblock; current_superblock < end_superblock + 1; current_superblock++) {
		//SPDK_NOTICELOG("Scheduling %p: %ld with start %ld (%p) and tree start %ld (%p) \n", bdev_io, current_superblock, bdev_io->u.bdev.offset_blocks, &bdev_io->u.bdev.offset_blocks, io_ctx->request->bdev->hashing_tree.data_start, io_ctx->request->bdev);
		//find_or_schedule_entry(io_ctx->request->bdev->cache, current_superblock, io_ctx->request->base_ch, global_freshness_config.eventual_consistency, freshness_update_IVs, io_ctx->request); 
		request_cache_block(current_superblock, io_ctx->request, freshness_update_IVs);
	}
}

/* Completion callback for IO that were issued from this bdev which checks
 * the freshness of the read block. We assume here only one block writes/reads.
 */
static void
freshness_verify_read(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	// SPDK_NOTICELOG("Reading %p\n", orig_io);
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)orig_io->driver_ctx;

	if (atomic_load_explicit(&io_ctx->request->bdev->hashing_tree.initialized, memory_order_acquire) != 2) {
		SPDK_ERRLOG("Submitted unitialized read request %ld with status: %d \n", orig_io->u.bdev.offset_blocks, atomic_load(&io_ctx->request->bdev->hashing_tree.initialized));
	} else if (success) {
		// We first oportunistically check the MD cache, if this fails, we conduct a full fledged check 
		// Verify the authenticity of the MD cached parent hashes of each element, and check if the cache matches the parent
		struct hash MAC;
		struct iovec *current_iov;
		size_t start_block_index = orig_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start;
		size_t current_block_index = start_block_index;
		bool need_full_check = false;

		void *current_start, *current_address, *current_end;
		size_t remaining_bytes = BLOCK_SIZE; 
		for (int iov_index = 0; iov_index < orig_io->u.bdev.iovcnt; iov_index++) {
			current_iov = orig_io->u.bdev.iovs + iov_index;
			current_start = current_iov->iov_base;
			current_end = current_iov->iov_base + current_iov->iov_len;
			current_address = current_start + remaining_bytes;
			remaining_bytes = 0;

			while (current_address < current_end) {
				if (*(uint64_t *)(current_address + INTEGRITY_LENGTH) == 0) {
					_pt_complete_io(bdev_io, success, orig_io);
					printf("Uninitialized read!\n");
					return;
				}

				// SPDK_NOTICELOG("HERE\n");
				if (!need_full_check) {
					// Check if the IV + cached parent are authentic
					hash(current_address + INTEGRITY_LENGTH, &MAC.hash, IV_LENGTH + HASH_LENGTH);
					// if (current_block_index == 0)
					// 	SPDK_NOTICELOG("Checking %ld %s : %s : %s\n", current_block_index, hexdump(current_address, INTEGRITY_LENGTH + IV_LENGTH + 2 * HASH_LENGTH), hexdump(&MAC.hash, HASH_LENGTH), hexdump(io_ctx->request->bdev->hashing_tree.hashes + current_block_index / LEAF_BRANCHING_FACTOR, HASH_LENGTH));
					// SPDK_NOTICELOG("%s %s\n", hexdump(&MAC.hash, HASH_LENGTH), hexdump(current_block_address + BLOCK_SIZE, METADATA_SIZE));
					if (memcmp(&MAC.hash, current_address + INTEGRITY_LENGTH + IV_LENGTH + HASH_LENGTH, HASH_LENGTH)) {
						// SPDK_ERRLOG("Fresshness broken\n");
						// Retry if possible
						// if (++io_ctx->request->retries > NUMBER_OF_RETRIES) {
						// 	SPDK_ERRLOG("Out of retries after broken freshness\n");
						// 	_pt_complete_io(bdev_io, false, orig_io);
						// } else {
						// 	SPDK_ERRLOG("Retrying after broken freshness for the %d time\n", io_ctx->request->retries);
						// 	pt_read_get_buf_cb(io_ctx->request->ch, orig_io, SPDK_BDEV_IO_STATUS_SUCCESS);
						// }
						// spdk_bdev_free_io(bdev_io);
						// return;

						need_full_check = true;
					}
					// Verify the IV - first check if the MD-cached parent is correct (fast path), if at least one fails, conduct a whole bdev_io check
					if (memcmp(current_address + INTEGRITY_LENGTH + IV_LENGTH, io_ctx->request->bdev->hashing_tree.hashes + current_block_index / LEAF_BRANCHING_FACTOR, HASH_LENGTH)) {
						// SPDK_NOTICELOG("Cache miss\n");
						need_full_check = true;
					}
				}

				// Copy IV to the temporary buffer
				memcpy(io_ctx->request->IVs + (current_block_index - start_block_index) * IV_LENGTH, current_address + INTEGRITY_LENGTH, IV_LENGTH);
				current_block_index++;

				// Add IPsec verification
				if (global_freshness_config.ipsec) {
					uint64_t counter = ipsec_get_send_counter();
					memcpy(current_address + INTEGRITY_LENGTH + IV_LENGTH, &counter, NETWORK_FRESHNESS_PACKET_SIZE);
					ipsec_authenticate_send(current_address + INTEGRITY_LENGTH);
				}
				
				// Move around because of interleaving of block and metadata
				current_address += METADATA_SIZE + BLOCK_SIZE;
				if (current_address >= current_end) {
					remaining_bytes = current_address - current_end;
					break;
				}
			}
		}

		// SPDK_NOTICELOG("Need full check @%ld? %s\n", (orig_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR, need_full_check ? "yes" : "no");

		// For evaluation, if the probabilistic check is set, use check ratio to set probabilistically need_full_check 
		if (global_freshness_config.freshness_probabilistic_check) {
			int threshold = 1 + rand() % 100;
			if (threshold <= global_freshness_config.freshness_check_ratio) {
				need_full_check = true;
			} else {
				need_full_check = false;
			}
			// SPDK_NOTICELOG("Probabilistic check: %s, threshold: %d, ratio: %d\n", 
			// 	need_full_check ? "true" : "false", threshold, global_freshness_config.freshness_check_ratio);
		}

		// Conduct the full check if needed
		if (need_full_check) {
			// With the current IOV sizes, we assume the blocks should not span more than two superblocks
			size_t start_superblock = (orig_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR;
			size_t end_superblock = (orig_io->u.bdev.offset_blocks + orig_io->u.bdev.num_blocks - 1 - io_ctx->request->bdev->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR;
			atomic_store_explicit(&io_ctx->request->remaining_checks, end_superblock - start_superblock + 1, memory_order_relaxed);
			if (atomic_load_explicit(&io_ctx->request->remaining_checks, memory_order_relaxed) > 2) SPDK_ERRLOG("There are more than two superblocks to check!\n");

			// SPDK_NOTICELOG("Scheduling %p\n", orig_io);
			for (size_t current_superblock = start_superblock; current_superblock < end_superblock + 1; current_superblock++) {
				request_cache_block(current_superblock, io_ctx->request, freshness_verify_IVs);
			}

			spdk_bdev_free_io(bdev_io);
			return;
		} 
		// else {
		// 	uint64_t start = io_ctx->request->start - io_ctx->request->bdev->hashing_tree.data_start;
		// 	printf("Fast path for %ld @ %ld\n", start, start / LEAF_BRANCHING_FACTOR);
		// }
	}
	// SPDK_NOTICELOG("Verified %p\n", orig_io);
	_pt_complete_io(bdev_io, success, orig_io);
}

// void freshness_complete_update(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
// 	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;
// 	spdk_bdev_free_io(bdev_io);
// }

static void
_pt_complete_zcopy_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;

	/* Complete the original IO and then free the one that we created here
	 * as a result of issuing an IO via submit_request.
	 */
	spdk_bdev_io_set_buf(orig_io, bdev_io->u.bdev.iovs[0].iov_base, bdev_io->u.bdev.iovs[0].iov_len);
	spdk_bdev_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

static void
vbdev_freshness_resubmit_io(void *arg)
{
	struct spdk_bdev_io *bdev_io = (struct spdk_bdev_io *)arg;
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)bdev_io->driver_ctx;

	vbdev_freshness_submit_request(io_ctx->ch, bdev_io);
}

static void
vbdev_freshness_queue_io(struct spdk_bdev_io *bdev_io)
{
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)bdev_io->driver_ctx;
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(io_ctx->ch);
	int rc;

	io_ctx->bdev_io_wait.bdev = bdev_io->bdev;
	io_ctx->bdev_io_wait.cb_fn = vbdev_freshness_resubmit_io;
	io_ctx->bdev_io_wait.cb_arg = bdev_io;

	/* Queue the IO using the channel of the base device. */
	rc = spdk_bdev_queue_io_wait(bdev_io->bdev, pt_ch->base_ch, &io_ctx->bdev_io_wait);
	if (rc != 0) {
		SPDK_ERRLOG("Queue io failed in vbdev_freshness_queue_io, rc=%d.\n", rc);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

/* Callback for getting a buf from the bdev pool in the event that the caller passed
 * in NULL, we need to own the buffer so it doesn't get freed by another vbdev module
 * beneath us before we're done with it. That won't happen in this example but it could
 * if this example were used as a template for something more complex.
 */
static void
pt_read_get_buf_cb(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io, bool success)
{
	struct vbdev_freshness *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_freshness,
					 pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)bdev_io->driver_ctx;
	int rc;

	// SPDK_NOTICELOG("Working on thread %p\n", spdk_get_thread());

	if (!success) {
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	// pt_init_ext_io_opts(bdev_io, &io_opts);
	rc = spdk_bdev_readv_blocks(pt_node->base_desc, pt_ch->base_ch, bdev_io->u.bdev.iovs,
									bdev_io->u.bdev.iovcnt, bdev_io->u.bdev.offset_blocks,
									bdev_io->u.bdev.num_blocks, freshness_verify_read,
									bdev_io);
	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory, start to queue io for freshness.\n");
			io_ctx->request->ch = ch;
			vbdev_freshness_queue_io(bdev_io);
		} else {
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

/* Called when someone above submits IO to this pt vbdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another bdev IO and call our cpl callback provided
 * below along with the original bdev_io so that we can complete it once this IO completes.
 */
static void
vbdev_freshness_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct vbdev_freshness *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_freshness, pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct freshness_bdev_io *io_ctx = (struct freshness_bdev_io *)bdev_io->driver_ctx;
	int rc = 0;

	// Make sure the tree is initialized. Initialize the tree and make sure noone else interrupts in the meantime
	// while (atomic_load(&hashing_tree.initialized) != 2) {}
	// 	SPDK_NOTICELOG("Waiting...\n");
	// }
	io_ctx->ch = ch;
	io_ctx->cycles = spdk_get_ticks();
	bdev_io->u.bdev.offset_blocks += pt_node->hashing_tree.data_start;
	bool registered = register_request(gather_write_IVs, bdev_io, &io_ctx->request);
	if (!registered) {
		SPDK_NOTICELOG("Run out of requests!\n");
		bdev_io->u.bdev.offset_blocks -= pt_node->hashing_tree.data_start;
		int result = spdk_thread_send_msg(spdk_get_thread(), vbdev_freshness_resubmit_io, bdev_io);
		if (result != 0) {
			SPDK_ERRLOG("Failed to send message to thread %p: %d\n", spdk_get_thread(), result);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
		return;
	}
	// int num_superblocks = (bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1 - pt_node->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR + 1 -
	// 	(bdev_io->u.bdev.offset_blocks - pt_node->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR;
	io_ctx->request->bdev = pt_node;
	io_ctx->request->ch = ch;
	io_ctx->request->base_ch = pt_ch->base_ch;
	// SPDK_NOTICELOG("Processing %p: %ld with type %d\n", bdev_io, bdev_io->u.bdev.offset_blocks, bdev_io->type);
	
	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		if (bdev_io->u.bdev.num_blocks > MAX_IO_SIZE) SPDK_ERRLOG("Reading more than 32 blocks\n");

		spdk_bdev_io_get_buf(bdev_io, pt_read_get_buf_cb,
				     bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);

		// TODO schedule the read of the cache parents without any function (NULL)
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		// SPDK_NOTICELOG("Submitting write\n");
		// SPDK_NOTICELOG("Writing block %ld: %s\n", bdev_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start, hexdump(bdev_io->u.bdev.iovs->iov_base + BLOCK_SIZE, METADATA_SIZE));
		// Serialize writes
		
		// printf("[%ld] Submitting request %p [%s] with start %ld and end %ld spanning %ld superblocks\n", spdk_get_ticks(), io_ctx->request, hexdump(io_ctx->request->bdev_io->u.bdev.iovs->iov_base, 2), bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1, num_superblocks);
		spdk_thread_send_msg(request_registry, schedule_request, io_ctx->request);
		// bool appended = schedule_request(io_ctx->request);
		// printf("received %s: %ld\n", hexdump(bdev_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH, sizeof(uint64_t)), 
			// *(uint64_t *)(bdev_io->u.bdev.iovs->iov_base + BLOCK_SIZE + INTEGRITY_LENGTH));
		// if (!appended) {
		// 	gather_write_IVs(bdev_io);
			// printf("[%ld] Running request %p with start %ld and end %ld\n", spdk_get_ticks(), io_ctx->request, bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1);
		//} // else printf("[%ld] Appended request %p with start %ld and end %ld\n", spdk_get_ticks(), io_ctx->request, bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.offset_blocks + bdev_io->u.bdev.num_blocks - 1);

		// find_or_schedule_entry(pt_node->cache,
		// 					   (bdev_io->u.bdev.offset_blocks - io_ctx->request->bdev->hashing_tree.data_start) / LEAF_BRANCHING_FACTOR,
		// 					   pt_ch->base_ch,
		// 					   freshness_check_write, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		rc = spdk_bdev_write_zeroes_blocks(pt_node->base_desc, pt_ch->base_ch,
						   bdev_io->u.bdev.offset_blocks,
						   bdev_io->u.bdev.num_blocks,
						   _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_UNMAP:
		rc = spdk_bdev_unmap_blocks(pt_node->base_desc, pt_ch->base_ch,
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks,
					    _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_FLUSH:
		rc = spdk_bdev_flush_blocks(pt_node->base_desc, pt_ch->base_ch,
					    bdev_io->u.bdev.offset_blocks,
					    bdev_io->u.bdev.num_blocks,
					    _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_RESET:
		rc = spdk_bdev_reset(pt_node->base_desc, pt_ch->base_ch,
				     _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_ZCOPY:
		rc = spdk_bdev_zcopy_start(pt_node->base_desc, pt_ch->base_ch, NULL, 0,
					   bdev_io->u.bdev.offset_blocks,
					   bdev_io->u.bdev.num_blocks, bdev_io->u.bdev.zcopy.populate,
					   _pt_complete_zcopy_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_ABORT:
		rc = spdk_bdev_abort(pt_node->base_desc, pt_ch->base_ch, bdev_io->u.abort.bio_to_abort,
				     _pt_complete_io, bdev_io);
		break;
	case SPDK_BDEV_IO_TYPE_COPY:
		rc = spdk_bdev_copy_blocks(pt_node->base_desc, pt_ch->base_ch,
					   bdev_io->u.bdev.offset_blocks,
					   bdev_io->u.bdev.copy.src_offset_blocks,
					   bdev_io->u.bdev.num_blocks,
					   _pt_complete_io, bdev_io);
		break;
	default:
		SPDK_ERRLOG("freshness: unknown I/O type %d\n", bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory, start to queue io for freshness.\n");
			io_ctx->request->ch = ch;
			vbdev_freshness_queue_io(bdev_io);
		} else {
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

/* We'll just call the base bdev and let it answer however if we were more
 * restrictive for some reason (or less) we could get the response back
 * and modify according to our purposes.
 */
static bool
vbdev_freshness_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct vbdev_freshness *pt_node = (struct vbdev_freshness *)ctx;

	return spdk_bdev_io_type_supported(pt_node->base_bdev, io_type);
}

/* We supplied this as an entry point for upper layers who want to communicate to this
 * bdev.  This is how they get a channel. We are passed the same context we provided when
 * we created our PT vbdev in examine() which, for this bdev, is the address of one of
 * our context nodes. From here we'll ask the SPDK channel code to fill out our channel
 * struct and we'll keep it in our PT node.
 */
static struct spdk_io_channel *
vbdev_freshness_get_io_channel(void *ctx)
{
	struct vbdev_freshness *pt_node = (struct vbdev_freshness *)ctx;
	struct spdk_io_channel *pt_ch = NULL;

	/* The IO channel code will allocate a channel for us which consists of
	 * the SPDK channel structure plus the size of our pt_io_channel struct
	 * that we passed in when we registered our IO device. It will then call
	 * our channel create callback to populate any elements that we need to
	 * update.
	 */
	pt_ch = spdk_get_io_channel(pt_node);

	return pt_ch;
}

/* This is the output for bdev_get_bdevs() for this vbdev */
static int
vbdev_freshness_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct vbdev_freshness *pt_node = (struct vbdev_freshness *)ctx;

	spdk_json_write_name(w, "freshness");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&pt_node->pt_bdev));
	spdk_json_write_named_string(w, "base_bdev_name", spdk_bdev_get_name(pt_node->base_bdev));
	spdk_json_write_object_end(w);

	return 0;
}

/* This is used to generate JSON that can configure this module to its current state. */
static int
vbdev_freshness_config_json(struct spdk_json_write_ctx *w)
{
	struct vbdev_freshness *pt_node;

	TAILQ_FOREACH(pt_node, &g_pt_nodes, link) {
		const struct spdk_uuid *uuid = spdk_bdev_get_uuid(&pt_node->pt_bdev);

		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "bdev_freshness_create");
		spdk_json_write_named_object_begin(w, "params");
		spdk_json_write_named_string(w, "base_bdev_name", spdk_bdev_get_name(pt_node->base_bdev));
		spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&pt_node->pt_bdev));
		if (!spdk_uuid_is_null(uuid)) {
			spdk_json_write_named_uuid(w, "uuid", uuid);
		}
		spdk_json_write_object_end(w);
		spdk_json_write_object_end(w);
	}
	return 0;
}

/* We provide this callback for the SPDK channel code to create a channel using
 * the channel struct we provided in our module get_io_channel() entry point. Here
 * we get and save off an underlying base channel of the device below us so that
 * we can communicate with the base bdev on a per channel basis.  If we needed
 * our own poller for this vbdev, we'd register it here.
 */
static int
pt_bdev_ch_create_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;
	struct vbdev_freshness *pt_node = io_device;

	pt_ch->base_ch = spdk_bdev_get_io_channel(pt_node->base_desc);
	SPDK_NOTICELOG("Channel theirs %p\n", pt_ch->base_ch);

	return 0;
}

/* We provide this callback for the SPDK channel code to destroy a channel
 * created with our create callback. We just need to undo anything we did
 * when we created. If this bdev used its own poller, we'd unregister it here.
 */
static void
pt_bdev_ch_destroy_cb(void *io_device, void *ctx_buf)
{
	struct pt_io_channel *pt_ch = ctx_buf;

	spdk_put_io_channel(pt_ch->base_ch);
}

/* Create the freshness association from the bdev and vbdev name and insert
 * on the global list. */
static int
vbdev_freshness_insert_name(const char *bdev_name, const char *vbdev_name,
			   const struct spdk_uuid *uuid)
{
	struct bdev_names *name;

	TAILQ_FOREACH(name, &g_bdev_names, link) {
		if (strcmp(vbdev_name, name->vbdev_name) == 0) {
			SPDK_ERRLOG("freshness bdev %s already exists\n", vbdev_name);
			return -EEXIST;
		}
	}

	name = calloc(1, sizeof(struct bdev_names));
	if (!name) {
		SPDK_ERRLOG("could not allocate bdev_names\n");
		return -ENOMEM;
	}

	name->bdev_name = strdup(bdev_name);
	if (!name->bdev_name) {
		SPDK_ERRLOG("could not allocate name->bdev_name\n");
		free(name);
		return -ENOMEM;
	}

	name->vbdev_name = strdup(vbdev_name);
	if (!name->vbdev_name) {
		SPDK_ERRLOG("could not allocate name->vbdev_name\n");
		free(name->bdev_name);
		free(name);
		return -ENOMEM;
	}

	spdk_uuid_copy(&name->uuid, uuid);
	TAILQ_INSERT_TAIL(&g_bdev_names, name, link);

	return 0;
}

/* On init, just perform bdev module specific initialization. */
static int
vbdev_freshness_init(void)
{
	return 0;
}

/* Called when the entire module is being torn down. */
static void
vbdev_freshness_finish(void)
{
	struct bdev_names *name;

	while ((name = TAILQ_FIRST(&g_bdev_names))) {
		TAILQ_REMOVE(&g_bdev_names, name, link);
		free(name->bdev_name);
		free(name->vbdev_name);
		free(name);
	}
}

/* During init we'll be asked how much memory we'd like passed to us
 * in bev_io structures as context. Here's where we specify how
 * much context we want per IO.
 */
static int
vbdev_freshness_get_ctx_size(void)
{
	return sizeof(struct freshness_bdev_io);
}

/* Where vbdev_freshness_config_json() is used to generate per module JSON config data, this
 * function is called to output any per bdev specific methods. For the PT module, there are
 * none.
 */
static void
vbdev_freshness_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	/* No config per bdev needed */
}

static int
vbdev_freshness_get_memory_domains(void *ctx, struct spdk_memory_domain **domains, int array_size)
{
	struct vbdev_freshness *pt_node = (struct vbdev_freshness *)ctx;

	/* freshness bdev doesn't work with data buffers, so it supports any memory domain used by base_bdev */
	return spdk_bdev_get_memory_domains(pt_node->base_bdev, domains, array_size);
}

/* When we register our bdev this is how we specify our entry points. */
static const struct spdk_bdev_fn_table vbdev_freshness_fn_table = {
	.destruct		= vbdev_freshness_destruct,
	.submit_request		= vbdev_freshness_submit_request,
	.io_type_supported	= vbdev_freshness_io_type_supported,
	.get_io_channel		= vbdev_freshness_get_io_channel,
	.dump_info_json		= vbdev_freshness_dump_info_json,
	.write_config_json	= vbdev_freshness_write_config_json,
	.get_memory_domains	= vbdev_freshness_get_memory_domains,
};

static void
vbdev_freshness_base_bdev_hotremove_cb(struct spdk_bdev *bdev_find)
{
	struct vbdev_freshness *pt_node, *tmp;

	TAILQ_FOREACH_SAFE(pt_node, &g_pt_nodes, link, tmp) {
		if (bdev_find == pt_node->base_bdev) {
			spdk_bdev_unregister(&pt_node->pt_bdev, NULL, NULL);
		}
	}
}

/* Called when the underlying base bdev triggers asynchronous event such as bdev removal. */
static void
vbdev_freshness_base_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
				  void *event_ctx)
{
	switch (type) {
	case SPDK_BDEV_EVENT_REMOVE:
		vbdev_freshness_base_bdev_hotremove_cb(bdev);
		break;
	default:
		SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
		break;
	}
}

/* Create and register the freshness vbdev if we find it in our list of bdev names.
 * This can be called either by the examine path or RPC method.
 */
static int
vbdev_freshness_register(const char *bdev_name)
{
	struct bdev_names *name;
	struct vbdev_freshness *pt_node;
	struct spdk_bdev *bdev;
	struct spdk_uuid ns_uuid;
	int rc = 0;

	spdk_uuid_parse(&ns_uuid, BDEV_freshness_NAMESPACE_UUID);

	/* Check our list of names from config versus this bdev and if
	 * there's a match, create the pt_node & bdev accordingly.
	 */
	TAILQ_FOREACH(name, &g_bdev_names, link) {
		if (strcmp(name->bdev_name, bdev_name) != 0) {
			continue;
		}

		SPDK_NOTICELOG("Match on %s\n", bdev_name);
		pt_node = calloc(1, sizeof(struct vbdev_freshness));
		if (!pt_node) {
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_node\n");
			break;
		}

		pt_node->pt_bdev.name = strdup(name->vbdev_name);
		if (!pt_node->pt_bdev.name) {
			rc = -ENOMEM;
			SPDK_ERRLOG("could not allocate pt_bdev name\n");
			free(pt_node);
			break;
		}
		pt_node->pt_bdev.product_name = "freshness";

		/* The base bdev that we're attaching to. */
		rc = spdk_bdev_open_ext(bdev_name, true, vbdev_freshness_base_bdev_event_cb,
					NULL, &pt_node->base_desc);
		if (rc) {
			if (rc != -ENODEV) {
				SPDK_ERRLOG("could not open bdev %s\n", bdev_name);
			}
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("base bdev opened\n");

		bdev = spdk_bdev_desc_get_bdev(pt_node->base_desc);
		pt_node->base_bdev = bdev;

		if (!spdk_uuid_is_null(&name->uuid)) {
			/* Use the configured UUID */
			spdk_uuid_copy(&pt_node->pt_bdev.uuid, &name->uuid);
		} else {
			/* Generate UUID based on namespace UUID + base bdev UUID. */
			rc = spdk_uuid_generate_sha1(&pt_node->pt_bdev.uuid, &ns_uuid,
						     (const char *)&pt_node->base_bdev->uuid, sizeof(struct spdk_uuid));
			if (rc) {
				SPDK_ERRLOG("Unable to generate new UUID for freshness bdev\n");
				spdk_bdev_close(pt_node->base_desc);
				free(pt_node->pt_bdev.name);
				free(pt_node);
				break;
			}
		}

		/* Copy some properties from the underlying base bdev. */
		pt_node->pt_bdev.write_cache = bdev->write_cache;
		pt_node->pt_bdev.required_alignment = bdev->required_alignment;
		pt_node->pt_bdev.optimal_io_boundary = bdev->optimal_io_boundary;
		pt_node->pt_bdev.blocklen = bdev->blocklen;
		pt_node->pt_bdev.blockcnt = bdev->blockcnt - create_hash_tree(&pt_node->hashing_tree, pt_node->base_bdev->blockcnt);
		pt_node->cache = (struct cache *)malloc(sizeof(struct cache));

		initialize_cache_registry(pt_node->cache, pt_node);
		initialize_global_constants();
		initialize_request_registry();
		launch_hashing_threads(&pt_node->hashing_tree);

		pt_node->pt_bdev.md_interleave = bdev->md_interleave;
		pt_node->pt_bdev.md_len = bdev->md_len;
		pt_node->pt_bdev.dif_type = bdev->dif_type;
		pt_node->pt_bdev.dif_is_head_of_md = bdev->dif_is_head_of_md;
		pt_node->pt_bdev.dif_check_flags = bdev->dif_check_flags;
		pt_node->pt_bdev.dif_pi_format = bdev->dif_pi_format;

		/* This is the context that is passed to us when the bdev
		 * layer calls in so we'll save our pt_bdev node here.
		 */
		pt_node->pt_bdev.ctxt = pt_node;
		pt_node->pt_bdev.fn_table = &vbdev_freshness_fn_table;
		pt_node->pt_bdev.module = &freshness_if;
		TAILQ_INSERT_TAIL(&g_pt_nodes, pt_node, link);

		spdk_io_device_register(pt_node, pt_bdev_ch_create_cb, pt_bdev_ch_destroy_cb,
					sizeof(struct pt_io_channel),
					name->vbdev_name);
		SPDK_NOTICELOG("io_device created at: 0x%p\n", pt_node);

		/* Save the thread where the base device is opened */
		pt_node->thread = spdk_get_thread();

		rc = spdk_bdev_module_claim_bdev(bdev, pt_node->base_desc, pt_node->pt_bdev.module);
		if (rc) {
			SPDK_ERRLOG("could not claim bdev %s\n", bdev_name);
			spdk_bdev_close(pt_node->base_desc);
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("bdev claimed\n");

		rc = spdk_bdev_register(&pt_node->pt_bdev);
		if (rc) {
			SPDK_ERRLOG("could not register pt_bdev\n");
			spdk_bdev_module_release_bdev(&pt_node->pt_bdev);
			spdk_bdev_close(pt_node->base_desc);
			TAILQ_REMOVE(&g_pt_nodes, pt_node, link);
			spdk_io_device_unregister(pt_node, NULL);
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("pt_bdev registered\n");
		SPDK_NOTICELOG("created pt_bdev for: %s\n", name->vbdev_name);

		// We assume that the initilization happens only on one of the threads
		pt_node->initialization_ch = spdk_bdev_get_io_channel(pt_node->base_desc);
		SPDK_NOTICELOG("Channel ours %p\n", pt_node->initialization_ch);
		initialize_tree(&pt_node->hashing_tree, pt_node->base_desc, pt_node->initialization_ch);
	}

	return rc;
}

/* Create the freshness disk from the given bdev and vbdev name. */
int
bdev_freshness_create_disk(const char *bdev_name, const char *vbdev_name,
			  const struct spdk_uuid *uuid)
{
	int rc;

	/* Insert the bdev name into our global name list even if it doesn't exist yet,
	 * it may show up soon...
	 */
	rc = vbdev_freshness_insert_name(bdev_name, vbdev_name, uuid);
	if (rc) {
		return rc;
	}

	rc = vbdev_freshness_register(bdev_name);
	if (rc == -ENODEV) {
		/* This is not an error, we tracked the name above and it still
		 * may show up later.
		 */
		SPDK_NOTICELOG("vbdev creation deferred pending base bdev arrival\n");
		rc = 0;
	}

	return rc;
}

void
bdev_freshness_delete_disk(const char *bdev_name, spdk_bdev_unregister_cb cb_fn, void *cb_arg)
{
	struct bdev_names *name;
	int rc;

	/* Cleanup the per device freshness tree. */


	/* Some cleanup happens in the destruct callback. */
	rc = spdk_bdev_unregister_by_name(bdev_name, &freshness_if, cb_fn, cb_arg);
	if (rc == 0) {
		/* Remove the association (vbdev, bdev) from g_bdev_names. This is required so that the
		 * vbdev does not get re-created if the same bdev is constructed at some other time,
		 * unless the underlying bdev was hot-removed.
		 */
		TAILQ_FOREACH(name, &g_bdev_names, link) {
			if (strcmp(name->vbdev_name, bdev_name) == 0) {
				TAILQ_REMOVE(&g_bdev_names, name, link);
				free(name->bdev_name);
				free(name->vbdev_name);
				free(name);
				break;
			}
		}
	} else {
		cb_fn(cb_arg, rc);
	}
}

/* Because we specified this function in our pt bdev function table when we
 * registered our pt bdev, we'll get this call anytime a new bdev shows up.
 * Here we need to decide if we care about it and if so what to do. We
 * parsed the config file at init so we check the new bdev against the list
 * we built up at that time and if the user configured us to attach to this
 * bdev, here's where we do it.
 */
static void
vbdev_freshness_examine(struct spdk_bdev *bdev)
{
	vbdev_freshness_register(bdev->name);

	spdk_bdev_module_examine_done(&freshness_if);
}

SPDK_LOG_REGISTER_COMPONENT(vbdev_freshness)
