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

#include "vbdev_integrity.h"
#include "spdk/rpc.h"
#include "spdk/env.h"
#include "spdk/endian.h"
#include "spdk/string.h"
#include "spdk/thread.h"
#include "spdk/util.h"
#include "spdk/event.h"
#include <stdatomic.h>

#include "spdk/bdev_module.h"
#include "spdk/log.h"
#include "doca_log.h"
#include "doca_buf.h"
#include "doca_mmap.h"
#include "doca_error.h"
#include "doca_ctx.h"
#include "doca_aes_gcm.h"
#include <doca_buf_inventory.h>
#include "doca_utils.h"
#include "math.h"
#include "doca_pe.h"
#include "ipsec.h"

DOCA_LOG_REGISTER(INTEGRITY);

struct spdk_event *event;

/* This namespace UUID was generated using uuid_generate() method. */
#define BDEV_PASSTHRU_NAMESPACE_UUID "7e25812e-c8c0-4d3f-8599-16d790555b75"

static int vbdev_integrity_init(void);
static int vbdev_integrity_get_ctx_size(void);
static void vbdev_integrity_examine(struct spdk_bdev *bdev);
static void vbdev_integrity_finish(void);
static int vbdev_integrity_config_json(struct spdk_json_write_ctx *w);
void pass(void *);
static void get_IV_allocation(uint64_t *IV_start, uint64_t *IV_end, struct spdk_spinlock *lock, size_t *device_IV, size_t *device_IV_limit);
extern struct iobuf g_iobuf;

static struct spdk_bdev_module integrity_if = {
	.name = "integrity",
	.module_init = vbdev_integrity_init,
	.get_ctx_size = vbdev_integrity_get_ctx_size,
	.examine_config = vbdev_integrity_examine,
	.module_fini = vbdev_integrity_finish,
	.config_json = vbdev_integrity_config_json
};

SPDK_BDEV_MODULE_REGISTER(integrity, &integrity_if)

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
struct vbdev_integrity {
	struct spdk_bdev		*base_bdev; /* the thing we're attaching to */
	struct spdk_bdev_desc	*base_desc; /* its descriptor we get from open */
	struct spdk_bdev		pt_bdev;    /* the PT virtual bdev */
	TAILQ_ENTRY(vbdev_integrity)	link;
	struct spdk_thread		*thread;    /* thread where base device is opened */
	struct spdk_spinlock	IV_lock; 	/* used for IV assignment locking */
	size_t device_IV;
	size_t device_IV_limit;
};
static TAILQ_HEAD(, vbdev_integrity) g_pt_nodes = TAILQ_HEAD_INITIALIZER(g_pt_nodes);

/* The pt vbdev channel struct. It is allocated and freed on my behalf by the io channel code.
 * If this vbdev needed to implement a poller or a queue for IO, this is where those things
 * would be defined. This integrity bdev doesn't actually need to allocate a channel, it could
 * simply pass back the channel of the bdev underneath it but for example purposes we will
 * present its own to the upper layers.
 * 
 * Each IO channel contains a doca config which after initialization has:
 * - opened device
 * - initialized AES-GCM engine
 * - started context 
 * - initialized progress engine
 * - initialized key
 * - buffer inventory
 */
struct pt_io_channel {
	struct spdk_io_channel		*base_ch; /* IO channel of base device */
	struct spdk_poller			*poller_submit;
	struct spdk_poller			*poller_complete;
	uint64_t 					IV; // represents the current IV that is being used TODO the IV should be a longer field such as using C23's _BitInt(N)
	uint64_t 					IV_limit; // represents the IV limit afer which another IV needs to be requested from the KBS
	struct doca_config			doca_config; 
};

struct integrity_bdev_io {
	/* for the read task */
	size_t remaining_tasks;
	size_t start_buffer_index;
	struct iovec iovs[10];
	size_t iovcnt;
	size_t cycles;

	/* bdev related */
	struct spdk_io_channel *ch;

	/* for bdev_io_wait */
	struct spdk_bdev_io_wait_entry bdev_io_wait;
};

static void vbdev_integrity_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io);

/* Callback for unregistering the IO device. */
static void
_device_unregister_cb(void *io_device)
{
	struct vbdev_integrity *pt_node  = io_device;

	/* Done with this pt_node. */
	free(pt_node->pt_bdev.name);
	free(pt_node);
}

/* Wrapper for the bdev close operation. */
static void
_vbdev_integrity_destruct(void *ctx)
{
	struct spdk_bdev_desc *desc = ctx;

	spdk_bdev_close(desc);
}

/* Called after we've unregistered following a hot remove callback.
 * Our finish entry point will be called next.
 */
static int
vbdev_integrity_destruct(void *ctx)
{
	struct vbdev_integrity *pt_node = (struct vbdev_integrity *)ctx;

	/* It is important to follow this exact sequence of steps for destroying
	 * a vbdev...
	 */

	TAILQ_REMOVE(&g_pt_nodes, pt_node, link);

	/* Unclaim the underlying bdev. */
	spdk_bdev_module_release_bdev(pt_node->base_bdev);

	/* Close the underlying bdev on its same opened thread. */
	if (pt_node->thread && pt_node->thread != spdk_get_thread()) {
		spdk_thread_send_msg(pt_node->thread, _vbdev_integrity_destruct, pt_node->base_desc);
	} else {
		spdk_bdev_close(pt_node->base_desc);
	}

	/* Unregister the io_device. */
	spdk_io_device_unregister(pt_node, _device_unregister_cb);

	return 0;
}

/* Allocates the IV by contacting the KBS for another range.
*/
static void get_IV_allocation(size_t *IV_start, size_t *IV_end, struct spdk_spinlock *lock, size_t *device_IV, size_t *device_IV_limit) {
	spdk_spin_lock(lock);
	if (*device_IV == *device_IV_limit) {
		// For now implemented simply as an increase in the range
		// TODO implement communication with the KBS
		*device_IV_limit += 0xFFFFFFFFFF; // 1T
	}
	size_t length = 0xFFFFFFF; // 256M
	*IV_start = *device_IV;
	*IV_end = (*IV_start) + length;
	*device_IV += length;
	spdk_spin_unlock(lock);
}

static inline void integrity_return_iov_bufs(struct spdk_bdev_io *bdev_io) {
    for (int i = 0; i < bdev_io->u.bdev.iovcnt; i++) {
        void *elem = bdev_io->u.bdev.iovs[i].iov_base;
        if (elem) (void)spdk_ring_enqueue(g_iobuf.small_pool, &elem, 1, NULL);
    }
	spdk_free(bdev_io->u.bdev.iovs);
    bdev_io->u.bdev.iovcnt = 0;
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
	
	/* Complete the original IO and then free the one that we created here
	 * as a result of issuing an IO via submit_request.
	 */
	// double time = (double)(spdk_get_ticks() - ((struct integrity_bdev_io *)orig_io->driver_ctx)->cycles) / spdk_get_ticks_hz();
	// if (time > 1) {
	// 	SPDK_ERRLOG("%.6f\n", time);
	// }
	spdk_bdev_io_complete(orig_io, status);
	spdk_bdev_free_io(bdev_io);
}

/* Completion callback for IO that were issued from this bdev. The original bdev_io
 * is passed in as an arg so we'll complete that one with the appropriate status
 * and then free the one that this module issued.
 */
static void
_pt_complete_crypto_io(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
{
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)orig_io->driver_ctx;

	if (--io_ctx->remaining_tasks == 0) {
		/* Complete the original IO and then free the one that we created here
		* as a result of issuing an IO via submit_request
		*/
		// double time = (double)(spdk_get_ticks() - io_ctx->cycles) / spdk_get_ticks_hz();
		// if (time > 1) {
		// 	SPDK_ERRLOG("%.6f\n", time);
		// }
		spdk_bdev_io_complete(orig_io, status);
	}
	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);
}

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
vbdev_integrity_resubmit_io(void *arg)
{
	struct resubmission_task *task = (struct resubmission_task *)arg;
	struct buffer *current_buffer = (struct buffer *)task->task_user_data.ptr;
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
		encrypt_completed_callback(task->encrypt_task, task->task_user_data, task->ctx_user_data);
		free(task);
		break;
	default:
		vbdev_integrity_submit_request(io_ctx->ch, bdev_io);
	}
}

static void
vbdev_integrity_queue_encrypt_io(struct resubmission_task *task)
{
	struct buffer *current_buffer = (struct buffer *)task->task_user_data.ptr;
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(io_ctx->ch);
	int rc;

	io_ctx->bdev_io_wait.bdev = bdev_io->bdev;
	io_ctx->bdev_io_wait.cb_fn = vbdev_integrity_resubmit_io;
	io_ctx->bdev_io_wait.cb_arg = task;

	/* Queue the IO using the channel of the base device. */
	rc = spdk_bdev_queue_io_wait(bdev_io->bdev, pt_ch->base_ch, &io_ctx->bdev_io_wait);
	if (rc != 0) {
		SPDK_ERRLOG("Queue io failed in vbdev_integrity_queue_io, rc=%d.\n", rc);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
	}
}

void encrypt_completed_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
							    union doca_data task_user_data,
								union doca_data ctx_user_data)
{
	struct spdk_io_channel *ch = (struct spdk_io_channel *)ctx_user_data.ptr;
	struct buffer *current_buffer = (struct buffer *)task_user_data.ptr;
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;	
	struct vbdev_integrity *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_integrity, pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	int rc = 0;

	// Add IPsec header
	if (IPSEC_ENABLED) {
		uint64_t counter = ipsec_get_send_counter();
		memcpy(current_buffer->temporary_metadata->network_freshness_counter, &counter, NETWORK_FRESHNESS_PACKET_SIZE);
		ipsec_authenticate_send((uint8_t *)&current_buffer->temporary_metadata->IV);
	}

	if (--io_ctx->remaining_tasks == 0) {
		rc = spdk_bdev_writev_blocks(pt_node->base_desc, pt_ch->base_ch,
										 io_ctx->iovs, io_ctx->iovcnt,
										 bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks,
										 _pt_complete_io,
										 bdev_io);
 	}

	if (rc != 0) {
		if (rc == -ENOMEM) {
			struct resubmission_task *task = (struct resubmission_task *)malloc(sizeof(struct resubmission_task));
			task->encrypt_task = encrypt_task;
			task->task_user_data = task_user_data;
			task->ctx_user_data = ctx_user_data;
			SPDK_ERRLOG("No memory, start to queue io for integrity.\n");
			io_ctx->ch = ch;
			vbdev_integrity_queue_encrypt_io(task);
		} else {
			SPDK_ERRLOG("ERROR %d on bdev_io submission!\n", -rc);
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}
}

void encrypt_error_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
			    			union doca_data task_user_data,
			    			union doca_data ctx_user_data)
{
	struct doca_task *task = doca_aes_gcm_task_encrypt_as_task(encrypt_task);
	DOCA_LOG_ERR("Encrypt task failed: %s", doca_error_get_descr(doca_task_get_status(task)));
	struct buffer *current_buffer = (struct buffer *)task_user_data.ptr;
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;
	spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
}

void decrypt_completed_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
								union doca_data task_user_data,
								union doca_data ctx_user_data)
{
	struct buffer *current_buffer = (struct buffer *)task_user_data.ptr;
	// printf("Completed %d, in buffer %d\n", current_buffer->block_offset, current_buffer->ticks);
	// printb(current_buffer);
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;

	// Now verify the IPsec
	if (IPSEC_ENABLED) {
		ipsec_verify_recv_hash((uint8_t *)&current_buffer->temporary_metadata->IV);
		uint64_t counter;
		memcpy(&counter, current_buffer->temporary_metadata->network_freshness_counter, NETWORK_FRESHNESS_PACKET_SIZE);
		ipsec_verify_recv_counter(counter);
	}

	_pt_complete_crypto_io(NULL, true, bdev_io);
}

void decrypt_error_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
							union doca_data task_user_data,
							union doca_data ctx_user_data)
{
	struct doca_task *task = doca_aes_gcm_task_decrypt_as_task(decrypt_task);
	struct buffer *current_buffer = (struct buffer *)task_user_data.ptr;
	struct spdk_bdev_io *bdev_io = current_buffer->bdev_io;
	struct spdk_io_channel *ch = (struct spdk_io_channel *)ctx_user_data.ptr;
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	
	DOCA_LOG_ERR("Decrypt task at offset %ld failed with: %s\n", current_buffer->block_offset, doca_error_get_descr(doca_task_get_status(task)));
	DOCA_LOG_ERR("Buffer %p: %p\n", current_buffer, current_buffer->temporary_buffer);
	printf("moved: %p %p %p\n", bdev_io, pt_ch, io_ctx);
	printb(current_buffer);

	_pt_complete_crypto_io(NULL, false, bdev_io);
	spdk_app_stop(-1);
}

static void submit_decrypt(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg) {
	struct spdk_bdev_io *orig_io = cb_arg;
	int status = success ? SPDK_BDEV_IO_STATUS_SUCCESS : SPDK_BDEV_IO_STATUS_FAILED;
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)orig_io->driver_ctx;
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(io_ctx->ch);
	struct buffer *current_buffer = &pt_ch->doca_config.temporary_buffers[io_ctx->start_buffer_index];

	if (bdev_io != NULL)
		spdk_bdev_free_io(bdev_io);

	if (status == SPDK_BDEV_IO_STATUS_FAILED) {
		spdk_bdev_io_complete(orig_io, status);
	} else if (orig_io->u.bdev.iovs->iov_base < g_iobuf.small_pool_base || orig_io->u.bdev.iovs->iov_base > g_iobuf.small_pool_base + g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize) {
		// If the current buffer's source is invalid, make the read unitialized, and complete it
		// TODO could set here the MD to indicate error
		// TODO potential error can happen where first block is initialized but one of the inside IV blocks are not and we get a critical error!
		DOCA_LOG_ERR("Uninitialized read at %ld", current_buffer->block_offset);
		io_ctx->remaining_tasks = 1;
		_pt_complete_crypto_io(NULL, true, orig_io);
	} else {
		// Otherwise schedule all of the decryption tasks
		size_t tasks = io_ctx->remaining_tasks;
		for (size_t i = 0; i < tasks; i++) {
			current_buffer = pt_ch->doca_config.temporary_buffers + ((io_ctx->start_buffer_index + i) % (g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE));
			doca_error_t result;

			// Verify if any block is unitialized
			if (current_buffer->temporary_metadata->IV == 0) {
				DOCA_LOG_ERR("Uninitialized read at %ld", current_buffer->block_offset);
				
				// Set the temporary address to zero
				memset(current_buffer->temporary_address, 0, BLOCK_SIZE);

				_pt_complete_crypto_io(NULL, true, orig_io);
				continue;
			}
			// potential flag optimizations
			// if (i == io_ctx->remaining_tasks - 1)
			// 	result = doca_task_submit_ex(doca_aes_gcm_task_decrypt_as_task(current_buffer->decryption_task), DOCA_TASK_SUBMIT_FLAG_FLUSH | DOCA_TASK_SUBMIT_FLAG_OPTIMIZE_REPORTS);
			// else
			// 	result = doca_task_submit_ex(doca_aes_gcm_task_decrypt_as_task(current_buffer->decryption_task), DOCA_TASK_SUBMIT_FLAG_OPTIMIZE_REPORTS);
			result = doca_task_submit_ex(doca_aes_gcm_task_decrypt_as_task(current_buffer->decryption_task), DOCA_TASK_SUBMIT_FLAG_NONE);
			if (result != DOCA_SUCCESS) {
				DOCA_LOG_ERR("Failed to submit decrypt task: %s", doca_error_get_descr(result));
				spdk_app_stop(-1);
			}
		}
	}
}

static void
vbdev_integrity_queue_io(struct spdk_bdev_io *bdev_io)
{
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(io_ctx->ch);
	int rc;

	io_ctx->bdev_io_wait.bdev = bdev_io->bdev;
	io_ctx->bdev_io_wait.cb_fn = vbdev_integrity_resubmit_io;
	io_ctx->bdev_io_wait.cb_arg = bdev_io;

	/* Queue the IO using the channel of the base device. */
	rc = spdk_bdev_queue_io_wait(bdev_io->bdev, pt_ch->base_ch, &io_ctx->bdev_io_wait);
	if (rc != 0) {
		SPDK_ERRLOG("Queue io failed in vbdev_integrity_queue_io, rc=%d.\n", rc);
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
	struct vbdev_integrity *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_integrity,
					 pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	int rc;

	if (!success) {
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}

	rc = spdk_bdev_readv_blocks(pt_node->base_desc, pt_ch->base_ch, io_ctx->iovs,
									io_ctx->iovcnt, bdev_io->u.bdev.offset_blocks,
									bdev_io->u.bdev.num_blocks, submit_decrypt,
									bdev_io); //&io_opts
	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory, start to queue io for integrity.\n");
			io_ctx->ch = ch;
			vbdev_integrity_queue_io(bdev_io);
		} else {
			SPDK_ERRLOG("ERROR on bdev_io submission!\n");
			spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		}
	}

	// Prepare all of the buffers
	if (bdev_io->u.bdev.iovs->iov_base >= g_iobuf.small_pool_base && bdev_io->u.bdev.iovs->iov_base <= g_iobuf.small_pool_base + g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize) {
		struct buffer *current_buffer;
		struct iovec *current_iov;
		struct doca_buf *original_buffer;
		size_t overall_index = 0;
		for (int iov_index = 0; iov_index < bdev_io->u.bdev.iovcnt; iov_index++) {
			current_iov = bdev_io->u.bdev.iovs + iov_index;
			for (size_t block_index = 0; block_index < current_iov->iov_len / BLOCK_SIZE; block_index++) {
				current_buffer = pt_ch->doca_config.temporary_buffers + ((io_ctx->start_buffer_index + overall_index) % (g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE));	
				current_buffer->bdev_io = bdev_io;
				current_buffer->block_offset = bdev_io->u.bdev.offset_blocks + overall_index;
				doca_buf_set_data_len(current_buffer->temporary_buffer, BLOCK_SIZE + CACHE_AUTH_TAG); //current_buffer->iov.iov_len
				original_buffer = *(pt_ch->doca_config.original_buffers + (current_iov->iov_base + block_index * BLOCK_SIZE - g_iobuf.small_pool_base) / BLOCK_SIZE);
				doca_buf_set_data_len(original_buffer, 0);
				doca_aes_gcm_task_decrypt_set_dst(current_buffer->decryption_task, original_buffer);
				overall_index++;
			}
		}
	} else {
		SPDK_NOTICELOG("Out of mmap buffer: %p %p %p\n", bdev_io->u.bdev.iovs->iov_base, g_iobuf.small_pool_base, g_iobuf.small_pool_base + g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize);
	}
}

/* Called when someone above submits IO to this pt vbdev. We're simply passing it on here
 * via SPDK IO calls which in turn allocate another bdev IO and call our cpl callback provided
 * below along with the original bdev_io so that we can complete it once this IO completes.
 */
static void
vbdev_integrity_submit_request(struct spdk_io_channel *ch, struct spdk_bdev_io *bdev_io)
{
	struct vbdev_integrity *pt_node = SPDK_CONTAINEROF(bdev_io->bdev, struct vbdev_integrity, pt_bdev);
	struct pt_io_channel *pt_ch = spdk_io_channel_get_ctx(ch);
	struct integrity_bdev_io *io_ctx = (struct integrity_bdev_io *)bdev_io->driver_ctx;
	size_t required_buffers, until_end, overall_index = 0;
	struct buffer *current_buffer;
	struct iovec *current_iov;
	io_ctx->ch = ch;
	// io_ctx->cycles = spdk_get_ticks();
	int rc = 0;

	switch (bdev_io->type) {
	case SPDK_BDEV_IO_TYPE_READ:
		required_buffers = bdev_io->u.bdev.num_blocks;
		io_ctx->remaining_tasks = required_buffers;
		until_end = g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE - pt_ch->doca_config.buffer_index - 1;
		if (until_end < required_buffers)
			pt_ch->doca_config.buffer_index = 0;
		io_ctx->iovs[0].iov_base = pt_ch->doca_config.temporary_buffers[pt_ch->doca_config.buffer_index].temporary_address;
		io_ctx->iovs[0].iov_len = required_buffers * CACHE_SIZE;
		io_ctx->iovcnt = 1;
		io_ctx->start_buffer_index = pt_ch->doca_config.buffer_index;
		pt_ch->doca_config.buffer_index += required_buffers;
		spdk_bdev_io_get_buf(bdev_io, pt_read_get_buf_cb,
							 bdev_io->u.bdev.num_blocks * bdev_io->bdev->blocklen);
		break;
	case SPDK_BDEV_IO_TYPE_WRITE:
	case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
		required_buffers = bdev_io->u.bdev.num_blocks;
		io_ctx->remaining_tasks = required_buffers;
		until_end = g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE - pt_ch->doca_config.buffer_index - 1;
		// printf("(%p) Until end %ld with buffer index %ld and required buffers %ld and location %p with small giobuf %p-%p and large giobuf %p-%p\n", pt_ch, until_end, pt_ch->doca_config.buffer_index, required_buffers, bdev_io->u.bdev.iovs->iov_base, g_iobuf.small_pool_base, g_iobuf.small_pool_base + g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize, g_iobuf.large_pool_base, g_iobuf.large_pool_base + g_iobuf.opts.large_pool_count * g_iobuf.opts.large_bufsize);
		if (until_end < required_buffers)
			pt_ch->doca_config.buffer_index = 0;
		io_ctx->iovs[0].iov_base = pt_ch->doca_config.temporary_buffers[pt_ch->doca_config.buffer_index].temporary_address;
		io_ctx->iovs[0].iov_len = required_buffers * CACHE_SIZE;
		io_ctx->iovcnt = 1;
		io_ctx->start_buffer_index = pt_ch->doca_config.buffer_index;
		int iovs;
		if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) iovs = bdev_io->u.bdev.iovcnt;
		else iovs = 1;

		for (int iov_index = 0; iov_index < iovs; iov_index++) {
			size_t current_iov_len;
			if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) {
				current_iov = bdev_io->u.bdev.iovs + iov_index;
				current_iov_len = current_iov->iov_len / BLOCK_SIZE;
			} else {
				current_iov = NULL;
				current_iov_len = required_buffers;
			}
			for (size_t block_index = 0; block_index < current_iov_len; block_index++) {
				current_buffer = pt_ch->doca_config.temporary_buffers + io_ctx->start_buffer_index + overall_index; // ) % (g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE));	
				// assert(!current_buffer->used);
				current_buffer->bdev_io = bdev_io;
				current_buffer->block_offset = bdev_io->u.bdev.offset_blocks + overall_index;
				// current_buffer->used = true

				// memcpy(current_buffer->source_address, current_iov->iov_base + block_index * BLOCK_SIZE, BLOCK_SIZE);
				// if (current_iov->iov_len % BLOCK_SIZE)
				// 	printf("%ld\n", current_iov->iov_len);
				// printm(pt_ch->doca_config.buffers[(pt_ch->doca_config.buffer_index) % CACHE_NUM_ELEMENTS]->source_address, 2*CACHE_SIZE);
				// DOCA_LOG_INFO("%d", current_buffer->iov.iov_len);
				// current_buffer->destination_metadata->valid = 0xfe;
				// printf("Current IVs %ld/%ld\n", pt_ch->IV, pt_ch->IV_limit);
				if (pt_ch->IV == pt_ch->IV_limit) {
					get_IV_allocation(&pt_ch->IV, &pt_ch->IV_limit, &pt_node->IV_lock, &pt_node->device_IV, &pt_node->device_IV_limit);
				}
				// Note we store only the upper bits of the IV instead of the whole IV with the lower log2(4096 / (128 / 8)) bits used for encrypting each block

				// TODO: Could change to actual IVs but this allows us to effectively check the performance impact of the MD cache
				// current_buffer->temporary_metadata->IV = 0xf0f0f0f0f0f0f0; //current_buffer->block_offset; //pt_ch->IV;
				current_buffer->temporary_metadata->IV = pt_ch->IV << 8;
				// printf("%ld %ld\n", current_buffer->temporary_metadata->IV, pt_ch->IV);
				pt_ch->IV += 1;
				// current_buffer->source_metadata->IV = 0xf0f0f0f0f0f0f0; //current_buffer->destination_metadata->IV << 8;
				// printb(current_buffer);
				// printf("\n\nPrinting the buffer after modification\n");

				// printb(current_buffer);

				// printb(current_buffer);
				// printf("%d, Channel: %ld Buffer: %ld\n", i, pt_ch->IV, current_buffer->source_metadata->IV);
				struct doca_buf *original_buffer;
				if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) {
					original_buffer = *(pt_ch->doca_config.original_buffers + (current_iov->iov_base + block_index * BLOCK_SIZE - g_iobuf.small_pool_base) / BLOCK_SIZE);
				} else {
					original_buffer = *(pt_ch->doca_config.zero_buffers + pt_ch->doca_config.zero_counter);
					pt_ch->doca_config.zero_counter += 1;
					pt_ch->doca_config.zero_counter %= g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE; // g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE = CACHE_NUM_ELEMENTS
				}
				void *selected_location;
				doca_buf_get_data(original_buffer, &selected_location);
				if (bdev_io->type == SPDK_BDEV_IO_TYPE_WRITE) {
					if (selected_location != current_iov->iov_base + block_index * BLOCK_SIZE)
						printf("ERROR buffer %p and iov base %p\n", selected_location, current_iov->iov_base + block_index * BLOCK_SIZE);
					current_buffer->source_address = current_iov->iov_base + block_index * BLOCK_SIZE;
				} else {
					if (selected_location != pt_ch->doca_config.zero_source_buffer)
						printf("ERROR buffer %p and zero buffer location %p\n", selected_location, pt_ch->doca_config.zero_source_buffer);
					current_buffer->source_address = pt_ch->doca_config.zero_source_buffer;
				}
				doca_buf_set_data_len(original_buffer, BLOCK_SIZE);
				doca_buf_set_data_len(current_buffer->temporary_buffer, 0);
				doca_aes_gcm_task_encrypt_set_src(current_buffer->encryption_task, original_buffer);

				int res = doca_task_submit_ex(doca_aes_gcm_task_encrypt_as_task(current_buffer->encryption_task), DOCA_TASK_SUBMIT_FLAG_NONE);
				if (res != DOCA_SUCCESS) {
					DOCA_LOG_ERR("Failed to submit encrypt task: %s", doca_error_get_descr(res));
					rc = 1;
				}
				overall_index++;
			}
		}
		pt_ch->doca_config.buffer_index += required_buffers;
		break;
	// case SPDK_BDEV_IO_TYPE_WRITE_ZEROES:
	// 	printf("Zeroing %p %ld %ld %ld %ld\n", bdev_io->u.bdev.offset_blocks, bdev_io->u.bdev.num_blocks);
	// 	rc = spdk_bdev_write_zeroes_blocks(pt_node->base_desc, pt_ch->base_ch,
	// 					   bdev_io->u.bdev.offset_blocks,
	// 					   bdev_io->u.bdev.num_blocks,
	// 					   _pt_complete_io, bdev_io);
	// 	break;
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
		SPDK_ERRLOG("integrity: unknown I/O type %d\n", bdev_io->type);
		spdk_bdev_io_complete(bdev_io, SPDK_BDEV_IO_STATUS_FAILED);
		return;
	}
	if (rc != 0) {
		if (rc == -ENOMEM) {
			SPDK_ERRLOG("No memory, start to queue io for integrity.\n");
			io_ctx->ch = ch;
			vbdev_integrity_queue_io(bdev_io);
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
vbdev_integrity_io_type_supported(void *ctx, enum spdk_bdev_io_type io_type)
{
	struct vbdev_integrity *pt_node = (struct vbdev_integrity *)ctx;
	// if (io_type == SPDK_BDEV_IO_TYPE_WRITE_ZEROES) return false;
	return spdk_bdev_io_type_supported(pt_node->base_bdev, io_type);
}

/* We supplied this as an entry point for upper layers who want to communicate to this
 * bdev.  This is how they get a channel. We are passed the same context we provided when
 * we created our PT vbdev in examine() which, for this bdev, is the address of one of
 * our context nodes. From here we'll ask the SPDK channel code to fill out our channel
 * struct and we'll keep it in our PT node.
 */
static struct spdk_io_channel *
vbdev_integrity_get_io_channel(void *ctx)
{
	struct vbdev_integrity *pt_node = (struct vbdev_integrity *)ctx;
	struct spdk_io_channel *pt_ch = NULL;
	doca_error_t result;

	/* The IO channel code will allocate a channel for us which consists of
	 * the SPDK channel structure plus the size of our pt_io_channel struct
	 * that we passed in when we registered our IO device. It will then call
	 * our channel create callback to populate any elements that we need to
	 * update.
	 */
	pt_ch = spdk_get_io_channel(pt_node);
	struct pt_io_channel *pt_io_ch = spdk_io_channel_get_ctx(pt_ch);
	DOCA_LOG_INFO("New channel allocated %p.", pt_io_ch);
	pt_io_ch->IV = 0;
	pt_io_ch->IV_limit = 0;
	
	// event = spdk_event_allocate(3, &test, NULL, NULL);
	// DOCA_LOG_INFO("DONE");
	// spdk_event_call(event);

	/* Initialize the DOCA elements */
	result = doca_initialize_channel(&pt_io_ch->doca_config, pt_ch, encrypt_completed_callback, encrypt_error_callback, decrypt_completed_callback, decrypt_error_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to initialize DOCA");
		spdk_app_stop(-1);
	}

	/* Create mmaps */
	size_t cache_num_elements = g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE;
	// We only need one zeroed buffer for write zeroes as the it's always zeroes and we only read from it
	// Note that the output buffer and its DOCA buffer are still going to be selected from the temporary output buffers (which are indexed by buffer_index)
	void *buf = spdk_malloc(CACHE_SIZE * cache_num_elements, 0, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE); 
	// SPDK_NOTICELOG("Allocated %p-%p\n", buf, buf + 2 * CACHE_SIZE * CACHE_NUM_ELEMENTS);
	if (buf == NULL) {
		DOCA_LOG_ERR("Failed to allocate SPDK buffers");
		spdk_app_stop(-1);
	}
	pt_io_ch->doca_config.overall_buffer = buf;
	pt_io_ch->doca_config.buffer_index = 0;
	
	// We use the zero mmap for write zeroes (so everything is zeroed out)
	// Same strategy can be used for buffers outside of the direct global mapping
	pt_io_ch->doca_config.zero_source_buffer = spdk_zmalloc(CACHE_SIZE, 0, NULL, SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA | SPDK_MALLOC_SHARE);
	result = doca_start_mmap(&pt_io_ch->doca_config, &pt_io_ch->doca_config.zero_mmap, pt_io_ch->doca_config.zero_source_buffer, CACHE_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap");
		spdk_app_stop(-1);
	}
	pt_io_ch->doca_config.zero_counter = 0;

	// We use the global/local mmaps for other write/read traffic that maps directly to the global receive/send buffers
	result = doca_start_mmap(&pt_io_ch->doca_config, &pt_io_ch->doca_config.local_mmap, buf, CACHE_SIZE * cache_num_elements);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap");
		spdk_app_stop(-1);
	}

	result = doca_start_mmap(&pt_io_ch->doca_config, &pt_io_ch->doca_config.global_mmap, g_iobuf.small_pool_base, g_iobuf.opts.small_bufsize * g_iobuf.opts.small_pool_count);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap");
		spdk_app_stop(-1);
	}

	/* Allocate the buffers */
	pt_io_ch->doca_config.zero_buffers = (struct doca_buf **)malloc(cache_num_elements * sizeof(struct doca_buf*));
	pt_io_ch->doca_config.temporary_buffers = (struct buffer *)malloc(cache_num_elements * sizeof(struct buffer));
	pt_io_ch->doca_config.original_buffers = (struct doca_buf **)malloc(cache_num_elements * sizeof(struct doca_buf*));
	for (size_t i = 0; i < cache_num_elements; i++) {
		result = doca_buf_inventory_buf_get_by_addr(pt_io_ch->doca_config.buf_inv, pt_io_ch->doca_config.zero_mmap, pt_io_ch->doca_config.zero_source_buffer, CACHE_SIZE, pt_io_ch->doca_config.zero_buffers + i);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s",
					doca_error_get_descr(result));
			doca_close_channel(&pt_io_ch->doca_config);
		}
		result = doca_buf_inventory_buf_get_by_addr(pt_io_ch->doca_config.buf_inv, pt_io_ch->doca_config.global_mmap, g_iobuf.small_pool_base + i * BLOCK_SIZE, CACHE_SIZE, pt_io_ch->doca_config.original_buffers + i);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s",
					doca_error_get_descr(result));
			doca_close_channel(&pt_io_ch->doca_config);
		}
		result = doca_register_buffer(&pt_io_ch->doca_config, buf + i * CACHE_SIZE, pt_io_ch->doca_config.temporary_buffers + i);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to reegister a buffer with DOCA");
			doca_close_channel(&pt_io_ch->doca_config);
		}
	}

	pt_io_ch->poller_submit = spdk_poller_register(doca_flush_tasks, pt_io_ch->doca_config.ctx, 1);
	pt_io_ch->poller_complete = spdk_poller_register(doca_check_pe, pt_io_ch->doca_config.pe, 1);
	get_IV_allocation(&pt_io_ch->IV, &pt_io_ch->IV_limit, &pt_node->IV_lock, &pt_node->device_IV, &pt_node->device_IV_limit);
	DOCA_LOG_INFO("DOCA initialized");

	return pt_ch;
}

/* This is the output for bdev_get_bdevs() for this vbdev */
static int
vbdev_integrity_dump_info_json(void *ctx, struct spdk_json_write_ctx *w)
{
	struct vbdev_integrity *pt_node = (struct vbdev_integrity *)ctx;

	spdk_json_write_name(w, "integrity");
	spdk_json_write_object_begin(w);
	spdk_json_write_named_string(w, "name", spdk_bdev_get_name(&pt_node->pt_bdev));
	spdk_json_write_named_string(w, "base_bdev_name", spdk_bdev_get_name(pt_node->base_bdev));
	spdk_json_write_object_end(w);

	return 0;
}

/* This is used to generate JSON that can configure this module to its current state. */
static int
vbdev_integrity_config_json(struct spdk_json_write_ctx *w)
{
	struct vbdev_integrity *pt_node;

	TAILQ_FOREACH(pt_node, &g_pt_nodes, link) {
		const struct spdk_uuid *uuid = spdk_bdev_get_uuid(&pt_node->pt_bdev);

		spdk_json_write_object_begin(w);
		spdk_json_write_named_string(w, "method", "bdev_integrity_create");
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
	struct vbdev_integrity *pt_node = io_device;

	pt_ch->base_ch = spdk_bdev_get_io_channel(pt_node->base_desc);

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
	DOCA_LOG_INFO("Closing channel");
	spdk_poller_unregister(&pt_ch->poller_complete);
	spdk_poller_unregister(&pt_ch->poller_submit);
	doca_error_t result = doca_close_channel(&pt_ch->doca_config);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to close DOCA");
	}
	spdk_put_io_channel(pt_ch->base_ch);
}

/* Create the integrity association from the bdev and vbdev name and insert
 * on the global list. */
static int
vbdev_integrity_insert_name(const char *bdev_name, const char *vbdev_name,
			   const struct spdk_uuid *uuid)
{
	struct bdev_names *name;

	TAILQ_FOREACH(name, &g_bdev_names, link) {
		if (strcmp(vbdev_name, name->vbdev_name) == 0) {
			SPDK_ERRLOG("integrity bdev %s already exists\n", vbdev_name);
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
vbdev_integrity_init(void)
{
	/* DOCA */
	doca_log_level_set_global_sdk_limit(DOCA_LOG_LEVEL_TRACE);
	if (doca_log_backend_create_standard() != DOCA_SUCCESS) spdk_app_stop(-1);

	return 0;
}

/* Called when the entire module is being torn down. */
static void
vbdev_integrity_finish(void)
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
vbdev_integrity_get_ctx_size(void)
{
	return sizeof(struct integrity_bdev_io);
}

/* Where vbdev_integrity_config_json() is used to generate per module JSON config data, this
 * function is called to output any per bdev specific methods. For the PT module, there are
 * none.
 */
static void
vbdev_integrity_write_config_json(struct spdk_bdev *bdev, struct spdk_json_write_ctx *w)
{
	/* No config per bdev needed */
}

static int
vbdev_integrity_get_memory_domains(void *ctx, struct spdk_memory_domain **domains, int array_size)
{
	struct vbdev_integrity *pt_node = (struct vbdev_integrity *)ctx;

	/* Integrity bdev doesn't work with data buffers, so it supports any memory domain used by base_bdev */
	return spdk_bdev_get_memory_domains(pt_node->base_bdev, domains, array_size);
}

/* When we register our bdev this is how we specify our entry points. */
static const struct spdk_bdev_fn_table vbdev_integrity_fn_table = {
	.destruct		= vbdev_integrity_destruct,
	.submit_request		= vbdev_integrity_submit_request,
	.io_type_supported	= vbdev_integrity_io_type_supported,
	.get_io_channel		= vbdev_integrity_get_io_channel,
	.dump_info_json		= vbdev_integrity_dump_info_json,
	.write_config_json	= vbdev_integrity_write_config_json,
	.get_memory_domains	= vbdev_integrity_get_memory_domains,
};

static void
vbdev_integrity_base_bdev_hotremove_cb(struct spdk_bdev *bdev_find)
{
	struct vbdev_integrity *pt_node, *tmp;

	TAILQ_FOREACH_SAFE(pt_node, &g_pt_nodes, link, tmp) {
		if (bdev_find == pt_node->base_bdev) {
			spdk_bdev_unregister(&pt_node->pt_bdev, NULL, NULL);
		}
	}
}

/* Called when the underlying base bdev triggers asynchronous event such as bdev removal. */
static void
vbdev_integrity_base_bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev,
				  void *event_ctx)
{
	switch (type) {
	case SPDK_BDEV_EVENT_REMOVE:
		vbdev_integrity_base_bdev_hotremove_cb(bdev);
		break;
	default:
		SPDK_NOTICELOG("Unsupported bdev event: type %d\n", type);
		break;
	}
}

/* Context to track our progress across multiple write initialization submissions */
struct zero_ctx {
    struct spdk_bdev_desc    *desc;
    struct spdk_io_channel   *ch;
    void                     *zero_buf;
    uint64_t                  lba;
    uint64_t                  total_blocks;
    uint64_t                  chunk_blocks;
    uint64_t                  current_length;
	uint64_t				  block_len;
};

void pass(void *arg) {
	return;
}

// static void
// vbdev_zero_write_cb(struct spdk_bdev_io *bdev_io, bool success, void *cb_arg)
// {
//     struct zero_ctx *ctx = cb_arg;
//     spdk_bdev_free_io(bdev_io);

//     if (!success) {
//         SPDK_ERRLOG("Zeroing WRITE failed at LBA %" PRIu64 "\n", ctx->lba);
//         goto cleanup;
//     }

//     /* Advance to next chunk */
//     ctx->lba += ctx->current_length;
//     if (ctx->lba < ctx->total_blocks) {
// 		if (ctx->lba % 1000 == 0) {
// 			SPDK_NOTICELOG("Initialized %lu of %lu blocks\n", ctx->lba, ctx->total_blocks);
// 		}
//         ctx->current_length = spdk_min(ctx->chunk_blocks, ctx->total_blocks - ctx->lba);

// 		/* Setup the bdev_io manually */
// 		struct spdk_bdev_io *bdev_io = calloc(1, sizeof(struct spdk_bdev_io));
// 		bdev_io->type = SPDK_BDEV_IO_TYPE_WRITE;
// 		bdev_io->u.bdev.iovs = &bdev_io->iov;
// 		bdev_io->u.bdev.iovcnt = 1;
// 		bdev_io->u.bdev.md_buf = NULL;
// 		bdev_io->u.bdev.iovs[0].iov_base = ctx->zero_buf;
// 		bdev_io->u.bdev.iovs[0].iov_len = ctx->current_length * ctx->block_len;
// 		bdev_io->u.bdev.offset_blocks = ctx->lba;
// 		bdev_io->u.bdev.num_blocks = ctx->current_length;
// 		bdev_io->internal.cb = vbdev_zero_write_cb;
// 		bdev_io->internal.caller_ctx = ctx;

// 		/* Submit via our vbdev fn_table path: */
// 		vbdev_integrity_submit_request(ctx->ch, bdev_io);
//         return;
//     }

//     SPDK_NOTICELOG("Zeroing complete\n");

// cleanup:
//     spdk_put_io_channel(ctx->ch);
//     spdk_dma_free(ctx->zero_buf);
//     free(ctx);
// }

/* Create and register the integrity vbdev if we find it in our list of bdev names.
 * This can be called either by the examine path or RPC method.
 */
static int
vbdev_integrity_register(const char *bdev_name)
{
	struct bdev_names *name;
	struct vbdev_integrity *pt_node;
	struct spdk_bdev *bdev;
	struct spdk_uuid ns_uuid;
	int rc = 0;
	spdk_uuid_parse(&ns_uuid, BDEV_PASSTHRU_NAMESPACE_UUID);

	/* Check our list of names from config versus this bdev and if
	 * there's a match, create the pt_node & bdev accordingly.
	 */
	TAILQ_FOREACH(name, &g_bdev_names, link) {
		if (strcmp(name->bdev_name, bdev_name) != 0) {
			continue;
		}

		SPDK_NOTICELOG("Match on %s\n", bdev_name);
		pt_node = calloc(1, sizeof(struct vbdev_integrity));
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
		pt_node->pt_bdev.product_name = "integrity";

		/* The base bdev that we're attaching to. */
		rc = spdk_bdev_open_ext(bdev_name, true, vbdev_integrity_base_bdev_event_cb,
					NULL, &pt_node->base_desc);
		if (rc) {
			if (rc != -ENODEV) {
				SPDK_ERRLOG("could not open bdev %s\n", bdev_name);
			}
			free(pt_node->pt_bdev.name);
			free(pt_node);
			break;
		}
		SPDK_NOTICELOG("bas` bdev opened\n");

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
				SPDK_ERRLOG("Unable to generate new UUID for integrity bdev\n");
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
		pt_node->pt_bdev.blocklen = BLOCK_SIZE;
		pt_node->pt_bdev.blockcnt = bdev->blockcnt;
		spdk_spin_init(&pt_node->IV_lock);
		pt_node->device_IV = 0;
		pt_node->device_IV_limit = 0;

		pt_node->pt_bdev.md_interleave = false;
		pt_node->pt_bdev.md_len = 0;
		pt_node->pt_bdev.dif_type = bdev->dif_type;
		pt_node->pt_bdev.dif_is_head_of_md = bdev->dif_is_head_of_md;
		pt_node->pt_bdev.dif_check_flags = bdev->dif_check_flags;
		pt_node->pt_bdev.dif_pi_format = bdev->dif_pi_format;

		/* This is the context that is passed to us when the bdev
		 * layer calls in so we'll save our pt_bdev node here.
		 */
		pt_node->pt_bdev.ctxt = pt_node;
		pt_node->pt_bdev.fn_table = &vbdev_integrity_fn_table;
		pt_node->pt_bdev.module = &integrity_if;
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

		// struct zero_ctx *ctx = calloc(1, sizeof(*ctx));
		// if (!ctx) {
		// 	SPDK_ERRLOG("Failed to allocate zero initialization context\n");
		// 	return -ENOMEM;
		// }
		// SPDK_NOTICELOG("Allocated zero initialization context\n");
		// ctx->chunk_blocks = spdk_min(bdev->blockcnt, (uint64_t)((1024 * 1024) / bdev->blocklen));
		// ctx->total_blocks = bdev->blockcnt;
		// ctx->zero_buf = spdk_dma_zmalloc(ctx->chunk_blocks * bdev->blocklen, bdev->required_alignment, NULL);
		// if (!ctx->zero_buf) {
		// 	SPDK_ERRLOG("Failed to allocate zero initializaiton buffer\n");
		// 	return -ENOMEM;
		// }
		// SPDK_NOTICELOG("Allocated zero initialization buffer\n");
		// ctx->lba = 0;
		// SPDK_NOTICELOG("Opening %s for zero initialization\n", pt_node->pt_bdev.name);
		// // rc = spdk_bdev_open_ext(pt_node->pt_bdev.name, true, pass, NULL, &ctx->desc);
		// // if (rc) {
		// // 	SPDK_ERRLOG("Cannot open backing bdev for zero initialization, errno %d)\n", rc);
		// // 	return rc;
		// // }
		// ctx->ch = vbdev_integrity_get_io_channel(pt_node);
		// ctx->block_len = pt_node->pt_bdev.blocklen;
		// SPDK_NOTICELOG("Got IO channel for zero initialization\n");
		// ctx->current_length = spdk_min(ctx->chunk_blocks, ctx->total_blocks - ctx->lba);

		// /* Setup the bdev_io manually */
		// struct spdk_bdev_io *bdev_io = calloc(1, sizeof(struct spdk_bdev_io));
		// bdev_io->type = SPDK_BDEV_IO_TYPE_WRITE;
		// bdev_io->u.bdev.iovs = &bdev_io->iov;
		// bdev_io->u.bdev.iovcnt = 1;
		// bdev_io->u.bdev.md_buf = NULL;
		// bdev_io->u.bdev.iovs[0].iov_base = ctx->zero_buf;
		// bdev_io->u.bdev.iovs[0].iov_len = ctx->current_length * ctx->block_len;
		// bdev_io->u.bdev.offset_blocks = ctx->lba;
		// bdev_io->u.bdev.num_blocks = ctx->current_length;
		// bdev_io->internal.cb = vbdev_zero_write_cb;
		// bdev_io->internal.caller_ctx = ctx;

		// /* Submit via our vbdev fn_table path: */
		// vbdev_integrity_submit_request(ctx->ch, bdev_io);
		// SPDK_NOTICELOG("Zero‐write initialization submitted (lba=%" PRIu64 ", len=%" PRIu64 ")\n", ctx->lba, ctx->current_length);
		//
	}
	return rc;
}

/* Create the integrity disk from the given bdev and vbdev name. */
int
bdev_integrity_create_disk(const char *bdev_name, const char *vbdev_name,
			  const struct spdk_uuid *uuid)
{
	int rc;

	/* Insert the bdev name into our global name list even if it doesn't exist yet,
	 * it may show up soon...
	 */
	rc = vbdev_integrity_insert_name(bdev_name, vbdev_name, uuid);
	if (rc) {
		return rc;
	}

	rc = vbdev_integrity_register(bdev_name);
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
bdev_integrity_delete_disk(const char *bdev_name, spdk_bdev_unregister_cb cb_fn, void *cb_arg)
{
	struct bdev_names *name;
	int rc;

	/* Some cleanup happens in the destruct callback. */
	rc = spdk_bdev_unregister_by_name(bdev_name, &integrity_if, cb_fn, cb_arg);
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
vbdev_integrity_examine(struct spdk_bdev *bdev)
{
	vbdev_integrity_register(bdev->name);

	spdk_bdev_module_examine_done(&integrity_if);
}

SPDK_LOG_REGISTER_COMPONENT(vbdev_integrity)