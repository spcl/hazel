/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *   All rights reserved.
 */

#include "vbdev_integrity.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/log.h"
#include "spdk/bdev.h"

/* Structure to hold the parameters for this RPC method. */
struct rpc_bdev_integrity_create {
	char *base_bdev_name;
	char *name;
	struct spdk_uuid uuid;
};

/* Free the allocated memory resource after the RPC handling. */
static void
free_rpc_bdev_integrity_create(struct rpc_bdev_integrity_create *r)
{
	free(r->base_bdev_name);
	free(r->name);
}

/* Structure to decode the input parameters for this RPC method. */
static const struct spdk_json_object_decoder rpc_bdev_integrity_create_decoders[] = {
	{"base_bdev_name", offsetof(struct rpc_bdev_integrity_create, base_bdev_name), spdk_json_decode_string},
	{"name", offsetof(struct rpc_bdev_integrity_create, name), spdk_json_decode_string},
	{"uuid", offsetof(struct rpc_bdev_integrity_create, uuid), spdk_json_decode_uuid, true},
};

/* Decode the parameters for this RPC method and properly construct the integrity
 * device. Error status returned in the failed cases.
 */
static void
rpc_bdev_integrity_create(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_bdev_integrity_create req = {NULL};
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_integrity_create_decoders,
				    SPDK_COUNTOF(rpc_bdev_integrity_create_decoders),
				    &req)) {
		SPDK_DEBUGLOG(vbdev_integrity, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = bdev_integrity_create_disk(req.base_bdev_name, req.name, &req.uuid);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_integrity_create(&req);
}
SPDK_RPC_REGISTER("bdev_integrity_create", rpc_bdev_integrity_create, SPDK_RPC_RUNTIME)

struct rpc_bdev_integrity_delete {
	char *name;
};

static void
free_rpc_bdev_integrity_delete(struct rpc_bdev_integrity_delete *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_integrity_delete_decoders[] = {
	{"name", offsetof(struct rpc_bdev_integrity_delete, name), spdk_json_decode_string},
};

static void
rpc_bdev_integrity_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_integrity_delete(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_bdev_integrity_delete req = {NULL};

	if (spdk_json_decode_object(params, rpc_bdev_integrity_delete_decoders,
				    SPDK_COUNTOF(rpc_bdev_integrity_delete_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev_integrity_delete_disk(req.name, rpc_bdev_integrity_delete_cb, request);

cleanup:
	free_rpc_bdev_integrity_delete(&req);
}
SPDK_RPC_REGISTER("bdev_integrity_delete", rpc_bdev_integrity_delete, SPDK_RPC_RUNTIME)


/*
 *
 * ZEROING OUT
 * 
 * 
 * Call with:
 * echo -n '{"jsonrpc":"2.0","method":"bdev_zero","params":{"bdev_name":"Main"},"id":1}' | sudo socat - UNIX-CONNECT:/var/tmp/spdk.sock
 *
 */

#define CHUNK_BLOCKS  8192
#define QUEUE_DEPTH   8

struct rpc_bdev_zero {
    char *bdev_name;
};

static const struct spdk_json_object_decoder rpc_bdev_zero_decoders[] = {
    { "bdev_name", offsetof(struct rpc_bdev_zero, bdev_name), spdk_json_decode_string },
};

struct zero_context {
    struct spdk_jsonrpc_request *request;

    struct spdk_bdev *bdev;
    struct spdk_bdev_desc *desc;
    struct spdk_io_channel *io_ch;

    uint32_t block_size;
    uint64_t total_blocks;
    uint32_t write_unit_size;

    uint64_t chunk_blocks;
    uint64_t next_lba;
    uint64_t remaining_blocks;
    uint64_t blocks_written;

    void *zero_buf;

    int inflight_ios;
    bool failed;
    bool hot_removed;
};

static inline uint64_t round_down_u64(uint64_t v, uint64_t a) { return a ? (v / a) * a : v; }

static void zero_context_free(struct zero_context *ctx) {
    if (ctx->io_ch) spdk_put_io_channel(ctx->io_ch);
    if (ctx->desc)  spdk_bdev_close(ctx->desc);
    if (ctx->zero_buf) spdk_dma_free(ctx->zero_buf);
    free(ctx);
}

static void send_error_and_free(struct zero_context *ctx, const char *msg) {
    spdk_jsonrpc_send_error_response(ctx->request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, msg);
    zero_context_free(ctx);
}

static void send_success_and_free(struct zero_context *ctx, const char *name) {
    struct spdk_json_write_ctx *w = spdk_jsonrpc_begin_result(ctx->request);
    spdk_json_write_object_begin(w);
    spdk_json_write_named_string(w, "bdev_name", name);
    spdk_json_write_named_bool(w, "zeroed", true);
    spdk_json_write_named_uint64(w, "total_blocks", ctx->total_blocks);
    spdk_json_write_named_uint64(w, "blocks_written", ctx->blocks_written);
    spdk_json_write_named_uint64(w, "chunk_blocks", ctx->chunk_blocks);
    spdk_json_write_object_end(w);
    spdk_jsonrpc_end_result(ctx->request, w);
    zero_context_free(ctx);
}

static void bdev_event_cb(enum spdk_bdev_event_type type, struct spdk_bdev *bdev, void *arg) {
    struct zero_context *ctx = arg;
    if (type == SPDK_BDEV_EVENT_REMOVE) {
        ctx->hot_removed = true;
    }
}

static void submit_next_io(struct zero_context *ctx);

static void write_complete_cb(struct spdk_bdev_io *bdev_io, bool success, void *arg) {
    struct zero_context *ctx = arg;
    spdk_bdev_free_io(bdev_io);

    ctx->inflight_ios--;
    if (!success || ctx->hot_removed) {
        ctx->failed = true;
    }

    if (!ctx->failed) {
        // Progress logging is based on accounting done at submission time.
        uint64_t percent = (ctx->blocks_written * 100) / (ctx->total_blocks ? ctx->total_blocks : 1);
        SPDK_NOTICELOG("Zeroing: %" PRIu64 "%% (%" PRIu64 "/%" PRIu64 " blocks)\n",
                       percent, ctx->blocks_written, ctx->total_blocks);
    }

    if (!ctx->failed && (ctx->remaining_blocks > 0 || ctx->inflight_ios > 0)) {
        submit_next_io(ctx);
        return;
    }

    if (ctx->inflight_ios == 0) {
        if (ctx->failed) send_error_and_free(ctx, "Zeroing failed");
        else             send_success_and_free(ctx, spdk_bdev_get_name(ctx->bdev));
    }
}

static void submit_next_io(struct zero_context *ctx) {
    while (!ctx->failed &&
           ctx->remaining_blocks > 0 &&
           ctx->inflight_ios < QUEUE_DEPTH) {

        uint64_t blocks = ctx->chunk_blocks;
        if (blocks > ctx->remaining_blocks) blocks = ctx->remaining_blocks;

        if (ctx->write_unit_size > 1) {
            uint64_t rounded = round_down_u64(blocks, ctx->write_unit_size);
            if (rounded == 0) {
                if (ctx->remaining_blocks < ctx->write_unit_size) {
                    ctx->failed = true;
                    break;
                }
                rounded = ctx->write_unit_size;
            }
            blocks = rounded;
        }

        int rc = spdk_bdev_write_blocks(
            ctx->desc,
            ctx->io_ch,
            ctx->zero_buf,
            ctx->next_lba,
            blocks,
            write_complete_cb,
            ctx
        );
        if (rc != 0) {
            ctx->failed = true;
            break;
        }

        ctx->next_lba        += blocks;
        ctx->remaining_blocks -= blocks;
        ctx->blocks_written  += blocks;
        ctx->inflight_ios++;
    }
}

static void rpc_bdev_zero(struct spdk_jsonrpc_request *request,
                          const struct spdk_json_val *params)
{
    struct rpc_bdev_zero req = {0};
    if (spdk_json_decode_object(params, rpc_bdev_zero_decoders,
                                SPDK_COUNTOF(rpc_bdev_zero_decoders), &req) != 0 ||
        req.bdev_name == NULL) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "Missing or invalid parameters. Expected bdev_name (string).");
        free(req.bdev_name);
        return;
    }

    struct zero_context *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Out of memory");
        free(req.bdev_name);
        return;
    }
    ctx->request = request;

    int rc = spdk_bdev_open_ext(req.bdev_name, true /* write */,
                            bdev_event_cb /* event_cb */,
                            ctx /* cb_arg */,
                            &ctx->desc);
    if (rc != 0 || !ctx->desc) {
        spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR, "Failed to open bdev");
        free(req.bdev_name);
        free(ctx);
        return;
    }

    ctx->bdev = spdk_bdev_desc_get_bdev(ctx->desc);
    ctx->block_size      = spdk_bdev_get_block_size(ctx->bdev);
    ctx->total_blocks    = spdk_bdev_get_num_blocks(ctx->bdev);
    ctx->write_unit_size = spdk_bdev_get_write_unit_size(ctx->bdev);

    if (ctx->total_blocks == 0 || ctx->block_size == 0) {
        send_error_and_free(ctx, "Invalid bdev geometry");
        free(req.bdev_name);
        return;
    }

    uint64_t chunk = CHUNK_BLOCKS ? CHUNK_BLOCKS : 8192;
    if (ctx->write_unit_size > 1) {
        chunk = round_down_u64(chunk, ctx->write_unit_size);
        if (chunk == 0) chunk = ctx->write_unit_size;
    }
    ctx->chunk_blocks = chunk;

    size_t buf_bytes = (size_t)ctx->chunk_blocks * ctx->block_size;
    ctx->zero_buf = spdk_dma_zmalloc(buf_bytes, ctx->block_size, NULL);
    if (!ctx->zero_buf) {
        send_error_and_free(ctx, "Failed to allocate DMA buffer");
        free(req.bdev_name);
        return;
    }
    memset(ctx->zero_buf, 0, buf_bytes);

    ctx->io_ch = spdk_bdev_get_io_channel(ctx->desc);
    if (!ctx->io_ch) {
        send_error_and_free(ctx, "Failed to get I/O channel");
        free(req.bdev_name);
        return;
    }

    ctx->next_lba         = 0;
    ctx->remaining_blocks = ctx->total_blocks;
    ctx->blocks_written   = 0;
    ctx->inflight_ios     = 0;
    ctx->failed           = false;

    SPDK_NOTICELOG("Zeroing '%s': %" PRIu64 " blocks @ %u B, chunk=%" PRIu64 ", QD=%d, WU=%u\n",
                   req.bdev_name, ctx->total_blocks, ctx->block_size,
                   ctx->chunk_blocks, QUEUE_DEPTH, ctx->write_unit_size);

    submit_next_io(ctx);   // kick it off
    free(req.bdev_name);   // no longer needed
}

SPDK_RPC_REGISTER("bdev_zero", rpc_bdev_zero, SPDK_RPC_RUNTIME);