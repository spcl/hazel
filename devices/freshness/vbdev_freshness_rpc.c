/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 *   All rights reserved.
 */

#include "vbdev_freshness.h"
#include "spdk/rpc.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/log.h"
#include <stdatomic.h>
#include <stddef.h>
#include "constants.h"
#include "hashing.h"

/* Structure to hold the parameters for this RPC method. */
struct rpc_bdev_freshness_create {
	char *base_bdev_name;
	char *name;
	struct spdk_uuid uuid;
};

/* Free the allocated memory resource after the RPC handling. */
static void
free_rpc_bdev_freshness_create(struct rpc_bdev_freshness_create *r)
{
	free(r->base_bdev_name);
	free(r->name);
}

/* Structure to decode the input parameters for this RPC method. */
static const struct spdk_json_object_decoder rpc_bdev_freshness_create_decoders[] = {
	{"base_bdev_name", offsetof(struct rpc_bdev_freshness_create, base_bdev_name), spdk_json_decode_string},
	{"name", offsetof(struct rpc_bdev_freshness_create, name), spdk_json_decode_string},
	{"uuid", offsetof(struct rpc_bdev_freshness_create, uuid), spdk_json_decode_uuid, true},
};

/* Decode the parameters for this RPC method and properly construct the freshness
 * device. Error status returned in the failed cases.
 */
static void
rpc_bdev_freshness_create(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_bdev_freshness_create req = {NULL};
	struct spdk_json_write_ctx *w;
	int rc;

	if (spdk_json_decode_object(params, rpc_bdev_freshness_create_decoders,
				    SPDK_COUNTOF(rpc_bdev_freshness_create_decoders),
				    &req)) {
		SPDK_DEBUGLOG(vbdev_freshness, "spdk_json_decode_object failed\n");
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	rc = bdev_freshness_create_disk(req.base_bdev_name, req.name, &req.uuid);
	if (rc != 0) {
		spdk_jsonrpc_send_error_response(request, rc, spdk_strerror(-rc));
		goto cleanup;
	}

	w = spdk_jsonrpc_begin_result(request);
	spdk_json_write_string(w, req.name);
	spdk_jsonrpc_end_result(request, w);

cleanup:
	free_rpc_bdev_freshness_create(&req);
}
SPDK_RPC_REGISTER("bdev_freshness_create", rpc_bdev_freshness_create, SPDK_RPC_RUNTIME)

struct rpc_bdev_freshness_delete {
	char *name;
};

static void
free_rpc_bdev_freshness_delete(struct rpc_bdev_freshness_delete *req)
{
	free(req->name);
}

static const struct spdk_json_object_decoder rpc_bdev_freshness_delete_decoders[] = {
	{"name", offsetof(struct rpc_bdev_freshness_delete, name), spdk_json_decode_string},
};

static void
rpc_bdev_freshness_delete_cb(void *cb_arg, int bdeverrno)
{
	struct spdk_jsonrpc_request *request = cb_arg;

	if (bdeverrno == 0) {
		spdk_jsonrpc_send_bool_response(request, true);
	} else {
		spdk_jsonrpc_send_error_response(request, bdeverrno, spdk_strerror(-bdeverrno));
	}
}

static void
rpc_bdev_freshness_delete(struct spdk_jsonrpc_request *request,
			 const struct spdk_json_val *params)
{
	struct rpc_bdev_freshness_delete req = {NULL};

	if (spdk_json_decode_object(params, rpc_bdev_freshness_delete_decoders,
				    SPDK_COUNTOF(rpc_bdev_freshness_delete_decoders),
				    &req)) {
		spdk_jsonrpc_send_error_response(request, SPDK_JSONRPC_ERROR_INTERNAL_ERROR,
						 "spdk_json_decode_object failed");
		goto cleanup;
	}

	bdev_freshness_delete_disk(req.name, rpc_bdev_freshness_delete_cb, request);

cleanup:
	free_rpc_bdev_freshness_delete(&req);
}
SPDK_RPC_REGISTER("bdev_freshness_delete", rpc_bdev_freshness_delete, SPDK_RPC_RUNTIME)


// ============================== RPC for freshness evaluation ==============================

/*
 * Used to update the freshness configuration per thread.
 */

/* Structure to hold temporary parameters for the freshness config update (needed in case there are more than one freshness vbdev) */
struct config_update_ctx {
    struct spdk_jsonrpc_request *request;
};

/*
 * RPC parameters struct. We decode "freshness_check_ratio" as a 32-bit int directly.
 */
struct rpc_bdev_freshness_update_config {
    bool        keep_metadata_fresh;
    bool        eventual_consistency;
    int         freshness_check_ratio; /* must be −1 .. 100 */
    bool        freshness_probabilistic_check;
    int         hashing_cores;
};

/*
 * Decoder table for JSON-RPC
 */
static const struct spdk_json_object_decoder rpc_bdev_freshness_update_config_decoders[] = {
    {"keep_metadata_fresh", offsetof(struct rpc_bdev_freshness_update_config, keep_metadata_fresh), spdk_json_decode_bool},
    {"eventual_consistency", offsetof(struct rpc_bdev_freshness_update_config, eventual_consistency), spdk_json_decode_bool},
    {"freshness_check_ratio", offsetof(struct rpc_bdev_freshness_update_config, freshness_check_ratio), spdk_json_decode_int32},
    {"freshness_probabilistic_check", offsetof(struct rpc_bdev_freshness_update_config, freshness_probabilistic_check), spdk_json_decode_bool},
    {"hashing_cores", offsetof(struct rpc_bdev_freshness_update_config, hashing_cores), spdk_json_decode_int32}
};

/*
 * RPC handler: bdev_freshness_update_config
 *
 * Expects:
 * {
 *   "jsonrpc": "2.0",
 *   "method": "bdev_freshness_update_config",
 *   "params": {
 *     "keep_metadata_fresh": <true|false>,
 *     "eventual_consistency": <true|false>,
 *     "freshness_check_ratio": <int in [-1, 100]>,
 *     "freshness_probabilistic_check": <true|false>,
 *     "hashing_cores": <int>
 *   },
 *   "id": <any>
 * }
 *
 * Returns:
 * {
 *   "jsonrpc": "2.0",
 *   "result": {
 *     "keep_metadata_fresh": <bool>,
 *     "eventual_consistency": <bool>,
 *     "freshness_check_ratio": <int>,
 *     "freshness_probabilistic_check": <bool>,
 *     "hashing_cores": <int>
 *   },
 *   "id": <same as request>
 * }
 *
 * Use this to call:
 * echo -n '{"jsonrpc":"2.0","method":"bdev_freshness_update_config","params":{"keep_metadata_fresh":true,"eventual_consistency":false,"freshness_check_ratio":28,"freshness_probabilistic_check":true,"hashing_cores":4},"id":1}'   | sudo socat - UNIX-CONNECT:/var/tmp/spdk.sock
 */

static void synchronize_freshness_config(void *arg)
{
    __sync_synchronize();
    printf("Current local values: \n"
           "  FRESHNESS_CHECK_RATIO: %d\n"
           "  KEEP_METADATA_FRESH: %s\n"
           "  EVENTUAL_CONSISTENCY: %s\n"
           "  FRESHNESS_PROBABILISTIC_CHECK: %s\n"
           "  HASHING_CORES: %d\n",
           global_freshness_config.freshness_check_ratio,
           global_freshness_config.keep_metadata_fresh ? "true" : "false",
           global_freshness_config.eventual_consistency ? "true" : "false",
           global_freshness_config.freshness_probabilistic_check ? "true" : "false",
           global_freshness_config.hashing_cores);
}

static void complete_freshness_config_update(void *arg)
{
    struct spdk_jsonrpc_request *request = (struct spdk_jsonrpc_request *)arg;
    struct spdk_json_write_ctx *w;

    /* Build the JSON-RPC result object with the final stored values */
    w = spdk_jsonrpc_begin_result(request);
    spdk_json_write_object_begin(w);

    spdk_json_write_named_bool(w, "keep_metadata_fresh",
                               global_freshness_config.keep_metadata_fresh);
    spdk_json_write_named_bool(w, "eventual_consistency",
                               global_freshness_config.eventual_consistency);
    spdk_json_write_named_int32(w, "freshness_check_ratio",
                                global_freshness_config.freshness_check_ratio);
    spdk_json_write_named_bool(w, "freshness_probabilistic_check",
                                global_freshness_config.freshness_probabilistic_check);
    spdk_json_write_named_int32(w, "hashing_cores",
                                global_freshness_config.hashing_cores);

    spdk_json_write_object_end(w);
    spdk_jsonrpc_end_result(request, w);

    SPDK_NOTICELOG("Freshness configuration updated successfully:\n"
                   "  FRESHNESS_CHECK_RATIO: %d\n"
                   "  KEEP_METADATA_FRESH: %s\n"
                   "  EVENTUAL_CONSISTENCY: %s\n"
                   "  FRESHNESS_PROBABILISTIC_CHECK: %s\n"
                   "  HASHING_CORES: %d\n",
                   global_freshness_config.freshness_check_ratio,
                   global_freshness_config.keep_metadata_fresh ? "true" : "false",
                   global_freshness_config.eventual_consistency ? "true" : "false",
                   global_freshness_config.freshness_probabilistic_check ? "true" : "false",
                   global_freshness_config.hashing_cores);
}

static void
rpc_bdev_freshness_update_config(struct spdk_jsonrpc_request *request,
                                 const struct spdk_json_val *params)
{
    int rc;
    struct rpc_bdev_freshness_update_config req = { false, true, 0, false, 4 };

    /* Decode JSON params into req */
    rc = spdk_json_decode_object(params,
                                 rpc_bdev_freshness_update_config_decoders,
                                 SPDK_COUNTOF(rpc_bdev_freshness_update_config_decoders),
                                 &req);
    if (rc != 0) {
        SPDK_DEBUGLOG(vbdev_freshness, "spdk_json_decode_object failed\n");
        spdk_jsonrpc_send_error_response(request,
                                         SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "Missing or invalid parameters. "
                                         "Expected keep_metadata_fresh (bool), "
                                         "eventual_consistency (bool), "
                                         "freshness_check_ratio (int), "
                                         "freshness_probabilistic_check (bool), and "
                                         "hashing_cores (int).");
        return;
    }

    /* Validate that freshness_check_ratio ∈ [−1, 100] */
    if (req.freshness_check_ratio < -1 || req.freshness_check_ratio > 100) {
        spdk_jsonrpc_send_error_response(request,
                                         SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                         "freshness_check_ratio must be between -1 and 100.");
        return;
    }

    if (req.hashing_cores <= 0 || req.hashing_cores > MAX_HASHER_THREADS) {
    spdk_jsonrpc_send_error_response(request,
                                     SPDK_JSONRPC_ERROR_INVALID_PARAMS,
                                     "hashing_cores must be > 0 and <= MAX_HASHER_THREADS.");
    return;
    }

    /* Call each of the threads with the update function and synchronize */
    global_freshness_config.keep_metadata_fresh = req.keep_metadata_fresh;
    global_freshness_config.eventual_consistency = req.eventual_consistency;
    global_freshness_config.freshness_check_ratio = req.freshness_check_ratio;
    global_freshness_config.freshness_probabilistic_check = req.freshness_probabilistic_check;
    global_freshness_config.hashing_cores = req.hashing_cores;
    __sync_synchronize();

    /* Propagate the change to all threads which will now synchronize as well */
    spdk_for_each_thread(synchronize_freshness_config, request, complete_freshness_config_update);

    /* Log the change */
    SPDK_NOTICELOG("Freshness configuration scheduled for update:\n"
                   "  FRESHNESS_CHECK_RATIO: %d\n"
                   "  KEEP_METADATA_FRESH: %s\n"
                   "  EVENTUAL_CONSISTENCY: %s\n"
                   "  FRESHNESS_PROBABILISTIC_CHECK: %s\n"
                   "  HASHING_CORES: %d\n",
                   global_freshness_config.freshness_check_ratio,
                   global_freshness_config.keep_metadata_fresh ? "true" : "false",
                   global_freshness_config.eventual_consistency ? "true" : "false",
                   global_freshness_config.freshness_probabilistic_check ? "true" : "false",
                   global_freshness_config.hashing_cores);
}

/* Register the RPC so SPDK’s JSON-RPC server knows about it */
SPDK_RPC_REGISTER("bdev_freshness_update_config", rpc_bdev_freshness_update_config, SPDK_RPC_RUNTIME);
