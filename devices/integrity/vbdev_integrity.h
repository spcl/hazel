/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 */

#ifndef SPDK_VBDEV_PASSTHRU_H
#define SPDK_VBDEV_PASSTHRU_H

#define CACHE_NUM_ELEMENTS 16384
#define BLOCK_SIZE 4096 // TODO make automatic
#define CACHE_AUTH_TAG AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES
#define CACHE_IV	   48 // size of IV and remaining information in bytes - note needs to make sure the bottom aligns with the actual metadata size
#define CACHE_METADATA 64 // note this needs to be the exact size of the metadata, otherwise, the alignment of buffers will be incorrect	
#define CACHE_SIZE (BLOCK_SIZE + CACHE_METADATA)

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/bdev_module.h"

/**
 * Create new pass through bdev.
 *
 * \param bdev_name Bdev on which pass through vbdev will be created.
 * \param vbdev_name Name of the pass through bdev.
 * \param uuid Optional UUID to assign to the pass through bdev.
 * \return 0 on success, other on failure.
 */
int bdev_integrity_create_disk(const char *bdev_name, const char *vbdev_name,
			      const struct spdk_uuid *uuid);

/**
 * Delete integrity bdev.
 *
 * \param bdev_name Name of the pass through bdev.
 * \param cb_fn Function to call after deletion.
 * \param cb_arg Argument to pass to cb_fn.
 */
void bdev_integrity_delete_disk(const char *bdev_name, spdk_bdev_unregister_cb cb_fn,
			       void *cb_arg);

#endif /* SPDK_VBDEV_PASSTHRU_H */
