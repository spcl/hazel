/*   SPDX-License-Identifier: BSD-3-Clause
 *   Copyright (C) 2018 Intel Corporation.
 *   All rights reserved.
 */

#ifndef SPDK_VBDEV_freshness_H
#define SPDK_VBDEV_freshness_H

#include "spdk/stdinc.h"

#include "spdk/bdev.h"
#include "spdk/bdev_module.h"

#include "constants.h"
#include "request.h"
#include "cache.h"
#include "hashing.h"

struct vbdev_freshness {
	struct spdk_bdev		*base_bdev; /* the thing we're attaching to */
	struct spdk_bdev_desc		*base_desc; /* its descriptor we get from open */
	struct spdk_bdev		pt_bdev;    /* the PT virtual bdev */
	TAILQ_ENTRY(vbdev_freshness)	link;
	struct spdk_thread		*thread;    /* thread where base device is opened */
	struct tree				hashing_tree;	/* the hashing tree. */
	struct cache			*cache; /* the in-memory cache for the IVs. */
	struct spdk_io_channel	*initialization_ch; /* channel used for initilization */
};

/**
 * Create new pass through bdev.
 *
 * \param bdev_name Bdev on which pass through vbdev will be created.
 * \param vbdev_name Name of the pass through bdev.
 * \param uuid Optional UUID to assign to the pass through bdev.
 * \return 0 on success, other on failure.
 */
int bdev_freshness_create_disk(const char *bdev_name, const char *vbdev_name,
			      const struct spdk_uuid *uuid);

/**
 * Delete freshness bdev.
 *
 * \param bdev_name Name of the pass through bdev.
 * \param cb_fn Function to call after deletion.
 * \param cb_arg Argument to pass to cb_fn.
 */
void bdev_freshness_delete_disk(const char *bdev_name, spdk_bdev_unregister_cb cb_fn,
			       void *cb_arg);

#endif /* SPDK_VBDEV_freshness_H */
