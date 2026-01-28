/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>
#include <doca_aes_gcm.h>

#include "doca_utils.h"
#include "vbdev_integrity.h"

DOCA_LOG_REGISTER(COMMON);
extern struct iobuf g_iobuf;

/**
 * Callback triggered whenever AES-GCM state changes
 *
 * @user_data [in]: User data associated with the AES-GCM context. Will hold struct aes_gcm_resources *
 * @ctx [in]: The AES-GCM context that had a state change
 * @prev_state [in]: Previous context state
 * @next_state [in]: Next context state (context is already in this state when the callback is called)
 */
static void aes_gcm_state_changed_callback(const union doca_data user_data,
										   struct doca_ctx *ctx,
										   enum doca_ctx_states prev_state,
										   enum doca_ctx_states next_state)
{
	switch (next_state) {
	case DOCA_CTX_STATE_IDLE:
		DOCA_LOG_INFO("AES-GCM context has been stopped");
		/* We can stop progressing the PE */
		break;
	case DOCA_CTX_STATE_STARTING:
		/**
		 * The context is in starting state, this is unexpected for AES-GCM.
		 */
		DOCA_LOG_ERR("AES-GCM context entered into starting state. Unexpected transition");
		break;
	case DOCA_CTX_STATE_RUNNING:
		DOCA_LOG_INFO("AES-GCM context is running");
		break;
	case DOCA_CTX_STATE_STOPPING:
		/**
		 * doca_ctx_stop() has been called.
		 * In this sample, this happens either due to a failure encountered, in which case doca_pe_progress()
		 * will cause any inflight task to be flushed, or due to the successful compilation of the sample flow.
		 * In both cases, in this sample, doca_pe_progress() will eventually transition the context to idle
		 * state.
		 */
		DOCA_LOG_INFO("AES-GCM context entered into stopping state. Any inflight tasks will be flushed");
		break;
	default:
		break;
	}
}

doca_error_t doca_initialize_channel(struct doca_config *cfg, struct spdk_io_channel *ch, doca_aes_gcm_task_encrypt_completion_cb_t encrypt_completion,
																						  doca_aes_gcm_task_encrypt_completion_cb_t encrypt_error,
																						  doca_aes_gcm_task_decrypt_completion_cb_t decrypt_completion,
																						  doca_aes_gcm_task_decrypt_completion_cb_t decrypt_error)
{
	doca_error_t result, tmp_result;
	union doca_data ctx_user_data;
	cfg->buffer_index = 0;

	result = open_doca_device_with_pci("03:00.0", &aes_gcm_task_is_supported, &cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to open DOCA device for DOCA AES-GCM: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_aes_gcm_create(cfg->dev, &cfg->aes_gcm);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create AES-GCM engine: %s", doca_error_get_descr(result));
		goto close_device;
	}

	cfg->ctx = doca_aes_gcm_as_ctx(cfg->aes_gcm);

	result = doca_ctx_set_state_changed_cb(cfg->ctx, aes_gcm_state_changed_callback);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set AES-GCM state change callback: %s", doca_error_get_descr(result));
		goto destroy_aes_gcm;
	}

	result = doca_pe_create(&cfg->pe);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create progress engine: %s", doca_error_get_descr(result));
		goto destroy_aes_gcm;
	}

	result = doca_pe_connect_ctx(cfg->pe, cfg->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set progress engine for PE: %s", doca_error_get_descr(result));
		goto destroy_pe;
	}

	result = doca_aes_gcm_task_encrypt_set_conf(cfg->aes_gcm,
												encrypt_completion,
												encrypt_error,
												g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set configurations for AES-GCM encrypt task: %s", doca_error_get_descr(result));
		goto destroy_pe;
	}

	result = doca_aes_gcm_task_decrypt_set_conf(cfg->aes_gcm,
												decrypt_completion,
												decrypt_error,
												g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set configurations for AES-GCM decrypt task: %s", doca_error_get_descr(result));
		goto destroy_pe;
	}

	ctx_user_data.ptr = ch;
	result = doca_ctx_set_user_data(cfg->ctx, ctx_user_data);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to set user context for AES-GCM: %s", doca_error_get_descr(result));
		goto destroy_pe;
	}

	result = doca_ctx_start(cfg->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
		goto destroy_pe;
	}

	memset(cfg->raw_key, 0, MAX_AES_GCM_KEY_SIZE);
	cfg->raw_key_type = DOCA_AES_GCM_KEY_256;
	cfg->tag_size = AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES;
	cfg->aad_size = 0;
	result = doca_aes_gcm_key_create(cfg->aes_gcm, cfg->raw_key, cfg->raw_key_type, &cfg->key);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DOCA AES-GCM key: %s", doca_error_get_descr(result));
		goto stop_ctx;
	}

	result = doca_buf_inventory_create(3 * g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE, &cfg->buf_inv); // 1 more needed for the zero buffer
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create buffer inventory: %s", doca_error_get_descr(result));
		goto stop_ctx;
	}

	result = doca_buf_inventory_start(cfg->buf_inv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to start buffer inventory: %s", doca_error_get_descr(result));
		goto destroy_buf_inv;
	}

	return result;

destroy_buf_inv:
	tmp_result = doca_buf_inventory_destroy(cfg->buf_inv);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destroy buffer inventory: %s", doca_error_get_descr(tmp_result));
	}
stop_ctx:
	tmp_result = doca_ctx_stop(cfg->ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to stop ctx: %s", doca_error_get_descr(tmp_result));
	}
destroy_aes_gcm:
	tmp_result = doca_aes_gcm_destroy(cfg->aes_gcm);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA AES-GCM: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_pe:
	tmp_result = doca_pe_destroy(cfg->pe);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destroy PE: %s", doca_error_get_descr(tmp_result));
	}
close_device:
	tmp_result = doca_dev_close(cfg->dev);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to close device: %s", doca_error_get_descr(tmp_result));
	}

	return result;
}

doca_error_t doca_close_channel(struct doca_config *cfg)
{
	doca_error_t result = DOCA_SUCCESS, tmp_result = DOCA_SUCCESS;

	for (size_t i = 0; i < g_iobuf.opts.small_pool_count * g_iobuf.opts.small_bufsize / BLOCK_SIZE; i++) {
		struct buffer *current_buffer = cfg->temporary_buffers + i;

		tmp_result = doca_buf_dec_refcount(*(cfg->zero_buffers + i), NULL);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_ERROR_PROPAGATE(result, tmp_result);
			DOCA_LOG_ERR("Failed to destory zero buffer: %s", doca_error_get_descr(tmp_result));
		}

		tmp_result = doca_buf_dec_refcount(current_buffer->temporary_buffer, NULL);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_ERROR_PROPAGATE(result, tmp_result);
			DOCA_LOG_ERR("Failed to destory destination buffer %ld: %s", i, doca_error_get_descr(tmp_result));
		}

		tmp_result = doca_buf_dec_refcount(*(cfg->original_buffers + i), NULL);
		if (tmp_result != DOCA_SUCCESS) {
			DOCA_ERROR_PROPAGATE(result, tmp_result);
			DOCA_LOG_ERR("Failed to destory source buffer %ld: %s", i, doca_error_get_descr(tmp_result));
		}

		doca_task_free(doca_aes_gcm_task_encrypt_as_task(current_buffer->encryption_task));
		doca_task_free(doca_aes_gcm_task_decrypt_as_task(current_buffer->decryption_task));
	}

	tmp_result = doca_mmap_destroy(cfg->local_mmap);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destory mmap: %s", doca_error_get_descr(tmp_result));
	}
	tmp_result = doca_mmap_destroy(cfg->global_mmap);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destory mmap: %s", doca_error_get_descr(tmp_result));
	}
	spdk_free(cfg->zero_source_buffer);
	spdk_free(cfg->overall_buffer);
	free(cfg->temporary_buffers);
	free(cfg->original_buffers);
	free(cfg->zero_buffers);

	tmp_result = doca_buf_inventory_stop(cfg->buf_inv);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to stop buffer inventory: %s", doca_error_get_descr(tmp_result));
	}

	tmp_result = doca_buf_inventory_destroy(cfg->buf_inv);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destroy buffer inventory: %s", doca_error_get_descr(tmp_result));
	}

	tmp_result = doca_aes_gcm_key_destroy(cfg->key);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA AES-GCM key: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_ctx_stop(cfg->ctx);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to stop ctx: %s", doca_error_get_descr(tmp_result));
		while (tmp_result != DOCA_SUCCESS) {
			tmp_result = doca_ctx_stop(cfg->ctx);
		}
	}

	tmp_result = doca_aes_gcm_destroy(cfg->aes_gcm);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA AES-GCM: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}

	tmp_result = doca_pe_destroy(cfg->pe);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destroy pe: %s", doca_error_get_descr(tmp_result));
	}

	tmp_result = doca_dev_close(cfg->dev);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to close device: %s", doca_error_get_descr(tmp_result));
	}

	return result;
}

doca_error_t doca_start_mmap(struct doca_config *cfg, struct doca_mmap **mmap, void *buf, size_t length)
{
	doca_error_t result, tmp_result;
	result = doca_mmap_create(mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create destination mmap: %s", doca_error_get_descr(result));
	}

	result = doca_mmap_add_dev(*mmap, cfg->dev);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to add device to destination mmap: %s", doca_error_get_descr(result));
		goto destroy_mmap;
	}

	result = doca_mmap_set_memrange(*mmap, buf, length);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto destroy_mmap;
	}

	result = doca_mmap_start(*mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto destroy_mmap;
	}

	return result;

destroy_mmap:
	tmp_result = doca_mmap_destroy(*mmap);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_ERROR_PROPAGATE(result, tmp_result);
		DOCA_LOG_ERR("Failed to destory mmap: %s", doca_error_get_descr(tmp_result));
	}

	return result;
}


doca_error_t doca_register_buffer(struct doca_config *cfg, void *temporary_buf, struct buffer *current_buffer) 
{
	doca_error_t result;
	current_buffer->temporary_address = temporary_buf;
	current_buffer->temporary_metadata = temporary_buf + BLOCK_SIZE;

	result = doca_buf_inventory_buf_get_by_addr(cfg->buf_inv, cfg->local_mmap, current_buffer->temporary_address, CACHE_SIZE, &current_buffer->temporary_buffer);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s",
			     doca_error_get_descr(result));
		return result;
	}

	union doca_data task_user_data = {0};
	task_user_data.ptr = current_buffer;
	result = doca_aes_gcm_task_encrypt_alloc_init(cfg->aes_gcm,
												  *cfg->original_buffers,
												  current_buffer->temporary_buffer,
												  cfg->key,
												  (uint8_t *)&current_buffer->temporary_metadata->IV,
												  sizeof(current_buffer->temporary_metadata->IV),
												  cfg->tag_size,
												  cfg->aad_size,
												  task_user_data,
												  &current_buffer->encryption_task);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate encrypt task: %s", doca_error_get_descr(result));
		return result;
	}

	result = doca_aes_gcm_task_decrypt_alloc_init(cfg->aes_gcm,
												  current_buffer->temporary_buffer,
												  *cfg->original_buffers,
												  cfg->key,
												  (uint8_t *)&current_buffer->temporary_metadata->IV,
												  sizeof(current_buffer->temporary_metadata->IV),
												  cfg->tag_size,
												  cfg->aad_size,
												  task_user_data,
												  &current_buffer->decryption_task);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate decrypt task: %s", doca_error_get_descr(result));
		return result;
	}

	return result;
}


doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval)
{
	struct doca_devinfo **dev_list;
	uint32_t nb_devs;
	uint8_t is_addr_equal = 0;
	int res;
	size_t i;

	/* Set default return value */
	*retval = NULL;

	res = doca_devinfo_create_list(&dev_list, &nb_devs);
	if (res != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to load doca devices list: %s", doca_error_get_descr(res));
		return res;
	}

	/* Search */
	for (i = 0; i < nb_devs; i++) {
		res = doca_devinfo_is_equal_pci_addr(dev_list[i], pci_addr, &is_addr_equal);
		if (res == DOCA_SUCCESS && is_addr_equal) {
			/* If any special capabilities are needed */
			if (func != NULL && func(dev_list[i]) != DOCA_SUCCESS)
				continue;

			/* if device can be opened */
			res = doca_dev_open(dev_list[i], retval);
			if (res == DOCA_SUCCESS) {
				doca_devinfo_destroy_list(dev_list);
				return res;
			}
		}
	}

	DOCA_LOG_WARN("Matching device not found");
	res = DOCA_ERROR_NOT_FOUND;

	doca_devinfo_destroy_list(dev_list);
	return res;
}

int doca_check_pe(void *ctx) {
	struct doca_pe *pe = (struct doca_pe *)ctx;
	int res = doca_pe_progress(pe);
	while (res != 0) {
		res = doca_pe_progress(pe);
	}
	return 1;
}

int doca_flush_tasks(void *ctx) {
	struct doca_ctx *d_ctx = (struct doca_ctx *)ctx;
	doca_ctx_flush_tasks(d_ctx);
	return 1;
}

doca_error_t aes_gcm_task_is_supported(struct doca_devinfo *devinfo)
{
	return doca_aes_gcm_cap_task_encrypt_is_supported(devinfo) && doca_aes_gcm_cap_task_decrypt_is_supported(devinfo);
}

/*
 * Prints one buffer as hexadecimal values.
*/
void printb(struct buffer *buffer) {
	size_t offset = 20;
	size_t length = BLOCK_SIZE;
	printf("\nPrinting buffer with offset: %ld and metadata %ld\n", buffer->block_offset, buffer->temporary_metadata->IV);
	void *location = buffer->temporary_address;
	printf("Offset: ");
	for (size_t i = 0; i < offset; i++) {
		printf("%02x", *((uint8_t *)location - offset + i));
	}
	printf("\nData source (%p): ", buffer->temporary_address);
	for (size_t i = offset; i < length + offset; i++) {
		printf("%02x", *((uint8_t *)location - offset + i));
	}
	printf("...\nMetadata source (%p): ", buffer->temporary_metadata);
    for (size_t i = offset + BLOCK_SIZE; i < BLOCK_SIZE + CACHE_METADATA + offset; i++) {
        printf("%02x", *((uint8_t *)location - offset + i));
    }
	printf("\n");
}

/*
 * Prints one buffer as hexadecimal values.
*/
void printbs(struct buffer *buffer) {
	static pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&print_mutex);
	size_t length = 16;
	void *location = buffer->source_address;
	for (size_t i = 0; i < length; i++) {
		printf("%02x", *((uint8_t *)location + i));
	}
	printf(" -> ");
	location = buffer->temporary_address;
	for (size_t i = 0; i < length; i++) {
		printf("%02x", *((uint8_t *)location + i));
	}
	printf("\n");
	pthread_mutex_unlock(&print_mutex);
}