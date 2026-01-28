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

#ifndef COMMON_H_
#define COMMON_H_

#include <doca_error.h>
#include <doca_dev.h>
#include <doca_buf.h>
#include "spdk/bdev_module.h"
#include "vbdev_integrity.h"
#include "ipsec.h"

#define CHECK_DOCA_SUCCESS(ret, msg)         \
    do {                                     \
        if ((ret) != DOCA_SUCCESS) {         \
            fprintf(stderr, "%s: %d\n",      \
                    (msg), ret);             \
        }                                    \
    } while (0)

#define AES_GCM_KEY_128_SIZE_IN_BYTES 16		   /* AES-GCM 128 bits key size */
#define AES_GCM_KEY_256_SIZE_IN_BYTES 32		   /* AES-GCM 256 bits key size */
#define MAX_AES_GCM_KEY_SIZE AES_GCM_KEY_256_SIZE_IN_BYTES /* Max AES-GCM key size in bytes */

#define AES_GCM_KEY_128_STR_SIZE (AES_GCM_KEY_128_SIZE_IN_BYTES * 2) /* AES-GCM 128 bits key string size */
#define AES_GCM_KEY_256_STR_SIZE (AES_GCM_KEY_256_SIZE_IN_BYTES * 2) /* AES-GCM 256 bits key string size */
#define MAX_AES_GCM_KEY_STR_SIZE (AES_GCM_KEY_256_STR_SIZE + 1)	     /* Max AES-GCM key string size */

#define AES_GCM_AUTH_TAG_96_SIZE_IN_BYTES 12  /* AES-GCM 96 bits authentication tag size */
#define AES_GCM_AUTH_TAG_128_SIZE_IN_BYTES 16 /* AES-GCM 128 bits authentication tag size */

#define MAX_AES_GCM_IV_LENGTH 12				    /* Max IV length in bytes */
#define MAX_AES_GCM_IV_STR_LENGTH ((MAX_AES_GCM_IV_LENGTH * 2) + 1) /* Max IV string length */

/* DOCA configuration */
struct doca_config {
	struct doca_aes_gcm 		*aes_gcm;
	struct doca_buf_inventory 	*buf_inv;
	struct doca_dev 			*dev;		    
	struct doca_ctx 			*ctx;
	struct doca_pe 				*pe;
	doca_notification_handle_t	handle;
	struct doca_aes_gcm_key 	*key;
	struct doca_mmap			*zero_mmap;
	struct doca_mmap			*local_mmap;
	struct doca_mmap			*global_mmap;
	struct buffer				*temporary_buffers;
	struct doca_buf				**zero_buffers;
	struct doca_buf				**original_buffers;
	void 						*zero_source_buffer;
	void						*overall_buffer;
	size_t						zero_counter;
	size_t						buffer_index;
	uint8_t raw_key[MAX_AES_GCM_KEY_SIZE];
	enum doca_aes_gcm_key_type raw_key_type;
	uint32_t tag_size;			      /* Authentication tag size */
	uint32_t aad_size;			      /* Additional authenticated data size */
};

/* DOCA buffers */
struct buffer {
	struct doca_aes_gcm_task_encrypt	*encryption_task;
	struct doca_aes_gcm_task_decrypt	*decryption_task;

	struct doca_buf						*temporary_buffer;
	void								*temporary_address;
	struct metadata						*temporary_metadata;
	void								*source_address;

	struct spdk_bdev_io					*bdev_io; // used for tracking where the bdev belongs
	uint64_t							block_offset; // how far in the device should we read / write in blocks
};

struct metadata {
	uint8_t		auth_tag[CACHE_AUTH_TAG];
	// uint8_t		valid;
	uint64_t	IV;
	uint8_t		network_freshness_counter[NETWORK_FRESHNESS_PACKET_SIZE]; // network freshness
	uint8_t		network_freshness_tag[NETWORK_FRESHNESS_TAG_SIZE]; // network freshness tag
	uint8_t		reserved[CACHE_METADATA - CACHE_AUTH_TAG - sizeof(uint64_t) - NETWORK_FRESHNESS_PACKET_SIZE - NETWORK_FRESHNESS_TAG_SIZE]; // reserved for future use
} __attribute__((packed, aligned(8)));

struct resubmission_task {
	struct doca_aes_gcm_task_encrypt 	*encrypt_task;
	union doca_data 					task_user_data;
	union doca_data 					ctx_user_data;
};

/* Function to check if a given device is capable of executing some task */
typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

/* 
 * Initializes all of the necessary DOCA resources for the IO channel.
 *
 * @doca_config [in]: The doca config corresponding to the IO channel for which resources should be initialized.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
*/
doca_error_t doca_initialize_channel(struct doca_config *, struct spdk_io_channel *, doca_aes_gcm_task_encrypt_completion_cb_t, doca_aes_gcm_task_encrypt_completion_cb_t, doca_aes_gcm_task_decrypt_completion_cb_t, doca_aes_gcm_task_decrypt_completion_cb_t);

/* 
 * Closes the DOCA channel.
 *
 * @doca_config [in]: The doca config corresponding to the IO channel for which resources should be initialized.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
*/
doca_error_t doca_close_channel(struct doca_config *);

/*
 * Registers a buffer with the current configurations that we have
*/
doca_error_t doca_register_buffer(struct doca_config *, void *, struct buffer *);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @pci_addr [in]: PCI address
 * @func [in]: pointer to a function that checks if the device have some task capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval);

/*
 * Check if given device is capable of executing a DOCA AES-GCM encrypt and decrypt tasks.
 *
 * @devinfo [in]: The DOCA device information
 * @return: DOCA_SUCCESS if the device supports DOCA AES-GCM encrypt task and DOCA_ERROR otherwise
 */
doca_error_t aes_gcm_task_is_supported(struct doca_devinfo *devinfo);

/*
 * Encrypt task completed callback
 *
 * @encrypt_task [in]: Completed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
void encrypt_completed_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
				union doca_data task_user_data,
				union doca_data ctx_user_data);

/*
 * Encrypt task error callback
 *
 * @encrypt_task [in]: failed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
void encrypt_error_callback(struct doca_aes_gcm_task_encrypt *encrypt_task,
			    union doca_data task_user_data,
			    union doca_data ctx_user_data);

/*
 * Decrypt task completed callback
 *
 * @decrypt_task [in]: Completed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
void decrypt_completed_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
				union doca_data task_user_data,
				union doca_data ctx_user_data);

/*
 * Decrypt task error callback
 *
 * @decrypt_task [in]: failed task
 * @task_user_data [in]: doca_data from the task
 * @ctx_user_data [in]: doca_data from the context
 */
void decrypt_error_callback(struct doca_aes_gcm_task_decrypt *decrypt_task,
			    union doca_data task_user_data,
			    union doca_data ctx_user_data);

/*
 * Checks the PE for progress. 
*/
int doca_check_pe(void *);
int doca_flush_tasks(void *ctx);

/*
 * Starts the mmap for a given config and buffer.
*/
doca_error_t doca_start_mmap(struct doca_config *cfg, struct doca_mmap **mmap, void *buf, size_t length);

void printb(struct buffer *location);
void printbs(struct buffer *location);

#endif