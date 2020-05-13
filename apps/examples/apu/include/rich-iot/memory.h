/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __RICH_IOT_NN_MEMORY_H__
#define __RICH_IOT_NN_MEMORY_H__

#include <stdint.h>
#include <rich-iot/memory.h>

#define SHARED_BUFFER_RW	0
#define SHARED_BUFFER_RO	(1 << 31)
#define SHARED_BUFFER_WO	(1 << 30)

struct apu_buffer {
	int fd;
	void *ptr;
	size_t size;
	size_t data_size;

	int mmap_refcount;
	int sync_refcount;
};

/**
 * @brief Allocate a shared memory
 * This allocates a buffer using ion in order to share it with the device.
 * @arg The size of buffer to allocate
 * @return an apu_buffer or NULL in the case of error
 */
struct apu_buffer *apu_alloc_buffer(struct apu_device *dev, size_t size);

/**
 * @brief Free a shared memory
 * This frees a buffer allocated using using ion.
 * @arg buffer The apu_buffer to release
 * @return a file descriptor
 */
void apu_free_buffer(struct apu_buffer *buffer);

/**
 * @brief Get access to buffer
 * This map the buffer to make it usable from CPU and request an exclusive
 * access. Once the buffer has been filled, it must be released using
 * apu_put_buffer().
 * @arg buffer The apu_buffer to map
 * @return the a pointer or NULL in the case of error
 */
void *apu_get_buffer(struct apu_buffer *buffer);

/**
 * @brief Release buffer access
 * Unmap the buffer and release exclusive access granted to CPU.
 * From here. the buffer could be used by the device.
 * @arg buffer The apu_buffer to unmap
 * @return 0 on success or a negative number in the case of error
 */
int apu_put_buffer(struct apu_buffer *buffer);

/* Optional API, more low level but useful to get better performances */

/**
 * @brief Mmap a buffer
 * Mmap a buffer to make usable from host.
 * @arg buffer The apu_buffer to map
 * @return the a pointer or NULL in the case of error
 */
void *apu_map_buffer(struct apu_buffer *buffer);

/**
 * @brief Unmap a buffer
 * @arg buffer The apu_buffer to unmap
 * @return 0 on success or a negative number in the case of error
 */
int apu_unmap_buffer(struct apu_buffer *buffer);

/**
 * @brief Request access to the buffer from CPU
 * The buffer is shared with the device. This requests the an exclusive access
 * to the buffer. This is required to avoid concurrent access between CPU and
 * remote device. In order, this will takes care of cache coherency.
 */
int apu_get_buffer_access(struct apu_buffer *buffer);

/**
 * @brief Release buffer CPU access
 * The buffer is shared with the device. This releases the exclusive access
 * granted to the CPU. From here, the device may start to use the buffer,
 * and this will take care of care of cache coherency.
 */
int apu_put_buffer_access(struct apu_buffer *buffer);

/**
 * @brief Share a buffer with the device
 * The kernel must map the buffer to make it available to the device.
 * This operation is done automatically by the driver before to execute a
 * command but this is time consumptive.
 * This function will instruct the kernel to map once the buffer, and left it
 * available to device until we unmap it.
 * @arg buffer The buffer to share with the device
 * @return 0 on success, or a negative a value in the case of error
 */
int apu_share_buffer(struct apu_buffer *buffer);

/**
 * @brief Unshare a buffer
 * This instruct the kernel to unmap the buffer.
 * From here, the device can't access to the buffer.
 * If a command use this buffer, then the kernel will map it automatically.
 * @arg buffer The buffer to share with the device
 * @return 0 on success, or a negative a value in the case of error
 */
int apu_unshare_buffer(struct apu_buffer *buffer);

#endif /* __RICH_IOT_NN_MEMORY_H__ */
