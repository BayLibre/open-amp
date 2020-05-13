/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <uapi/dma-buf.h>
#include <uapi/ion.h>

#include <rich-iot/apu-host.h>
#include <rich-iot/memory.h>
#include "ion.h"

struct apu_buffer *apu_alloc_buffer(struct apu_device *dev, size_t size)
{
	int ret;
	struct apu_buffer *buffer;
	int heap_id = find_ion_heap_id(dev->ion_fd, ION_HEAP_TYPE_DMA);
	struct ion_allocation_data data = {
		.len = size,
		.heap_id_mask = 1 << heap_id,
		.flags = ION_FLAG_CACHED,
		.fd = 0,
	};

	ret = ioctl(dev->ion_fd, ION_IOC_ALLOC, (void *)&data);
	if (ret < 0)
		return NULL;

	buffer = malloc(sizeof(*buffer));
	if (!buffer) {
		close(data.fd);
		return NULL;
	}

	buffer->fd = data.fd;
	buffer->size = size;
	buffer->data_size = size;
	buffer->mmap_refcount = 0;
	buffer->sync_refcount = 0;

	return buffer;
}

void apu_free_buffer(struct apu_buffer *buffer)
{
	close(buffer->fd);
	free(buffer);
}

void *apu_map_buffer(struct apu_buffer *buffer)
{
	if (buffer->mmap_refcount++ == 0) {
		buffer->ptr = mmap(NULL, buffer->size, PROT_READ | PROT_WRITE,
				   MAP_SHARED, buffer->fd, 0);
		if(buffer->ptr == MAP_FAILED)
			return NULL;
	}

	return buffer->ptr;
}

int apu_unmap_buffer(struct apu_buffer *buffer)
{
	if (buffer->mmap_refcount-- == 1) {
		int ret;

		ret = munmap(buffer->ptr, buffer->size);
		if (!ret)
			buffer->ptr = NULL;
		return ret;
	}

	return 0;
}

int apu_get_buffer_access(struct apu_buffer *buffer)
{
	if (buffer->sync_refcount++ == 0) {
		struct dma_buf_sync sync_start = { 0 };

		sync_start.flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW;
		return ioctl(buffer->fd, DMA_BUF_IOCTL_SYNC, &sync_start);
	}

	return 0;
}

int apu_put_buffer_access(struct apu_buffer *buffer)
{
	if (buffer->sync_refcount-- == 1) {
		struct dma_buf_sync sync_start = { 0 };

		sync_start.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
		return ioctl(buffer->fd, DMA_BUF_IOCTL_SYNC, &sync_start);
	}

	return 0;
}

void *apu_get_buffer(struct apu_buffer *buffer)
{
	if (!apu_map_buffer(buffer))
		return NULL;

	if (apu_get_buffer_access(buffer)) {
		apu_unmap_buffer(buffer);
		return NULL;
	}

	return buffer->ptr;
}

int apu_put_buffer(struct apu_buffer *buffer)
{
	int ret;

	ret = apu_put_buffer_access(buffer);
	if (ret)
		return ret;

	ret = apu_unmap_buffer(buffer);
	if (ret)
		return ret;

	return 0;
}
