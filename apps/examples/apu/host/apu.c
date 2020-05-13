/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include <rich-iot/apu-host.h>
#include <rich-iot/memory.h>
#include <uapi/mtk_apu.h>

struct apu_device *apu_device_open(int device_id)
{
	char file_name[32];
	struct apu_device *dev;

	dev = malloc(sizeof(*dev));
	if (!dev)
		return NULL;

	sprintf(file_name, "/dev/apu%d", device_id);
	dev->apu_fd = open(file_name, 0);
	if (dev->apu_fd < 0) {
		printf("Can't open device file: %s\n", file_name);
		free(dev);
		return  NULL;
	}

	dev->ion_fd = open("/dev/ion", 0);
	if (dev->ion_fd < 0) {
		printf("Can't open ion device file\n");
		close(dev->apu_fd);
		free(dev);
		return  NULL;
	}

	return dev;
}

void apu_device_close(struct apu_device *dev)
{
	close(dev->ion_fd);
	close(dev->apu_fd);
	free(dev);
}

struct apu_inline_buffer *apu_inline_buffer(void *data_in, size_t size_in,
	     				    size_t size_out, int flags)
{
	struct apu_inline_buffer *buffer;

	buffer = malloc(sizeof(*buffer));
	if (!buffer)
		return buffer;

	buffer->data_in = data_in;
	buffer->size_in = size_in;
	buffer->data_out = NULL;
	buffer->size_out = size_out;
	buffer->flags = flags;

	if (buffer->size_out) {
		buffer->data_out = malloc(buffer->size_out);
		if (!buffer->data_out) {
			free(buffer);
			return NULL;
		}
	}

	return buffer;
}

void apu_inline_buffer_free(struct apu_inline_buffer *buffer)
{
	if (buffer->data_in)
		free(buffer->data_in);
	if (buffer->data_out)
		free(buffer->data_out);
	free(buffer);
}

struct apu_inline_buffer *apu_inline_buffer_in(void *data_in, size_t size_in)
{
	return apu_inline_buffer(data_in, size_in, 0, 0);
}

struct apu_inline_buffer *apu_inline_buffer_rw(void *data_in, size_t size_in)
{
	return apu_inline_buffer(data_in, size_in, 0, INLINE_BUFFER_RW);
}

struct apu_inline_buffer *apu_inline_buffer_out(size_t size_out)
{
	return apu_inline_buffer(NULL, 0, size_out, 0);
}

size_t apu_inline_buffer_size(struct apu_inline_buffer *buffer)
{
	if (!buffer)
		return 0;

	return buffer->size_in + buffer->size_out;
}

void *apu_inline_buffer_in_read(struct apu_inline_buffer *buffer, size_t *len)
{
	if (buffer->flags & INLINE_BUFFER_RW)
	{
		if (len)
			*len = buffer->size_in;
		return buffer->data_in;
	}

	return NULL;
}

void *apu_inline_buffer_out_read(struct apu_inline_buffer *buffer, size_t *len)
{
	if (len)
		*len = buffer->size_out;
	return buffer->data_out;
}

size_t apu_request_size(struct apu_inline_buffer *buffer, int count)
{
	size_t size = sizeof(struct apu_request);

	size += apu_inline_buffer_size(buffer);
	size += sizeof(uint32_t) * count * 2;

	return size;
}

struct apu_request *apu_request_alloc(struct apu_inline_buffer *buffer,
				      int count)
{
	int size;
	struct apu_request *req;

	size = apu_request_size(buffer, count);
	req = malloc(size);
	if (!req)
		return NULL;

	if (buffer) {
		req->size_in = buffer->size_in;
		req->size_out = buffer->size_out;
		memcpy(req->data, buffer->data_in, buffer->size_in);
		buffer->data_in = NULL;
	} else {
		req->size_in = 0;
		req->size_out = 0;
	}

	req->count = count;

	return req;
}

int apu_request_update_inline_buffer(struct apu_request *req,
				     struct apu_inline_buffer *buffer)
{
	if (!buffer)
		return 0;

	if (buffer->flags & INLINE_BUFFER_RW && req->size_in) {
		buffer->size_in = req->size_in;
		buffer->data_in = malloc(req->size_in);
		if (!buffer->data_in)
			return -ENOMEM;
		memcpy(buffer->data_in, req->data, req->size_in);
	}

	if (req->size_out) {
		buffer->size_out = req->size_out;
		buffer->data_out = malloc(req->size_out);
		if (!buffer->data_out)
			return -ENOMEM;
		memcpy(buffer->data_out, req->data + req->size_in,
			 req->size_out);
	}

	return 0;
}

static void *apu_request_fd(struct apu_request *req)
{
	return req->data + req->size_in + req->size_out;
}

static void *apu_request_fd_size(struct apu_request *req)
{
	return apu_request_fd(req) + sizeof(uint32_t) * req->count;
}

static void *apu_response_fd_size(struct apu_request *req)
{
	return apu_request_fd(req);
}

int apu_exec(struct apu_device *dev, int cmd,
	     struct apu_inline_buffer *inline_buffer,
	     struct apu_buffer **buffers, int count)
{
	int ret;
	struct apu_request *req;
	uint32_t *req_fd;
	uint32_t *req_size;
	int i;

	req = apu_request_alloc(inline_buffer, count);
	if (!req)
		return -ENOMEM;
	req->cmd = cmd;
	req_fd = apu_request_fd(req);
	req_size = apu_request_fd_size(req);

	for (i = 0; i < count; i++) {
		struct apu_buffer *buffer = buffers[i];

		if (!buffer) {
			ret = -EINVAL;
			goto err_free_req;
		}

		req_fd[i] = buffer->fd;
		req_size[i] = buffer->data_size;
	}

	ret = ioctl(dev->apu_fd, APU_SEND_REQ_IOCTL, req);
	if (ret) {
		printf("Failed to execute APU_SEND_REQ_IOCTL\n");
		goto err_free_req;
	}

	ret = -req->result;
	if (ret) {
		printf("%s: Failed to execute command, returned %d\n",
			"apu0", ret);
		goto err_free_req;
	}

	req_size = apu_response_fd_size(req);
	ret = apu_request_update_inline_buffer(req, inline_buffer);
	if (ret) {
		printf("Failed to allocate inline data buffer\n");
		goto err_free_req;
	}

	for (i = 0; i < req->count; i++) {
		struct apu_buffer *buffer = buffers[i];

		if (buffer)
			buffer->data_size = req_size[i];
	}

err_free_req:
	free(req);

	return ret;
}

int apu_vexec(struct apu_device *dev, int cmd,
	      struct apu_inline_buffer *inline_buffer,
	      int count, ...)
{
	struct apu_buffer *buffers[count];
	va_list ap;
	int i;

	va_start(ap, count);
	for (i = 0; i < count; i++)
		buffers[i] = va_arg(ap, struct apu_buffer *);
	va_end(ap);

	return apu_exec(dev, cmd,inline_buffer, buffers, count);
}
