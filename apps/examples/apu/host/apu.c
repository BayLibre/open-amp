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
#include <poll.h>
#include <pthread.h>

#include <rich-iot/apu-host.h>
#include <rich-iot/memory.h>
#include <uapi/mtk_apu.h>

struct node {
	struct apu_request *req;
	struct apu_inline_buffer *inline_buffer;
	struct apu_buffer **buffers;
	int count;
	apu_callback callback;
	void *data;
	struct node *next;
};

struct sync_request_data {
	int result;
	pthread_cond_t *cv;
};

static struct node *head;
static pthread_mutex_t mutex;

static void *apu_device_main_loop_th(void *arg);

static void add(struct apu_request *req,
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers,
		int count,
		apu_callback callback,
		void *data)
{
	struct node *new_node = (struct node *) malloc(sizeof(struct node));

	new_node->req = req;
	new_node->inline_buffer = inline_buffer;
	new_node->buffers = buffers;
	new_node->count = count;
	new_node->callback = callback;
	new_node->data = data;

	pthread_mutex_lock(&mutex);
	new_node->next = head;
	head = new_node;
	pthread_mutex_unlock(&mutex);
}

static struct node *pop(int id)
{
	struct node *current = head;
	struct node *previous = NULL;

	pthread_mutex_lock(&mutex);
	if (head == NULL) {
		pthread_mutex_unlock(&mutex);
		return NULL;
	}

	while (current->req->id != id) {
		if (current->next == NULL) {
			pthread_mutex_unlock(&mutex);
			return NULL;
		}
		previous = current;
		current = current->next;
	}

	if (current == head)
		head = head->next;
	else
		previous->next = current->next;

	pthread_mutex_unlock(&mutex);
	return current;
}

static void sync_request_callback(
	struct apu_inline_buffer *inline_buffer,
	struct apu_buffer **buffers, int count,
	int result, void *data)
{
	(void) inline_buffer;
	(void) buffers;
	(void) count;
	((struct sync_request_data *)data)->result = result;
	pthread_cond_t *cv = ((struct sync_request_data *)data)->cv;

	pthread_cond_signal(cv);
}

void apu_device_loop(struct apu_device *dev)
{
	pthread_join(dev->main_loop_thread, NULL);
}

void apu_device_quit(struct apu_device *dev)
{
	dev->stop = 1;
}

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

	dev->stop = 0;

	pthread_mutex_init(&mutex, NULL);
	pthread_create(&dev->main_loop_thread, NULL, apu_device_main_loop_th, dev);

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
	if (buffer->flags & INLINE_BUFFER_RW) {
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
	return ((uint8_t *)req->data) + req->size_in + req->size_out;
}

static void *apu_request_fd_size(struct apu_request *req)
{
	return ((uint8_t *)apu_request_fd(req)) + sizeof(uint32_t) * req->count;
}

static void *apu_device_main_loop_th(void *arg)
{
	struct apu_device *dev = (struct apu_device *)arg;
	struct pollfd pfd;
	struct apu_request *req;
	uint32_t *req_size;
	int ret;
	int i;
	short revents;

	pfd.fd = dev->apu_fd;
	pfd.events = POLLIN;
	while (1) {
		ret = poll(&pfd, 1, 1000);
		if (ret == -1) {
			printf("error during poll\n");
			break;
		}
		revents = pfd.revents;
		if (revents & POLLIN) {
			__u16 id;
			int result;

			ret = ioctl(pfd.fd, APU_GET_NEXT_AVAILABLE_IOCTL, &id);
			if (ret < 0) {
				if (ret == -ENOMSG)
					continue;

				printf("error during ioctl\n");
				break;
			}
			struct node *node = pop(id);

			if (!node) {
				struct apu_request del_req;

				printf("Error: node id %i, not found\n", id);
				// force the kernel to drop the corresponding request
				memset(&del_req, 0, sizeof(struct apu_request));
				del_req.id = id;
				ioctl(pfd.fd, APU_GET_RESP_IOCTL, &del_req);
				continue;
			}

			req = node->req;
			ret = ioctl(pfd.fd, APU_GET_RESP_IOCTL, req);
			if (ret < 0) {
				printf("error during ioctl\n");
				break;
			}
			result = -req->result;

			req_size = apu_request_fd_size(req);
			ret = apu_request_update_inline_buffer(req, node->inline_buffer);
			if (ret) {
				printf("Failed to allocate inline data buffer\n");
				break;
			}

			for (i = 0; i < node->count; i++) {
				struct apu_buffer *buffer = node->buffers[i];

				if (buffer)
					buffer->data_size = req_size[i];
			}
			if (node->callback)
				((apu_callback)node->callback)(node->inline_buffer,
					node->buffers, node->count, result, node->data);
			free(node);
		}
		if (dev->stop)
			break;
	}
	pthread_exit(NULL);
}

static int _apu_exec(struct apu_device *dev, int cmd,
	     struct apu_inline_buffer *inline_buffer,
	     struct apu_buffer **buffers, int count,
		 apu_callback callback, void *data)
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
	if (ret < 0) {
		printf("Failed to execute APU_SEND_REQ_IOCTL\n");
		goto err_free_req;
	}

	req->id = ret;
	add(req, inline_buffer, buffers, count, callback, data);

	return 0;

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

	return apu_exec(dev, cmd, inline_buffer, buffers, count);
}

int apu_exec(struct apu_device *dev, int cmd,
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers, int count)
{
	int ret;
	struct sync_request_data data;
	pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

	data.result = -1;
	data.cv = &cv;
	ret = _apu_exec(dev, cmd, inline_buffer, buffers, count, sync_request_callback, &data);
	if (ret < 0)
		return ret;

	pthread_mutex_lock(&lock);
	pthread_cond_wait(&cv, &lock);
	pthread_mutex_unlock(&lock);
	return data.result;
}

int apu_exec_async(struct apu_device *dev, int cmd,
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers, int count,
		apu_callback callback, void *data)
{
	int ret;

	ret = _apu_exec(dev, cmd, inline_buffer, buffers, count, callback, data);
	if (ret < 0)
		return ret;
	return 0;
}
