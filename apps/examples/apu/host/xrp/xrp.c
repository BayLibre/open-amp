#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <pthread.h>

#include <xrp/xrp_api.h>
#include <rich-iot/apu-host.h>
#include <rich-iot/memory.h>

#define MAX_BUFFER_GROUP 128

struct xrp_refcounted {
	_Atomic unsigned long count;
};

struct xrp_device {
	struct xrp_refcounted ref;
	struct apu_device *device;
};

struct xrp_queue
{
	struct xrp_refcounted ref;
	struct xrp_device *device;
	int use_nsid;
	int priority;
	uint8_t nsid[XRP_NAMESPACE_ID_SIZE];
};

struct xrp_buffer {
	struct xrp_refcounted ref;
	struct xrp_device *device;
	enum {
		XRP_BUFFER_TYPE_HOST,
		XRP_BUFFER_TYPE_DEVICE,
	} type;
	size_t size;
	_Atomic unsigned long map_count;
	enum xrp_access_flags map_flags;

	struct apu_buffer *buffer;
	void *host_ptr;
};

struct xrp_buffer_group_record {
	struct xrp_buffer *buffer;
	enum xrp_access_flags access_flags;
};

struct xrp_buffer_group
{
	struct xrp_refcounted ref;
	pthread_mutex_t mutex;
	size_t n_buffers;
	size_t capacity;
	struct xrp_buffer_group_record *buffer;
};

struct xrp_event
{
	struct xrp_refcounted ref;
	struct xrp_queue *queue;
	_Atomic enum xrp_status status;
	struct xrp_event *group;
	struct xrp_event_link *link;

	pthread_cond_t cv;
	pthread_mutex_t lock;
	void *out_data;
	struct xrp_device *device;
	struct xrp_buffer_group *buffer_group;
};

struct xrp_event_link {
	struct xrp_event *group;
	struct xrp_event_link *next, *prev;
};

struct xrp_inline_buffer_group {
	uint32_t da;
	uint32_t size;
};

struct xrp_inline_buffer
{
	uint32_t in_data_size;
	uint32_t out_data_size;
	uint32_t n_buffers;
	uint8_t nsid[XRP_NAMESPACE_ID_SIZE];
	struct xrp_inline_buffer_group group[MAX_BUFFER_GROUP];

	uint8_t data[0];
}  __packed;

/* Helpers */

static void set_status(enum xrp_status *status, enum xrp_status v)
{
	if (status) {
		*status = v;
	}
}

static void *alloc_refcounted(size_t sz)
{
	void *buf = calloc(1, sz);
	struct xrp_refcounted *ref = buf;

	if (ref)
		ref->count = 1;

	return buf;
}

static void retain_refcounted(struct xrp_refcounted *ref)
{
	(void)++ref->count;
}

static int last_release_refcounted(struct xrp_refcounted *ref)
{
	return --ref->count == 0;
}

/* Device API. */

struct xrp_device *xrp_open_device(int idx, enum xrp_status *status)
{
	struct xrp_device *device;

	set_status(status, XRP_STATUS_FAILURE);

	device = alloc_refcounted(sizeof(*device));
	if (!device)
		return NULL;

	device->device = apu_device_open(idx);
	if (!device->device) {
		free(device);
		return NULL;
	}

	set_status(status, XRP_STATUS_SUCCESS);
	return device;
}

void xrp_retain_device(struct xrp_device *device)
{
	retain_refcounted(&device->ref);
}

void xrp_release_device(struct xrp_device *device)
{
	if (last_release_refcounted(&device->ref)) {
		apu_device_quit(device->device);
		apu_device_loop(device->device);
		apu_device_close(device->device);
		free(device);
	}
}

/* Buffer API. */

struct xrp_buffer *xrp_create_buffer(struct xrp_device *device,
				     size_t size, void *host_ptr,
				     enum xrp_status *status)
{
	struct xrp_buffer *buf;

	if (!host_ptr && !device) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	buf = alloc_refcounted(sizeof(*buf));
	if (!buf) {
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	buf->host_ptr = NULL;
	buf->size = size;
	buf->buffer = apu_alloc_buffer(device->device, size);
	if (!buf->buffer) {
		free(buf);
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	if (host_ptr) {
		buf->type = XRP_BUFFER_TYPE_HOST;
		buf->host_ptr = host_ptr;
	}

	xrp_retain_device(device);
	buf->device = device;

	set_status(status, XRP_STATUS_SUCCESS);

	return buf;
}

void xrp_retain_buffer(struct xrp_buffer *buffer)
{
	retain_refcounted(&buffer->ref);
}

void xrp_release_buffer(struct xrp_buffer *buffer)
{
	if (last_release_refcounted(&buffer->ref)) {
		xrp_release_device(buffer->device);
		apu_free_buffer(buffer->buffer);
		free(buffer);
	}
}

void *xrp_map_buffer(struct xrp_buffer *buffer, size_t offset, size_t size,
		     enum xrp_access_flags map_flags, enum xrp_status *status)
{
	(void)size;
	(void)map_flags;
	void *ptr;

	xrp_retain_buffer(buffer);
	ptr = apu_get_buffer(buffer->buffer);
	if (!ptr) {
		xrp_release_buffer(buffer);
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	set_status(status, XRP_STATUS_SUCCESS);
	return ((uint8_t *)ptr) + offset;
}

void xrp_unmap_buffer(struct xrp_buffer *buffer, void *p,
		      enum xrp_status *status)
{
	(void)p;
	set_status(status, XRP_STATUS_SUCCESS);
	apu_put_buffer(buffer->buffer);
	xrp_release_buffer(buffer);
}

void xrp_buffer_get_info(struct xrp_buffer *buffer, enum xrp_buffer_info info,
			 void *out, size_t out_sz, enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	switch (info) {
	case XRP_BUFFER_SIZE_SIZE_T:
		sz = sizeof(buffer->size);
		ptr = &buffer->size;
		break;

	case XRP_BUFFER_HOST_POINTER_PTR:
		if (buffer->type != XRP_BUFFER_TYPE_HOST) {
			static void *p = NULL;
			ptr = &p;
		} else {
			ptr = &buffer->host_ptr;
		}
		sz = sizeof(void *);
		break;

	default:
		goto out;
	}

	if (sz == out_sz) {
		memcpy(out, ptr, sz);
		s = XRP_STATUS_SUCCESS;
	}
out:
	set_status(status, s);
}

/* Buffer group API. */

struct xrp_buffer_group *xrp_create_buffer_group(enum xrp_status *status)
{
	struct xrp_buffer_group *group = alloc_refcounted(sizeof(*group));

	if (group) {
		pthread_mutex_init(&group->mutex, NULL);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}

	return group;
}

void xrp_retain_buffer_group(struct xrp_buffer_group *group)
{
	retain_refcounted(&group->ref);
}

void xrp_release_buffer_group(struct xrp_buffer_group *group)
{
	if (last_release_refcounted(&group->ref)) {
		size_t i;

		pthread_mutex_lock(&group->mutex);
		for (i = 0; i < group->n_buffers; ++i)
			xrp_release_buffer(group->buffer[i].buffer);
		pthread_mutex_unlock(&group->mutex);
		pthread_mutex_destroy(&group->mutex);
		free(group->buffer);
		free(group);
	}
}

size_t xrp_add_buffer_to_group(struct xrp_buffer_group *group,
			       struct xrp_buffer *buffer,
			       enum xrp_access_flags access_flags,
			       enum xrp_status *status)
{
	size_t n_buffers;

	pthread_mutex_lock(&group->mutex);
	if (group->n_buffers == group->capacity) {
		struct xrp_buffer_group_record *r =
			realloc(group->buffer,
				sizeof(struct xrp_buffer_group_record) *
				((group->capacity + 2) * 2));

		if (r == NULL) {
			pthread_mutex_unlock(&group->mutex);
			set_status(status, XRP_STATUS_FAILURE);
			return -1;
		}
		group->buffer = r;
		group->capacity = (group->capacity + 2) * 2;
	}

	xrp_retain_buffer(buffer);
	group->buffer[group->n_buffers].buffer = buffer;
	group->buffer[group->n_buffers].access_flags = access_flags;
	n_buffers = group->n_buffers++;
	pthread_mutex_unlock(&group->mutex);
	set_status(status, XRP_STATUS_SUCCESS);
	return n_buffers;
}

void xrp_set_buffer_in_group(struct xrp_buffer_group *group,
			     size_t index,
			     struct xrp_buffer *buffer,
			     enum xrp_access_flags access_flags,
			     enum xrp_status *status)
{
	struct xrp_buffer *old_buffer;

	xrp_retain_buffer(buffer);

	pthread_mutex_lock(&group->mutex);
	if (index < group->n_buffers) {
		old_buffer = group->buffer[index].buffer;
		group->buffer[index].buffer = buffer;
		group->buffer[index].access_flags = access_flags;
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		old_buffer = buffer;
		set_status(status, XRP_STATUS_FAILURE);
	}
	pthread_mutex_unlock(&group->mutex);
	xrp_release_buffer(old_buffer);
}

struct xrp_buffer *xrp_get_buffer_from_group(struct xrp_buffer_group *group,
					     size_t idx,
					     enum xrp_status *status)
{
	struct xrp_buffer *buffer = NULL;

	pthread_mutex_lock(&group->mutex);
	if (idx < group->n_buffers) {
		buffer = group->buffer[idx].buffer;
		xrp_retain_buffer(buffer);
		set_status(status, XRP_STATUS_SUCCESS);
	} else {
		set_status(status, XRP_STATUS_FAILURE);
	}
	pthread_mutex_unlock(&group->mutex);
	return buffer;
}

void xrp_buffer_group_get_info(struct xrp_buffer_group *group,
			       enum xrp_buffer_group_info info, size_t idx,
			       void *out, size_t out_sz,
			       enum xrp_status *status)
{
	enum xrp_status s = XRP_STATUS_FAILURE;
	size_t sz;
	void *ptr;

	pthread_mutex_lock(&group->mutex);
	switch (info) {
	case XRP_BUFFER_GROUP_BUFFER_FLAGS_ENUM:
		if (idx >= group->n_buffers)
			goto out;
		sz = sizeof(group->buffer[idx].access_flags);
		ptr = &group->buffer[idx].access_flags;
		break;

	case XRP_BUFFER_GROUP_SIZE_SIZE_T:
		sz = sizeof(group->n_buffers);
		ptr = &group->n_buffers;
		break;

	default:
		goto out;
	}

	if (sz == out_sz) {
		memcpy(out, ptr, sz);
		s = XRP_STATUS_SUCCESS;
	}
out:
	pthread_mutex_unlock(&group->mutex);
	set_status(status, s);
}

/* Queue API. */

void xrp_impl_create_queue(struct xrp_queue *queue,
			   enum xrp_status *status)
{
	set_status(status, XRP_STATUS_FAILURE);

	if (!queue->use_nsid)
		memset(queue->nsid, 0, XRP_NAMESPACE_ID_SIZE);

	set_status(status, XRP_STATUS_SUCCESS);
}

void xrp_impl_release_queue(struct xrp_queue *queue)
{
	(void)queue;
}

struct xrp_queue *xrp_create_queue(struct xrp_device *device,
				   enum xrp_status *status)
{
	return xrp_create_ns_queue(device, NULL, status);
}

struct xrp_queue *xrp_create_ns_queue(struct xrp_device *device,
				      const void *nsid,
				      enum xrp_status *status)
{
	return xrp_create_nsp_queue(device, nsid, 0, status);
}

struct xrp_queue *xrp_create_nsp_queue(struct xrp_device *device,
				       const void *nsid,
				       int priority,
				       enum xrp_status *status)
{
	struct xrp_queue *queue;

	xrp_retain_device(device);
	queue = alloc_refcounted(sizeof(*queue));

	if (!queue) {
		xrp_release_device(device);
		set_status(status, XRP_STATUS_FAILURE);
		return NULL;
	}

	queue->device = device;
	if (nsid) {
		queue->use_nsid = 1;
		memcpy(queue->nsid, nsid, XRP_NAMESPACE_ID_SIZE);
	}
	queue->priority = priority;

	xrp_impl_create_queue(queue, status);

	return queue;
}

void xrp_retain_queue(struct xrp_queue *queue)
{
	retain_refcounted(&queue->ref);
}

void xrp_release_queue(struct xrp_queue *queue)
{
	if (last_release_refcounted(&queue->ref)) {
		xrp_impl_release_queue(queue);
		xrp_release_device(queue->device);
		free(queue);
	}
}

/* Event API. */

static void xrp_impl_event_init(struct xrp_event *event)
{
	pthread_cond_init(&event->cv, NULL);
	pthread_mutex_init(&event->lock, NULL);
	event->status = XRP_STATUS_PENDING;
}

static struct xrp_event *xrp_event_create(void)
{
	struct xrp_event *event = alloc_refcounted(sizeof(*event));

	if (!event)
		return NULL;
	xrp_impl_event_init(event);
	return event;
}

static void xrp_impl_release_event(struct xrp_event *event)
{
	pthread_mutex_destroy(&event->lock);
}

void xrp_retain_event(struct xrp_event *event)
{
	retain_refcounted(&event->ref);
}

void xrp_release_event(struct xrp_event *event)
{
	if (last_release_refcounted(&event->ref)) {
		xrp_impl_release_event(event);
		xrp_release_queue(event->queue);
		free(event);
	}
}

void xrp_event_status(struct xrp_event *event, enum xrp_status *status)
{
	set_status(status, event->status);
}

/* Communication API */

void xrp_run_command_sync(struct xrp_queue *queue,
			  const void *in_data, size_t in_data_size,
			  void *out_data, size_t out_data_size,
			  struct xrp_buffer_group *buffer_group,
			  enum xrp_status *status)
{
	struct xrp_event *evt;
	enum xrp_status s;

	xrp_enqueue_command(queue, in_data, in_data_size,
			    out_data, out_data_size,
			    buffer_group, &evt, &s);
	if (s != XRP_STATUS_SUCCESS) {
		set_status(status, s);
		return;
	}
	xrp_wait(evt, NULL);
	xrp_event_status(evt, status);
	xrp_release_event(evt);
}


static void sync_request_callback(
	struct apu_inline_buffer *inline_buffer,
	struct apu_buffer **buffers, int count,
	int ret,
	void *data)
{
	(void) inline_buffer;
	(void) buffers;
	(void) count;
	size_t i;
	struct xrp_event *event = data;
	pthread_cond_t *cv = &event->cv;
	struct xrp_buffer_group *buffer_group = event->buffer_group;
	struct xrp_inline_buffer *xrp_inline_buffer;

	xrp_inline_buffer = apu_get_buffer(buffers[0]);
	memcpy(event->out_data,
	       xrp_inline_buffer->data + xrp_inline_buffer->in_data_size,
	       xrp_inline_buffer->out_data_size);
	if (buffer_group) {
		for (i = 0; i < buffer_group->n_buffers; i++) {
			struct apu_buffer *tmp;

			tmp = buffer_group->buffer[i].buffer->buffer;
			apu_iommu_unmap_buffer(event->device->device, tmp);
			if (buffer_group->buffer[i].buffer->host_ptr) {
				void *ptr;

				ptr = apu_get_buffer(tmp);
				memcpy(buffer_group->buffer[i].buffer->host_ptr, ptr, tmp->size);
				apu_put_buffer(tmp);
			}
		}
	}

	apu_put_buffer(buffers[0]);
	apu_free_buffer(buffers[0]);
	free(buffers);
	if (buffer_group)
		xrp_release_buffer_group(event->buffer_group);

	event->status = ret ? XRP_STATUS_FAILURE : XRP_STATUS_SUCCESS;
	pthread_cond_signal(cv);

	xrp_release_event(event);
}


void xrp_enqueue_command(struct xrp_queue *queue,
			 const void *in_data, size_t in_data_size,
			 void *out_data, size_t out_data_size,
			 struct xrp_buffer_group *buffer_group,
			 struct xrp_event **event,
			 enum xrp_status *status)
{
	struct apu_buffer *buffer;
	struct apu_buffer **buffers = malloc(sizeof(*buffers));
	struct xrp_inline_buffer *xrp_inline_buffer;
	struct xrp_event *p_event = NULL;
	size_t count = buffer_group ? buffer_group->n_buffers : 0;
	size_t i;

	*status = XRP_STATUS_FAILURE;

	buffer = apu_alloc_buffer(queue->device->device,
				  sizeof(*xrp_inline_buffer) +
				  in_data_size + out_data_size);
	if (!buffer)
		return;

	xrp_inline_buffer = apu_get_buffer(buffer);
	xrp_inline_buffer->in_data_size = in_data_size;
	xrp_inline_buffer->out_data_size = out_data_size;
	xrp_inline_buffer->n_buffers = count;
	memcpy(xrp_inline_buffer->data, in_data, in_data_size);
	memcpy(xrp_inline_buffer->nsid, queue->nsid, XRP_NAMESPACE_ID_SIZE);
	for (i = 0; i < count; i++) {
		uint32_t da;
		struct apu_buffer *tmp = buffer_group->buffer[i].buffer->buffer;

		da = apu_iommu_map_buffer(queue->device->device, tmp);
		xrp_inline_buffer->group[i].da = da;
		xrp_inline_buffer->group[i].size = tmp->size;

		if (buffer_group->buffer[i].buffer->host_ptr) {
			void *ptr;

			ptr = apu_get_buffer(tmp);
			memcpy(ptr, buffer_group->buffer[i].buffer->host_ptr, tmp->size);
			apu_put_buffer(tmp);
		}
	}
	apu_put_buffer(buffer);

	p_event = xrp_event_create();
	if (!p_event) {
		apu_free_buffer(buffer);
		return;
	}

	p_event->out_data = out_data;
	p_event->buffer_group = buffer_group;
	p_event->device = queue->device;
	p_event->queue = queue;
	if (buffer_group)
		xrp_retain_buffer_group(buffer_group);
	xrp_retain_queue(queue);

	if (event) {
		*event = p_event;
		xrp_retain_event(p_event);
	}

	buffers[0] = buffer;
	apu_exec_async(queue->device->device, 0, NULL, buffers, 1,
			sync_request_callback, p_event);

	*status = XRP_STATUS_SUCCESS;
}

void xrp_wait(struct xrp_event *event, enum xrp_status *status)
{
	pthread_mutex_lock(&event->lock);
	if (event->status == XRP_STATUS_PENDING)
		pthread_cond_wait(&event->cv, &event->lock);
	pthread_mutex_unlock(&event->lock);
	set_status(status, XRP_STATUS_SUCCESS);
}

size_t xrp_wait_any(struct xrp_event **event, size_t n_events,
		    enum xrp_status *status)
{
	size_t i, rv;
	struct xrp_event group;
	struct xrp_event_link *link;

	if (!n_events) {
		*status = XRP_STATUS_FAILURE;
		return 0;
	}

	link = calloc(n_events, sizeof(struct xrp_event_link));

	xrp_impl_event_init(&group);

	for (i = 0; i < n_events; ++i) {
		pthread_mutex_lock(&event[i]->lock);
		if (event[i]->status == XRP_STATUS_PENDING) {
			link[i].group = event[i]->group;
			link[i].next = event[i]->link;

			if (event[i]->link)
				event[i]->link->prev = link + i;

			event[i]->group = &group;
			event[i]->link = link + i;
		} else {
			pthread_mutex_unlock(&event[i]->lock);
			break;
		}
		pthread_mutex_unlock(&event[i]->lock);

	}

	rv = i;

	if (i == n_events)
		xrp_wait(&group, NULL);
	else
		n_events = i;

	for (i = 0; i < n_events; ++i) {
		pthread_mutex_lock(&event[i]->lock);
		if (event[i]->group == &group) {
			event[i]->group = link[i].group;
			event[i]->link = link[i].next;
		}
		if (link[i].next) {
			link[i].next->prev = link[i].prev;
		}
		if (link[i].prev) {
			if (link[i].prev->group == &group) {
				link[i].prev->group = link[i].group;
				link[i].prev->next = link[i].next;
			} else {
				printf("inconsistent link state\n");
			}
		}
		if (event[i]->status != XRP_STATUS_PENDING)
			rv = i;
		pthread_mutex_unlock(&event[i]->lock);
	}
	xrp_impl_release_event(&group);
	free(link);
	*status = XRP_STATUS_SUCCESS;
	return rv;
}
