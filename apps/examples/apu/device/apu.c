/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <openamp/open_amp.h>
#include <metal/alloc.h>
#include "platform_info.h"

#include <rich-iot/apu-device.h>

static struct apu_request *alloc_apu_reply(struct apu_request *req,
					   uint16_t result,
					   uint16_t size_in, uint16_t size_out,
					   uint16_t count,
					   size_t *len)
{
	struct apu_request *resp;
	void *req_data_in, *req_data_out, *req_buffer_size;
	void *resp_data_in, *resp_data_out, *resp_buffer_size;

	*len = sizeof(*resp) + size_in + size_out + sizeof(uint32_t) * count;
	resp = metal_allocate_memory(*len);
	if (!resp)
		return NULL;

	resp->id = req->id;
	resp->cmd = req->cmd;
	resp->result = result;
	resp->size_in = size_in;
	resp->size_out = size_out;

	req_data_in = req->data;
	req_data_out = req_data_in + size_in;
	req_buffer_size = req_data_out + size_out + count * sizeof(uint32_t);

	resp_data_in = resp->data;
	resp_data_out = resp_data_in + size_in;
	resp_buffer_size = resp_data_out + size_out;

	memcpy(resp_data_in, req_data_in, size_in);
	memcpy(resp_data_out, req_data_out, size_out);
	memcpy(resp_buffer_size, req_buffer_size, count * sizeof(uint32_t));

	return resp;
}

static void apu_handler(struct rpmsg_endpoint *ept, void *data, size_t len,
			struct apu_device *device, struct apu_handler *handler)
{
	struct apu_request *req = data;
	struct apu_request *resp;
	uint16_t size_in = req->size_in;
	uint16_t size_out = req->size_out;
	void *data_in = req->data;
	void *data_out = data_in + size_in;
	uint32_t *buffer = data_out + size_out;
	uint32_t *buffer_size = (uint32_t *)(buffer + req->count);
	uint16_t ret;
	int i;

	metal_log(METAL_LOG_DEBUG, "Executing %s\n", handler->name);

	for (i = 0; i < req->count; i++)
		xthal_dcache_region_invalidate((void *)buffer[i],
					       buffer_size[i]);

	if (!size_in)
		data_in = NULL;
	if (!size_out)
		data_out = NULL;
	if (!req->count) {
		buffer = NULL;
		buffer_size = NULL;
	}

	ret = handler->handler(device, data_in, &size_in, data_out, &size_out,
			       (void **)buffer, (size_t *)buffer_size,
			       &req->count);

	for (i = 0; i < req->count; i++)
		xthal_dcache_region_writeback((void *)buffer[i],
					      buffer_size[i]);

	metal_log(METAL_LOG_DEBUG, "%s returned %d\n",
		  handler->name, ret);

	resp = alloc_apu_reply(req, ret, size_in, size_out, req->count, &len);
	if (!resp) {
		/*
		 * Failed to allocate a reply buffer, use the request one
		 * to notify the host about it
		 */
		req->result = ENOMEM;
		resp = req;
		len = sizeof(*req);
	}

	/* Send data back to master */
	if (rpmsg_send(ept, resp, len) < 0) {
		metal_log(METAL_LOG_ERROR, "rpmsg_send failed\n");
	}

	if (resp != req)
		metal_free_memory(resp);
}

static int apu_event_dispatcher(struct rpmsg_endpoint *ept,
				void *data, size_t len,
				uint32_t src, void *priv)
{
	(void)src;

	int i;
	struct apu_device *device = priv;
	struct apu_handler *handlers = device->apu_handler;
	struct apu_request *req = data;

	metal_log(METAL_LOG_DEBUG,
		  "Looking for a handler for cmd %u coming from %u\n",
		  req->cmd, src);

	for (i = 0; handlers[i].handler; i++) {
		if (handlers[i].cmd == req->cmd) {
			apu_handler(ept, data, len, device, &handlers[i]);

			return RPMSG_SUCCESS;
		}
	}

	/* Notify host that the request have not been handled */
	req->result = ENOTSUP;
	if (rpmsg_send(ept, req, sizeof(*req)) < 0) {
		metal_log(METAL_LOG_ERROR, "rpmsg_send failed\n");
	}

	return RPMSG_SUCCESS;
}

static void apu_ept_unbind(struct rpmsg_endpoint *ept)
{
	(void)ept;
	metal_log(METAL_LOG_INFO, "unexpected Remote endpoint destroy\n");
}

int apu_init(struct apu_device *device,
	     struct apu_handler *apu_handlers)
{
	int ret;

	/* Initialize platform */
	ret = platform_init(0, NULL, &device->platform);
	if (ret) {
		metal_log(METAL_LOG_ERROR, "Failed to initialize platform.\n");
		return ret;
	}

	device->rpdev = platform_create_rpmsg_vdev(device->platform, 0,
						   VIRTIO_DEV_SLAVE,
						   NULL, NULL);
	if (!device->rpdev) {
		metal_log(METAL_LOG_ERROR, "Failed to create rpmsg virtio device.\n");
		ret = -ENODEV;
		goto err_platform_cleanup;

	}

	ret = rpmsg_create_ept(&device->ept, device->rpdev,
			       APU_RPMSG_SERVICE, APU_CTRL_SRC,
			       RPMSG_ADDR_ANY, apu_event_dispatcher,
			       apu_ept_unbind);
	if (ret) {
		metal_log(METAL_LOG_ERROR, "Failed to create endpoint.\n");
		goto err_release_rpmsg;
	}

	device->apu_handler = apu_handlers;
	device->ept.priv = device;

	return 0;

err_release_rpmsg:
	platform_release_rpmsg_vdev(device->rpdev);
err_platform_cleanup:
	platform_cleanup(device->platform);

	return ret;
}

void apu_release(struct apu_device *device)
{
	rpmsg_destroy_ept(&device->ept);
	platform_release_rpmsg_vdev(device->rpdev);
	platform_cleanup(device->platform);
}
