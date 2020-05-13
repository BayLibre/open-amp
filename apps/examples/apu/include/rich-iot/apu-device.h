/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __RICH_IOT_apu_DEVICE_H__
#define __RICH_IOT_apu_DEVICE_H__

#include <openamp/rpmsg.h>
#include <rich-iot/apu.h>

#define APU_VERSION_MAJOR 0
#define APU_VERSION_MINOR 1

struct apu_device;

typedef int (*apu_blob_handler)(struct apu_device *device,
				void *data, size_t size);

struct apu_handler {
	uint16_t (*handler)(struct apu_device *device,
			    void *data_in, uint16_t *size_in,
			    void *data_out, uint16_t *size_out,
			    void **buffer, uint32_t *buffer_size,
			    uint16_t *count);
	const char *name;
	uint16_t cmd;
	uint16_t type;
};

#define HANDLER_TYPE_NONE 0
#define HANDLER_TYPE_CTRL 1
#define HANDLER_TYPE_EXEC 2
#define HANDLER_TYPE_BLOB 3
#define HANDLER_TYPE_GENERIC 4

#define APU_HANDLER(id, fn)				\
	{						\
		.handler = fn,				\
		.name = #fn,				\
		.cmd = id,				\
		.type = HANDLER_TYPE_GENERIC,		\
	}

struct apu_device {
	void *platform;
	struct rpmsg_device *rpdev;
	struct rpmsg_endpoint ept;
	struct apu_handler *apu_handler;
};

int apu_init(struct apu_device *device,
	     struct apu_handler *apu_handler);
void apu_release(struct apu_device *device);

#endif /* __RICH_IOT_apu_DEVICE_H__ */
