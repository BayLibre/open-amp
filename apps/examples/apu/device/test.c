/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <openamp/open_amp.h>
#include <metal/alloc.h>
#include <metal/cache.h>
#include "platform_info.h"

#include <rich-iot/apu-device.h>
#include <rich-iot/apu-test.h>

static struct apu_device apu_device;

static uint16_t _test_log_error(uint16_t err, const char *func, int line)
{
	metal_log(METAL_LOG_ERROR, "%s failed at line %d\n", func, line);
	return err;
}
#define test_log_error(err) _test_log_error(err, __func__, __LINE__)

static uint16_t test_copy_shared_buffer(struct apu_device *device,
					void *data_in, uint16_t *size_in,
					void *data_out, uint16_t *size_out,
					void **buffer, uint32_t *buffer_size,
					uint16_t *count)
{
	(void)device;
	int len;

	if (data_in || *size_in || data_out || *size_out)
		return test_log_error(EINVAL);

	if (!count || *count > 2)
		return test_log_error(EINVAL);

	if (*count == 2 && buffer_size[0] > buffer_size[1])
		return test_log_error(EINVAL);

	len = buffer_size[0];
	if (*count == 1) {
		len >>= 1;
		memcpy(buffer[0] + len, buffer[0], len);
	} else {
		memcpy(buffer[1], buffer[0], len);
	}

	return 0;
}

static uint16_t test_copy_inline_buffer(struct apu_device *device,
					void *data_in, uint16_t *size_in,
					void *data_out, uint16_t *size_out,
					void **buffer, uint32_t *buffer_size,
					uint16_t *count)
{
	(void)device;

	if (*count || buffer || buffer_size)
		return test_log_error(EINVAL);

	if (*size_in > *size_out)
		return test_log_error(EINVAL);

	memcpy(data_out, data_in, *size_in);
	*size_out = *size_in;

	return 0;
}

static uint16_t test_copy_inline_to_shared_buffer(struct apu_device *device,
						  void *data_in,
						  uint16_t *size_in,
						  void *data_out,
						  uint16_t *size_out,
						  void **buffer,
						  uint32_t *buffer_size,
						  uint16_t *count)
{
	(void)device;

	if (!data_in || *size_in == 0 || data_out || *size_out)
		return test_log_error(EINVAL);

	if (*count == 0 || !buffer || !buffer_size)
		return test_log_error(EINVAL);

	if (*size_in > buffer_size[0])
		return test_log_error(EINVAL);

	memcpy(buffer[0], data_in, *size_in);
	buffer_size[0] = *size_in;

	return 0;
}

static uint16_t test_copy_shared_to_inline_buffer(struct apu_device *device,
						  void *data_in,
						  uint16_t *size_in,
						  void *data_out,
						  uint16_t *size_out,
						  void **buffer,
						  uint32_t *buffer_size,
						  uint16_t *count)
{
	(void)device;

	if (!data_out || *size_out == 0 || data_in || *size_in)
		return test_log_error(EINVAL);

	if (*count == 0 || !buffer || !buffer_size)
		return test_log_error(EINVAL);

	if (buffer_size[0] > *size_out)
		return test_log_error(EINVAL);

	memcpy(data_out, buffer[0], buffer_size[0]);
	*size_out = buffer_size[0];

	return 0;
}

static uint16_t test_fill_buffer(struct apu_device *device,
				 void *data_in, uint16_t *size_in,
				 void *data_out, uint16_t *size_out,
				 void **buffer, uint32_t *buffer_size,
				 uint16_t *count)
{
	(void)device;
	uint8_t value;
	uint16_t size;

	if (!data_in || *size_in == 0 || *count > 1)
		return test_log_error(EINVAL);

	if (*size_in != (sizeof(uint8_t) + sizeof(uint16_t)))
		return test_log_error(EINVAL);

	if (*count == 0 && *size_out == 0)
		return test_log_error(EINVAL);

	value = *((uint8_t *)data_in);
	size = *((uint8_t *)data_in + 1);

	if (*count == 0) {
		memset(data_out, value, size);
		*size_out = size;
	} else {
		memset(buffer[0], value, size);
		buffer_size[0] = size;
	}

	return 0;
}

static uint16_t test_buffer_iommu_mmap(struct apu_device *device,
				       void *data_in, uint16_t *size_in,
				       void *data_out, uint16_t *size_out,
				       void **buffer, uint32_t *buffer_size,
				       uint16_t *count)
{
	(void)device;
	(void)data_out;
	(void)size_out;
	(void)buffer;
	(void)buffer_size;
	(void)count;
	struct test_buffer_iommu_mmap *data;
	uint8_t *buffer_in;
	uint8_t *buffer_out;
	uint32_t size;

	if (!data_in || *size_in == 0)
		return test_log_error(EINVAL);

	if (*size_in != (sizeof(*data)))
		return test_log_error(EINVAL);

	data = data_in;
	buffer_in = (uint8_t *)data->buffer_in_da;
	buffer_out = (uint8_t *)data->buffer_out_da;
	size = data->size;

	metal_machine_cache_invalidate(buffer_in, size);
	memcpy(buffer_out, buffer_in, size);
	metal_machine_cache_flush(buffer_out, size);

	return 0;
}

static struct apu_handler handlers[] = {
	APU_HANDLER(TEST_COPY_SHARED_BUFFER, test_copy_shared_buffer),
	APU_HANDLER(TEST_COPY_INLINE_BUFFER, test_copy_inline_buffer),
	APU_HANDLER(TEST_COPY_INLINE2SHARED, test_copy_inline_to_shared_buffer),
	APU_HANDLER(TEST_COPY_SHARED2INLINE, test_copy_shared_to_inline_buffer),
	APU_HANDLER(TEST_FILL_BUFFER, test_fill_buffer),
	APU_HANDLER(TEST_BUFFER_IOMMU_MMAP, test_buffer_iommu_mmap),
	APU_HANDLER(0, NULL),
};

int main(int argc, char *argv[])
{
	int ret;

	metal_unused(argc);
	metal_unused(argv);

	ret = apu_init(&apu_device, handlers);
	if (ret)
		return ret;

	while(1)
		platform_poll(apu_device.platform);

	apu_release(&apu_device);

	return 0;
}
