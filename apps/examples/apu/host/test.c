/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <rich-iot/apu-host.h>
#include <rich-iot/apu-test.h>
#include <rich-iot/memory.h>
#include <uapi/mtk_apu.h>

typedef int (*test_function)(struct apu_device *dev, void *args);

struct test {
	test_function fn;
	void *args;
	const char *name;
	const char *args_name;
};

#define TEST_FUNCTION(fn, args) \
	{ fn, args, #fn, #args }

#define INLINE_BUFFER_SIZE_MAX 256

int apu_buffer_memset(struct apu_buffer *buffer, int value, size_t size,
		      int offset)
{
	void *ptr;

	ptr = apu_get_buffer(buffer);
	if (!ptr) {
		printf("Failed to map memory\n");
		return -ENOMEM;
	}

	if (offset + size > buffer->size) {
		printf("Invalid size or offset\n");
		apu_put_buffer(buffer);
		return -EINVAL;
	}

	memset(buffer->ptr + offset, value, size);
	apu_put_buffer(buffer);

	return 0;
}

struct apu_buffer *apu_buffer_alloc_init(struct apu_device *dev,
					 size_t buffer_size, int value,
					 size_t size, int offset)
{
	struct apu_buffer *buffer;

	buffer = apu_alloc_buffer(dev, buffer_size);
	if (!buffer) {
		printf("Failed to allocate buffer\n");
		return NULL;
	}

	if (apu_buffer_memset(buffer, value, size, offset)) {
		apu_free_buffer(buffer);
		return NULL;
	}

	return buffer;
}

int apu_null(void *ptr, int len)
{
	uint8_t null_buffer[len];

	memset(null_buffer, 0, len);
	return !memcmp(null_buffer, ptr, len);
}

int apu_buffer_memcmp(struct apu_buffer *buffer1, struct apu_buffer *buffer2,
		      void *data)
{
	void *ptr1, *ptr2;
	int ret;

	ptr1 = apu_get_buffer(buffer1);
	if (!ptr1) {
		printf("Failed to map buffer 1\n");
		return -ENOMEM;
	}

	if (!buffer2 && !data) {
		int len = buffer1->size / 2;
		ret = memcmp(ptr1, ptr1 + len, len);
		ret |= apu_null(ptr1, len);
		goto put_buf1;
	}

	if (!buffer2 && data) {
		ret = memcmp(ptr1, data, buffer1->size);
		ret |= apu_null(ptr1, buffer1->size);
		ret |= apu_null(data, buffer1->size);
		goto put_buf1;
	}

	if (buffer1->size != buffer2->size) {
		ret = -EINVAL;
		goto put_buf1;
	}

	ptr2 = apu_get_buffer(buffer2);
	if (!ptr2) {
		printf("Failed to map buffer 2\n");
		ret = -ENOMEM;
		goto put_buf1;
	}

	ret = memcmp(ptr1, ptr2, buffer1->size);
	ret |= apu_null(ptr1, buffer1->size);
	ret |= apu_null(ptr2, buffer1->size);

	apu_put_buffer(buffer2);
put_buf1:
	apu_put_buffer(buffer1);

	return ret;
}

struct test_basic_args {
	int count;
	int size;
};


static int test_copy_shared_buffer(struct apu_device *dev, void *args)
{
	struct test_basic_args *p_args = args;
	struct apu_buffer *buffer1, *buffer2;
	int ret;
	int i;

	if (!p_args)
		return -EINVAL;

	for (i = 0; i < p_args->count; i++) {
		buffer1 = apu_buffer_alloc_init(dev, p_args->size, 0x12,
						p_args->size / 2, 0);
		if (!buffer1)
			return -ENOMEM;

		ret = apu_vexec(dev, TEST_COPY_SHARED_BUFFER, NULL, 1, buffer1);
		if (ret)
			goto err_free_buf1;

		ret = apu_buffer_memcmp(buffer1, NULL, NULL);
		if (ret)
			goto err_free_buf1;

		buffer2 = apu_buffer_alloc_init(dev, p_args->size, 0x14,
						p_args->size, 0);
		if (!buffer2) {
			ret = -ENOMEM;
			goto err_free_buf1;
		}

		ret = apu_vexec(dev, TEST_COPY_SHARED_BUFFER, NULL,
				2, buffer1, buffer2);
		if (ret)
			goto err_free_buf2;

		ret = apu_buffer_memcmp(buffer1, buffer2, NULL);
		if (ret)
			goto err_free_buf2;

		apu_free_buffer(buffer2);
		apu_free_buffer(buffer1);
	}

	return 0;

err_free_buf2:
	apu_free_buffer(buffer2);
err_free_buf1:
	apu_free_buffer(buffer1);

	return ret;
}

static int test_copy_inline_buffer(struct apu_device *dev, void *args)
{
	(void)args;
	int i;
	int ret;
	char data_in[INLINE_BUFFER_SIZE_MAX];
	char *data_out;
	struct apu_inline_buffer *inline_buffer;

	for (i = 1; i < INLINE_BUFFER_SIZE_MAX / 2; i <<= 1) {
		inline_buffer = apu_inline_buffer(data_in, i, i, 0);
		if (!inline_buffer)
			return -ENOMEM;

		memset(data_in, i, i);
		ret = apu_vexec(dev, TEST_COPY_INLINE_BUFFER, inline_buffer, 0);
		if (ret) {
			apu_inline_buffer_free(inline_buffer);
			return ret;
		}

		data_out = apu_inline_buffer_out_read(inline_buffer, NULL);
		if (memcmp(data_in, data_out, i)) {
			apu_inline_buffer_free(inline_buffer);
			return -EINVAL;
		}
		apu_inline_buffer_free(inline_buffer);
	}

	return 0;
}

static int test_copy_inline_to_shared_buffer(struct apu_device *dev, void *args)
{
	(void)args;
	struct apu_inline_buffer *inline_buffer;
	char data[INLINE_BUFFER_SIZE_MAX];
	struct apu_buffer *buffer;
	int ret;

	inline_buffer = apu_inline_buffer_in(data, INLINE_BUFFER_SIZE_MAX);
	if (!inline_buffer)
		return -ENOMEM;

	buffer = apu_buffer_alloc_init(dev, INLINE_BUFFER_SIZE_MAX, 0x12,
				       INLINE_BUFFER_SIZE_MAX, 0);
	if (!buffer) {
		ret = -ENOMEM;
		goto err_free_inline_buf;
	}

	memset(data, 0x65, INLINE_BUFFER_SIZE_MAX);
	ret = apu_vexec(dev, TEST_COPY_INLINE2SHARED, inline_buffer, 1, buffer);
	if (ret)
		goto err_free_buf;

	ret = apu_buffer_memcmp(buffer, NULL, data);

err_free_buf:
	apu_free_buffer(buffer);
err_free_inline_buf:
	apu_inline_buffer_free(inline_buffer);

	return ret;
}

static int test_copy_shared_to_inline_buffer(struct apu_device *dev, void *args)
{
	(void)args;
	struct apu_inline_buffer *inline_buffer;
	struct apu_buffer *buffer;
	void *data;
	int ret;

	inline_buffer = apu_inline_buffer_out(INLINE_BUFFER_SIZE_MAX);
	if (!inline_buffer)
		return -ENOMEM;

	buffer = apu_buffer_alloc_init(dev, INLINE_BUFFER_SIZE_MAX, 0x12,
				       INLINE_BUFFER_SIZE_MAX, 0);
	if (!buffer) {
		ret = -ENOMEM;
		goto err_free_inline_buf;
	}

	ret = apu_vexec(dev, TEST_COPY_SHARED2INLINE, inline_buffer, 1, buffer);
	if (ret)
		goto err_free_buf;

	data = apu_inline_buffer_out_read(inline_buffer, NULL);
	ret = apu_buffer_memcmp(buffer, NULL, data);

err_free_buf:
	apu_free_buffer(buffer);
err_free_inline_buf:
	apu_inline_buffer_free(inline_buffer);

	return ret;
}

static int test_fill_buffer(struct apu_device *dev, void *args)
{
	(void)args;
	struct apu_inline_buffer *inline_buffer;
	char data_in[INLINE_BUFFER_SIZE_MAX];
	char size_in = sizeof(uint8_t) + sizeof(uint16_t);
	char *data_out;
	char expected_data[INLINE_BUFFER_SIZE_MAX] = { 0x56 };
	struct apu_buffer *buffer;
	size_t len;
	int ret;

	inline_buffer = apu_inline_buffer(data_in, size_in,
					  INLINE_BUFFER_SIZE_MAX, 0);
	if (!inline_buffer)
		return -ENOMEM;

	buffer = apu_buffer_alloc_init(dev, INLINE_BUFFER_SIZE_MAX, 0x12,
				       INLINE_BUFFER_SIZE_MAX, 0);
	if (!buffer) {
		ret = -ENOMEM;
		goto err_free_inline_buf;
	}

	data_in[0] = 0x56;
	*((uint16_t *)&data_in[1]) = 120;
	ret = apu_vexec(dev, TEST_FILL_BUFFER, inline_buffer, 0);
	if (ret)
		goto err_free_buf;

	data_out = apu_inline_buffer_out_read(inline_buffer, &len);
	if (len != 120) {
		ret = -EINVAL;
		goto err_free_buf;
	}

	ret = memcmp(data_out, expected_data, len);
	if (ret)
		goto err_free_buf;

err_free_buf:
	apu_free_buffer(buffer);
err_free_inline_buf:
	apu_inline_buffer_free(inline_buffer);

	return 0;
}

static int test_buffer_iommu_mmap(struct apu_device *dev, void *args)
{
	(void)args;
	struct apu_inline_buffer *inline_buffer;
	struct test_buffer_iommu_mmap test_buffer;
	struct apu_buffer *buffer1, *buffer2;
	uint32_t buffer1_da, buffer2_da;
	int ret;

	buffer1 = apu_buffer_alloc_init(dev, INLINE_BUFFER_SIZE_MAX, 0x12,
					INLINE_BUFFER_SIZE_MAX, 0);
	if (!buffer1)
		return -ENOMEM;

	buffer1_da = apu_iommu_map_buffer(dev, buffer1);
	if (!buffer1_da) {
		ret = -ENOMEM;
		goto err_free_buffer1;
	}

	buffer2 = apu_buffer_alloc_init(dev, INLINE_BUFFER_SIZE_MAX, 0x15,
					INLINE_BUFFER_SIZE_MAX, 0);
	if (!buffer2) {
		ret = -ENOMEM;
		goto err_unmap_buffer1;
	}

	buffer2_da = apu_iommu_map_buffer(dev, buffer2);
	if (!buffer2_da) {
		ret = -ENOMEM;
		goto err_free_buffer2;
	}

	test_buffer.buffer_in_da = buffer1_da;
	test_buffer.buffer_out_da = buffer2_da;
	test_buffer.size = INLINE_BUFFER_SIZE_MAX;
	inline_buffer = apu_inline_buffer_in(&test_buffer, sizeof(test_buffer));
	if (!inline_buffer) {
		ret = -ENOMEM;
		goto err_unmap_buffer2;
	}

	ret = apu_vexec(dev, TEST_BUFFER_IOMMU_MMAP, inline_buffer, 0);
	if (ret)
		goto err_free_inline_buf;

	ret = apu_buffer_memcmp(buffer1, buffer2, NULL);

err_free_inline_buf:
	apu_inline_buffer_free(inline_buffer);
err_unmap_buffer2:
	apu_iommu_unmap_buffer(dev, buffer2);
err_free_buffer2:
	apu_free_buffer(buffer2);
err_unmap_buffer1:
	apu_iommu_unmap_buffer(dev, buffer1);
err_free_buffer1:
	apu_free_buffer(buffer1);

	return ret;
}

struct test_basic_args test_basic_1_256 = {1, 256};
struct test_basic_args test_basic_1_4096 = {1, 4096};
struct test_basic_args test_basic_1_65535 = {1, 65535};

struct test_basic_args test_basic_4096_256 = {4096, 256};
struct test_basic_args test_basic_4096_4096 = {4096, 4096};
struct test_basic_args test_basic_4096_65535 = {4096, 65535};

struct test tests[] = {
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_1_256),
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_1_4096),
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_1_65535),
	TEST_FUNCTION(test_copy_inline_buffer, &test_basic_1_256),
	TEST_FUNCTION(test_copy_inline_to_shared_buffer, NULL),
	TEST_FUNCTION(test_copy_shared_to_inline_buffer, NULL),
	TEST_FUNCTION(test_fill_buffer, NULL),
	TEST_FUNCTION(test_buffer_iommu_mmap, NULL),
};

struct test long_run_tests[] = {
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_4096_256),
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_4096_4096),
	TEST_FUNCTION(test_copy_shared_buffer, &test_basic_4096_65535),
};

int run_tests(struct apu_device *dev, struct test *tests, int count)
{
	int i;
	int ret;
	int test_failed = 0;


	for (i = 0; i < count; i++) {
		ret = tests[i].fn(dev, tests[i].args);
		if (ret)
			test_failed++;
		printf("%s - %s, %s\n", tests[i].name, tests[i].args_name,
		       ret ? "failed" : "passed");
	}

	return test_failed;
}

void callback(
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers, int count,
		int result, void *data)
{
	(void) inline_buffer;
	(void) count;
	int ret;

	if (result)
		goto free_request;

	ret = apu_buffer_memcmp(*buffers, NULL, NULL);
	if (ret)
		printf("error\n");
	else
		printf("passed!\n");
free_request:
	apu_free_buffer(buffers[0]);
	apu_device_quit((struct apu_device *)(data));
}

int async_test(struct apu_device *dev)
{
	struct apu_buffer *buffer1;
	int ret;

	buffer1 = apu_buffer_alloc_init(dev, 256, 0x12, 128, 0);
	if (!buffer1)
		return -ENOMEM;
	ret = apu_exec_async(dev, TEST_COPY_SHARED_BUFFER, NULL, &buffer1, 1, callback, dev);
	return ret;
}

/* Main - Call the ioctl functions */
int main(int argc, char *argv[])
{
	struct apu_device *dev;
	int total_test_count = 0;
	int test_count;
	int test_failed = 0;
	int opt;

	dev = apu_device_open(0);
	if (!dev)
		return -ENODEV;

	test_count = sizeof(tests) / sizeof(struct test);
	total_test_count += test_count;
	test_failed += run_tests(dev, tests, test_count);

	while ((opt = getopt(argc, argv, "l")) != -1) {
		switch (opt) {
		case 'l':
			test_count = sizeof(long_run_tests) / sizeof(struct test);
			total_test_count += test_count;
			test_failed += run_tests(dev, long_run_tests, test_count);
			break;
		default:
			printf("Unknown option: -%c\n", opt);
			return -EINVAL;
		}
	}

	printf ("%d / %d passed\n", total_test_count - test_failed,
		total_test_count);

	async_test(dev);
	apu_device_loop(dev);
	apu_device_close(dev);

	return 0;
}
