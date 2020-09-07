/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __RICH_IOT_NN_TEST_H__
#define __RICH_IOT_NN_TEST_H__

#include <stdint.h>

#define TEST_COPY_SHARED_BUFFER		1
#define TEST_COPY_INLINE_BUFFER		2
#define TEST_COPY_INLINE2SHARED		3
#define TEST_COPY_SHARED2INLINE		4
#define TEST_FILL_BUFFER		5
#define TEST_BUFFER_IOMMU_MMAP		6

struct test_buffer_iommu_mmap {
	uint32_t buffer_in_da;
	uint32_t buffer_out_da;
	uint32_t size;
};

#endif /* __RICH_IOT_NN_TEST_H__ */
