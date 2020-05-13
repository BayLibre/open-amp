/*
 * Copyright (C) 2010 ARM Limited. All rights reserved.
 *
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "ion.h"

static int ion_query_heap_cnt(int fd, int* cnt)
{
	int ret;
	struct ion_heap_query query;

	memset(&query, 0, sizeof(query));
	ret = ioctl(fd, ION_IOC_HEAP_QUERY, &query);
	if (ret < 0)
		return ret;
	*cnt = query.cnt;

	return ret;
}

static int ion_query_get_heaps(int fd, int cnt, void* buffers)
{
	struct ion_heap_query query = {
		.cnt = cnt,
		.heaps = (uintptr_t)buffers,
	};

	return ioctl(fd, ION_IOC_HEAP_QUERY, &query);
}

int find_ion_heap_id(int ion_client, enum ion_heap_type type)
{
	int i, ret, cnt, heap_id = -1;
	struct ion_heap_data *data;

	ret = ion_query_heap_cnt(ion_client, &cnt);
	if (ret)
		return -1;

	data = (struct ion_heap_data *)malloc(cnt * sizeof(*data));
	if (!data)
		return -1;

	ret = ion_query_get_heaps(ion_client, cnt, data);
	if (ret) {
		free(data);
		return -1;
	}

	for (i = 0; i < cnt; i++) {
		struct ion_heap_data *dat = (struct ion_heap_data *)data;
		if (dat[i].type == type) {
			heap_id = dat[i].heap_id;
			break;
		}
	}

	if (i > cnt)
		heap_id = -1;

	free(data);
	return heap_id;
}
