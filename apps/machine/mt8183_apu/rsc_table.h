/*
 * Copyright (c) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef RSC_TABLE_H_
#define RSC_TABLE_H_

#include <stddef.h>
#include <memory.h>
#include <openamp/open_amp.h>

#if defined __cplusplus
extern "C" {
#endif

#define IOMMU_READ		(1 << 0)
#define IOMMU_WRITE		(1 << 1)
#define IOMMU_CACHE		(1 << 2)
#define IOMMU_NOEXEC		(1 << 3)
#define IOMMU_MMIO		(1 << 4)

#define NO_RESOURCE_ENTRIES         11

#define SRAM_TOTAL_SIZE		(256 * MB)

#define SROM_DA			((uint32_t)&_memmap_mem_srom_start)
#define SRAM_DA			((uint32_t)&_memmap_mem_sram_start)
#define LOG_BUFFER_DA		((uint32_t)&_log_start)
#define VDEV_BUFFER_DA		((uint32_t)&_vdev_start)
#define VDEV_RING0_DA		((uint32_t)&_vring0_start)
#define VDEV_RING1_DA		((uint32_t)&_vring1_start)
#define SRAM_STACK_DA		((uint32_t)&_stack_sentry)
#define SRAM_HEAP_DA		((uint32_t)&_heap_sentry - SRAM_HEAP_SIZE)

#define FW_RSC_ADDR_ANY		(-1)

extern uint32_t _memmap_mem_srom_start;
extern uint32_t _memmap_mem_sram_start;
extern uint32_t _memmap_mem_sram_end;
extern uint32_t _resource_table_start;
extern uint32_t _resource_table_end;
extern uint32_t _log_start;
extern uint32_t _vdev_start;
extern uint32_t _vring0_start;
extern uint32_t _vring1_start;

extern uint32_t _stack_sentry;
extern uint32_t _heap_sentry;

METAL_PACKED_BEGIN
struct fw_rsc_iova {
	uint32_t type;
	uint32_t da;
	uint32_t len;
	uint32_t reserved;
	uint8_t name[RPROC_MAX_NAME_LEN];
} METAL_PACKED_END;

/* Resource table for the given remote */
struct remote_resource_table {
	unsigned int version;
	unsigned int num;
	unsigned int reserved[2];
	unsigned int offset[NO_RESOURCE_ENTRIES];

	struct fw_rsc_iova iova_hdr;
	struct fw_rsc_carveout srom_hdr;
	struct fw_rsc_carveout sram_hdr;
	struct fw_rsc_carveout stack_hdr;
	struct fw_rsc_carveout heap_hdr;
	struct fw_rsc_carveout logbuf_hdr;
	struct fw_rsc_carveout vdev0buffer_hdr;
	struct fw_rsc_carveout vdev0ring0_hdr;
	struct fw_rsc_carveout vdev0ring1_hdr;
	struct fw_rsc_trace trace_hdr;

	/* rpmsg vdev entry */
	struct fw_rsc_vdev rpmsg_vdev;
	struct fw_rsc_vdev_vring rpmsg_vring0;
	struct fw_rsc_vdev_vring rpmsg_vring1;
}__attribute__((packed, aligned(0x1000)));

void *get_resource_table (int rsc_id, int *len);

#if defined __cplusplus
}
#endif

#endif /* RSC_TABLE_H_ */
