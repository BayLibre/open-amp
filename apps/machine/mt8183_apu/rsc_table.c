/*
 * Copyright (c) 2020 BayLibre SAS
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "rsc_table.h"

#define RPMSG_IPU_C0_FEATURES        1

/* VirtIO rpmsg device id */
#define VIRTIO_ID_RPMSG_             7

/* Remote supports Name Service announcement */
#define VIRTIO_RPMSG_F_NS           0

/* Resource table entries */
#define NUM_VRINGS                  0x02
#define VRING_ALIGN                 0x1000
#define VRING_SIZE                  256

struct remote_resource_table s_table __attribute__((section (".resource_table"))) = {
	.version = 1,
	.num = NO_RESOURCE_ENTRIES,
	.reserved = {0, 0},
	.offset = {
		offsetof(struct remote_resource_table, srom_hdr),
		offsetof(struct remote_resource_table, sram_hdr),
		offsetof(struct remote_resource_table, stack_hdr),
		offsetof(struct remote_resource_table, heap_hdr),
		offsetof(struct remote_resource_table, logbuf_hdr),
		offsetof(struct remote_resource_table, vdev0buffer_hdr),
		offsetof(struct remote_resource_table, vdev0ring0_hdr),
		offsetof(struct remote_resource_table, vdev0ring1_hdr),
		offsetof(struct remote_resource_table, trace_hdr),
		offsetof(struct remote_resource_table, rpmsg_vdev),
	},
	.srom_hdr = {
		.type = RSC_CARVEOUT,
		.da = SROM_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = SROM_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE,
		.name = "System ROM",
		.reserved = 0,
	},
	.sram_hdr = {
		.type = RSC_CARVEOUT,
		.da = SRAM_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = SRAM_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "System RAM",
		.reserved = 0,
	},
	.stack_hdr = {
		.type = RSC_CARVEOUT,
		.da = SRAM_STACK_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = SRAM_STACK_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "Stack",
		.reserved = 0,
	},
	.heap_hdr = {
		.type = RSC_CARVEOUT,
		.da = SRAM_HEAP_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = SRAM_HEAP_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "Heap",
		.reserved = 0,
	},
	.logbuf_hdr = {
		.type = RSC_CARVEOUT,
		.da = LOG_BUFFER_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = LOG_BUFFER_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "Log buffer",
		.reserved = 0,
	},
	.vdev0buffer_hdr = {
		.type = RSC_CARVEOUT,
		.da = VDEV_BUFFER_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = VDEV_BUFFER_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "vdev0buffer",
		.reserved = 0,
	},
	.vdev0ring0_hdr = {
		.type = RSC_CARVEOUT,
		.da = VDEV_RING0_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = VRING_BUFFER_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "vdev0vring0",
		.reserved = 0,
	},
	.vdev0ring1_hdr = {
		.type = RSC_CARVEOUT,
		.da = VDEV_RING1_DA,
		.pa = FW_RSC_ADDR_ANY,
		.len = VRING_BUFFER_SIZE,
		.flags = IOMMU_READ|IOMMU_WRITE|IOMMU_NOEXEC,
		.name = "vdev0vring1",
		.reserved = 0,
	},
	.trace_hdr = {
		.type = RSC_TRACE,
		.da = LOG_BUFFER_DA, /* Log Buffer address */
		.len = LOG_BUFFER_SIZE,
		.name = "Trace",
		.reserved = 0,
	},
	.rpmsg_vdev = {
		RSC_VDEV, VIRTIO_ID_RPMSG_, 0, RPMSG_IPU_C0_FEATURES, 0, 0, 0,
		NUM_VRINGS, {0, 0},
	},

	/* Vring rsc entry - part of vdev rsc entry */
	.rpmsg_vring0 = {FW_RSC_ADDR_ANY, VRING_ALIGN, VRING_SIZE, 1, 0},
	.rpmsg_vring1 = {FW_RSC_ADDR_ANY, VRING_ALIGN, VRING_SIZE, 2, 0},
};

void *get_resource_table (int rsc_id, int *len)
{
	(void) rsc_id;
	*len = sizeof(s_table);
	return &s_table;
}
