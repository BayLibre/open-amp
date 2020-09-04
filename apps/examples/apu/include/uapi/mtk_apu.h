/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (c) 2020 BayLibre
 */

#ifndef _UAPI_RPMSG_APU_H_
#define _UAPI_RPMSG_APU_H_

#include <linux/ioctl.h>
#include <linux/types.h>

struct apu_request {
	__u16 id;
	__u16 cmd;
	__u16 result;
	__u16 size_in;
	__u16 size_out;
	__u16 count;
	__u16 reserved;
	__u8 data[0];
};

struct apu_version {
	__u16 major;
	__u16 minor;
};

struct apu_iommu_mmap {
	uint32_t fd;
	uint32_t da;
};

#define APU_VERSION_IOCTL	_IOWR(0xb7, 0x1, struct apu_version)
#define APU_SEND_REQ_IOCTL	_IOW(0xb7, 0x2, struct apu_request)
#define APU_GET_NEXT_AVAILABLE_IOCTL	_IOR(0xb7, 0x3, __u16)
#define APU_GET_RESP_IOCTL	_IOWR(0xb7, 0x4, struct apu_request)
#define APU_IOMMU_MMAP		_IOWR(0xb7, 0x5, struct apu_iommu_mmap)
#define APU_IOMMU_MUNMAP	_IOWR(0xb7, 0x6, uint32_t)

#endif
