/*
 * Copyright (C) 2020 BayLibre SAS
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __RICH_IOT_NN_HOST_H__
#define __RICH_IOT_NN_HOST_H__

#define INLINE_BUFFER_RW	1

struct apu_device {
	int apu_fd;
	int ion_fd;
};

/**
 * @brief Inline buffer
 * An inline buffer is a buffer that will use a preallocated rpmsg buffer
 * to share data with the APU. This is only expected for small data.
 * Indeed, the is limited by rpmsg to 512 bytes and this usage implies many
 * memory copy.
 */
struct apu_inline_buffer {
	void *data_in;
	size_t size_in;
	void *data_out;
	size_t size_out;
	int flags;
};

struct apu_buffer;

/**
 * @brief Get an APU device
 * @arg device_id the id of the device to open
 * @return an apu_device pointer or NULL in the case of error
 */
struct apu_device *apu_device_open(int device_id);

/**
 * @brief Close an APU device
 * @arg dev the apu_device object to release
 */
void apu_device_close(struct apu_device *dev);

/**
 * @brief Allocate an inline buffer
 * Allocate and initialize an inline buffer.
 * @arg data_in data to copy to inline buffer, or NULL if there is no data to
 *      copy
 * @arg size_in the size of data to copy
 * @arg size_out the of data to get back from APU. This used to reserve the
 *      memory
 * @arg flags Set to INLINE_BUFFER_RW if the input buffer could be updated by
 *      the APU
 * @return an inline buffer or NULL in the case of error.
 */
struct apu_inline_buffer *apu_inline_buffer(void *data_in, size_t size_in,
	     				    size_t size_out, int flags);

/**
 * @brief Free an inline buffer
 * @arg buffer the buffer to free
 */
void apu_inline_buffer_free(struct apu_inline_buffer *buffer);

/**
 * @brief Allocate a read only inline buffer
 * Allocate and fill a read only inline buffer (from APU point of view).
 * @arg data_in data to copy to inline buffer, or NULL if there is no data to
 *      copy
 * @arg size_in the size of data to copy
 * @return an inline buffer or NULL in the case of error.
 */
struct apu_inline_buffer *apu_inline_buffer_in(void *data_in, size_t size_in);

/**
 * @brief Allocate a read write inline buffer
 * Allocate and fill a read write inline buffer (from APU point of view).
 * @arg data_in data to copy to inline buffer, or NULL if there is no data to
 *      copy
 * @arg size_in the size of data to copy
 * @return an inline buffer or NULL in the case of error.
 */
struct apu_inline_buffer *apu_inline_buffer_rw(void *data_in, size_t size_in);

/**
 * @brief Allocate a write only inline buffer
 * Allocate and fill a write inline buffer (from APU point of view).
 * @arg size_out the of data to get back from APU. This used to reserve the
 *      memory
 * @return an inline buffer or NULL in the case of error.
 */
struct apu_inline_buffer *apu_inline_buffer_out(size_t size_out);

/**
 * @return the total size of inline buffer
 */
size_t apu_inline_buffer_size(struct apu_inline_buffer *inline_buffer);

/**
 * @brief Get data updated by the APU from inline buffer
 * @arg buffer the buffer to use to get the data
 * @arg len the size of data updated by the APU
 * @return the data update by the APU
 */
void *apu_inline_buffer_in_read(struct apu_inline_buffer *buffer, size_t *len);

/**
 * @brief Get data sent by the APU
 * @arg buffer the buffer to use to get the data
 * @arg len the size of data sent by the APU
 * @return the data sent by the APU
 */
void *apu_inline_buffer_out_read(struct apu_inline_buffer *buffer, size_t *len);

/*
 * @brief Send a command to execute on the device
 * @arg cmd The command id to execute on target
 * @arg inline_buffer a pointer to inline buffer or NULL if not used
 * @arg buffers an array of apu_buffer, could be NULL if not used
 * @arg count the number of apu_buffer to share with the APU
 * @return 0 or a negative number in the case of error
 */
int apu_exec(struct apu_device *dev, int cmd,
	     struct apu_inline_buffer *inline_buffer,
	     struct apu_buffer **buffers, int count);

/*
 * @brief Send a command to execute on the device
 * @arg cmd The command id to execute on target
 * @arg inline_buffer a pointer to inline buffer or NULL if not used
 * @arg count the number of apu_buffer to share with the APU
 * @arg ... pointers to all the apu_buffer to share with the APU
 * @return 0 or a negative number in the case of error
 */
int apu_vexec(struct apu_device *dev, int cmd,
	      struct apu_inline_buffer *inline_buffer, int count, ...);

#endif /* __RICH_IOT_NN_HOST_H__ */
