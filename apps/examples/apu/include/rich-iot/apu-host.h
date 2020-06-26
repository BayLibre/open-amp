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
	int stop;
	pthread_t main_loop_thread;
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
 * @brief Callback to register that will be called when asynchronous request are done
 * @arg inline_buffer pointer to the inline_buffer that was used for the request
 * @arg buffers pointer to the array of apu_buffer used for the request
 * @arg count number of apu_buffer in buffers
 * @arg data user data
 */
typedef void (*apu_callback) (
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers, int count,
		int result, void *data);

/*
 * @brief Send a sync command to execute on the device
 * @arg dev The apu device
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
 * @brief Send a async command to execute on the device
 * @arg dev The apu device
 * @arg cmd The command id to execute on target
 * @arg inline_buffer User data to be sent to the device without using apu_buffer
 * @arg buffers Array of apu_buffer
 * @arg count The number of apu_buffer inside buffers
 * @arg callback The function to call when request is executed
 * @arg data Used data
 * @return 0 or a negative number in the case of error
 */
int apu_exec_async(struct apu_device *dev, int cmd,
		struct apu_inline_buffer *inline_buffer,
		struct apu_buffer **buffers, int count,
		apu_callback callback, void *data);

/*
 * @brief Send a sync command to execute on the device
 * @arg dev The apu device
 * @arg cmd The command id to execute on target
 * @arg inline_buffer a pointer to inline buffer or NULL if not used
 * @arg count the number of apu_buffer to share with the APU
 * @arg ... pointers to all the apu_buffer to share with the APU
 * @return 0 or a negative number in the case of error
 */
int apu_vexec(struct apu_device *dev, int cmd,
	      struct apu_inline_buffer *inline_buffer, int count, ...);

/*
 * @brief Start the main apu_device_loop
 * It will block and wait for response from device.
 * When response is received from device, the corresponding apu_callback is called
 * @arg dev the apu_device
 * @see apu_device_quit to stop the main loop
 * @see apu_callback
 */
void apu_device_loop(struct apu_device *dev);

/*
 * @brief Quit the main apu_device_loop started with apu_device_loop
 * It wills stop the main loop device, and app will not be notified for future response.
 * @arg dev the apu_device
 * @see apu_device_loop
 */
void apu_device_quit(struct apu_device *dev);

#endif /* __RICH_IOT_NN_HOST_H__ */
