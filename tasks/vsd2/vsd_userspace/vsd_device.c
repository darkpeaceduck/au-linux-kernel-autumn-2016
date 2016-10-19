#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "vsd_device.h"
#include "vsd_ioctl.h"

static int device_fd = -1;
#define DEVICE_NAME "/dev/"MISC_DEVICE_NAME
#define PAGE_ALIGNED(x) (x % getpagesize() == 0)

int vsd_init()
{
	if (device_fd != -1)
		return -1;
	device_fd = open(DEVICE_NAME, O_RDWR);
    return device_fd == -1;
}

int vsd_deinit()
{
	if (device_fd == -1)
		return -1;
	int rc = close(device_fd);
	device_fd = -1;
	return rc;
}

int vsd_get_size(size_t *out_size)
{
	if (device_fd == -1)
		return -1;
	vsd_ioctl_get_size_arg_t arg;
	memset(&arg, 0, sizeof(arg));
	int rc = ioctl(device_fd, VSD_IOCTL_GET_SIZE, &arg);
	if (!rc) {
		*out_size = arg.size;
	}
    return rc;
}

int vsd_set_size(size_t size)
{
	if (device_fd == -1)
		return -1;
	return 	ioctl(device_fd, VSD_IOCTL_SET_SIZE, &(vsd_ioctl_set_size_arg_t){
		.size = size
	});
}

ssize_t vsd_read(char* dst, off_t offset, size_t size)
{
	if (device_fd == -1)
		return -1;
	return pread(device_fd, (void *)dst, size, offset);
}

ssize_t vsd_write(const char* src, off_t offset, size_t size)
{
	if (device_fd == -1)
		return -1;
	return pwrite(device_fd, (const void *)src, size, offset);
}

void* vsd_mmap(size_t offset)
{
	if (device_fd == -1 || !PAGE_ALIGNED(offset))
		return NULL;
	size_t vsd_size;
	void * addr;
	if (vsd_get_size(&vsd_size))
		return NULL;
	addr = mmap(NULL, vsd_size - offset, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, device_fd, offset);
	if (addr == MAP_FAILED) {
		addr = NULL;
	}
    return addr;
}

int vsd_munmap(void* addr, size_t offset)
{
	if (!PAGE_ALIGNED(offset))
		return -1;
	size_t vsd_size;
	if (vsd_get_size(&vsd_size))
		return -1;
    return munmap(addr, vsd_size - offset);
}
