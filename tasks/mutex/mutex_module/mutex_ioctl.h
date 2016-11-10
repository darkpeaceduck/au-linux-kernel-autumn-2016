#ifndef _MUTEX_UAPI_H
#define _MUTEX_UAPI_H

#ifdef __KERNEL__
#include <asm/ioctl.h>
#include "shared_spinlock.h"
#else
#include <sys/ioctl.h>
#include <stddef.h>
#include <shared_spinlock.h>
#endif //__KERNEL__

#define MUTEX_IOCTL_MAGIC 'M'

// TODO define mutex dev IOCTL interface here
// Example:

typedef int mutex_id_t;

typedef struct mutex_ioctl_create_arg {
	int * queue_empty;
	int * completed;
	mutex_id_t * mutex_id;
} mutex_ioctl_create_arg_t;

typedef struct mutex_ioctl_destroy_arg {
	mutex_id_t id;
} mutex_ioctl_destroy_arg_t;

typedef struct mutex_ioctl_lock_arg {
	mutex_id_t id;
} mutex_ioctl_lock_arg_t;

typedef struct mutex_ioctl_unlock_arg {
	mutex_id_t id;
} mutex_ioctl_unlock_arg_t;

#define MUTEX_IOCTL_CREATE \
    _IOW(MUTEX_IOCTL_MAGIC, 1, mutex_ioctl_create_arg_t)
#define MUTEX_IOCTL_DESTROY \
    _IOW(MUTEX_IOCTL_MAGIC, 2, mutex_ioctl_destroy_arg_t)
#define MUTEX_IOCTL_LOCK \
	_IOW(MUTEX_IOCTL_MAGIC, 3, mutex_ioctl_lock_arg_t)
#define MUTEX_IOCTL_UNLOCK \
	_IOW(MUTEX_IOCTL_MAGIC, 4, mutex_ioctl_unlock_arg_t)


#endif //_VSD_UAPI_H
