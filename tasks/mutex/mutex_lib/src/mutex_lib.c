#include <mutex.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>

static int mutex_sys_fd = -1;

static void propagate_completed(mutex_t * m, int val) {
	m->completed = val;
	__sync_synchronize();
}

mutex_err_t mutex_init(mutex_t *m)
{
    // TODO initialize userspace side mutex state
    // and create kernel space mutex state
	m->completed = 1;
	m->queue_empty = 0;
	shared_spinlock_init(&m->lock);
	int rc = ioctl(mutex_sys_fd, MUTEX_IOCTL_CREATE,
			&(mutex_ioctl_create_arg_t) {
		.queue_empty = &m->queue_empty,
		.completed = &m->completed,
		.mutex_id = &m->id
	});
    return rc ? MUTEX_INTERNAL_ERR : MUTEX_OK;
}

mutex_err_t mutex_deinit(mutex_t *m)
{
	propagate_completed(m, 1);
	int rc = ioctl(mutex_sys_fd, MUTEX_IOCTL_DESTROY,
			&(mutex_ioctl_destroy_arg_t) {
		.id = m->id,
	});
	return rc ? MUTEX_INTERNAL_ERR : MUTEX_OK;
}

mutex_err_t mutex_lock(mutex_t *m)
{
    // TODO lock spinlock here.
    // If not successful then go to sleep
    // in kernel.

	while (!shared_spin_trylock(&m->lock)) {
		int ret = ioctl(mutex_sys_fd, MUTEX_IOCTL_LOCK,
				&(mutex_ioctl_lock_arg_t) {
			.id = m->id,
		});
		if (ret)
			return MUTEX_INTERNAL_ERR;
		/* it case of avoiding race described below
		 * here may be multiple threads - so
		 * we cant just break here
		 * and don't unlock spinlock if queue isn't empty in
		 * mutex_unlock
		 */
	}
	propagate_completed(m, 0);
    return MUTEX_OK;
}

static int check_wait_queue_empty(mutex_t * m) {
	return m->queue_empty == 0;
}

mutex_err_t mutex_unlock(mutex_t *m)
{
    // TODO unlock spinlock
    // and wakeup one kernel side waiter
    // if it exists.

	/*
	 * we propagating completed info to kernel
	 * to avoid this race:
	 * thread1 = t1, thread2 = t2
	 *  1) t1 entered to critical section
	 *	2) t2 tryed to entter - failed, jumped to kernel
	 *	3) t1 checked queue size = 0
	 *	4) t2 went to sleep
	 *	5) t1 exited section
	 */
	propagate_completed(m, 1);
	if (!check_wait_queue_empty(m)) {
		shared_spin_unlock(&m->lock);
		int rc = ioctl(mutex_sys_fd, MUTEX_IOCTL_UNLOCK,
				&(mutex_ioctl_unlock_arg_t) {
			.id = m->id,
		});
		return rc ? MUTEX_INTERNAL_ERR : MUTEX_OK;
	} else
		shared_spin_unlock(&m->lock);
    return MUTEX_OK;
}

mutex_err_t mutex_lib_init()
{
	if (mutex_sys_fd != -1)
		return MUTEX_INTERNAL_ERR;
	mutex_sys_fd = open("/dev/mutex", O_RDWR);
	return mutex_sys_fd < 0 ? MUTEX_INTERNAL_ERR : MUTEX_OK;
}

mutex_err_t mutex_lib_deinit()
{
	if (mutex_sys_fd == -1)
		return MUTEX_INTERNAL_ERR;
    close(mutex_sys_fd);
    mutex_sys_fd = -1;
    return MUTEX_OK;
}
