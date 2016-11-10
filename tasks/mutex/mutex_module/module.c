#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <uapi/linux/fs.h>
#include <uapi/linux/stat.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/err.h>
#include <linux/wait.h>
#include "mutex_ioctl.h"

#define LOG_TAG "[MUTEX_MODULE] "

typedef struct kernel_mutex_keeper {
	struct rcu_head rcu;
	struct hlist_node list;
	wait_queue_head_t q;
	int __user * queue_empty;
	int __user * completed;
	spinlock_t user;
	mutex_id_t id;
	int destroying;
}kernel_mutex_keeper_t;

typedef struct tgstate {
	struct rcu_head rcu;
	struct hlist_node list;
	struct hlist_head mutexes;
	spinlock_t wlock;
	pid_t tgid;

	mutex_id_t last_id;
}tgstate_t;

typedef struct system_mutex_state {
    // lock only when adding new tgroup
    spinlock_t wlock;
    struct hlist_head tgstates;
} system_mutex_state_t;

typedef struct mutex_dev {
    struct miscdevice mdev;
    system_mutex_state_t sysmstate;
} mutex_dev_t;

static mutex_dev_t *mutex_dev;

typedef enum {
	RCU,
	DEFAULT
} search_mode;

static kernel_mutex_keeper_t * mutex_create(mutex_id_t id,
		int __user * queue_empty,
		int __user * completed) {
	kernel_mutex_keeper_t * keeper = kmalloc(sizeof(kernel_mutex_keeper_t), GFP_KERNEL);

	/* no rcu head initialoation */
	INIT_HLIST_NODE(&keeper->list);
	init_waitqueue_head(&keeper->q);
	keeper->queue_empty = queue_empty;
	keeper->completed = completed;
	spin_lock_init(&keeper->user);
	keeper->id = id;
	keeper->destroying = 0;
	return keeper;
}

static void mutex_shedule_release(kernel_mutex_keeper_t *keeper) {
	hlist_del_rcu(&keeper->list);
	kfree_rcu(keeper, rcu);
}

static tgstate_t * tg_create(void) {
	tgstate_t * fresh = kmalloc(sizeof(tgstate_t), GFP_KERNEL);
	INIT_HLIST_HEAD(&fresh->mutexes);
	INIT_HLIST_NODE(&fresh->list);
	spin_lock_init(&fresh->wlock);
	fresh->tgid = current->tgid;
	fresh->last_id = 0;
	return fresh;
}

static void tg_shedule_destroy(tgstate_t * state) {
	kfree_rcu(state, rcu);
}

static int tg_search_check(tgstate_t * state) {
	return current->tgid == state->tgid;
}

static tgstate_t * tg_search(search_mode mode) {
	tgstate_t * state;

	if (mode == RCU) {
		hlist_for_each_entry_rcu(state, &mutex_dev->sysmstate.tgstates, list) {
			if(tg_search_check(state))
				return state;
		}
	} else {
		hlist_for_each_entry(state, &mutex_dev->sysmstate.tgstates, list) {
			if(tg_search_check(state))
				return state;
		}
	}

	return NULL;
}

static int mutex_check(mutex_id_t id, kernel_mutex_keeper_t * keeper) {
	return keeper->id == id;
}

static kernel_mutex_keeper_t * mutex_search(tgstate_t * state,
		mutex_id_t id, search_mode mode) {
	kernel_mutex_keeper_t * keeper;


	if (mode == RCU) {
		hlist_for_each_entry_rcu(keeper, &state->mutexes, list) {
			if (mutex_check(id, keeper)) {
				return keeper;
			}
		}
	} else {
		hlist_for_each_entry(keeper, &state->mutexes, list) {
			if (mutex_check(id, keeper)) {
				return keeper;
			}
		}
	}
	return NULL;
}

static void init_system_mutex_state(system_mutex_state_t *sysmstate)
{
    spin_lock_init(&sysmstate->wlock);
    INIT_HLIST_HEAD(&sysmstate->tgstates);
}

static void deinit_system_mutex_state(system_mutex_state_t *sysmstate)
{
    // This is called on module release. So no opened file descriptors
    // exist. Thus we have nothing to cleanup here
}

static int mutex_dev_open(struct inode *inode, struct file *filp)
{
	system_mutex_state_t * state = &mutex_dev->sysmstate;
	tgstate_t * fresh = tg_create();

	spin_lock(&state->wlock);
	fresh = tg_search(DEFAULT);
	if (fresh != NULL) {
		spin_unlock(&state->wlock);
		return -EINVAL;
	}
	fresh = tg_create();
	hlist_add_tail_rcu(&fresh->list, &state->tgstates);
	spin_unlock(&state->wlock);

    pr_notice(LOG_TAG " opened successfully\n");
    return 0;
}

static int mutex_dev_release(struct inode *inode, struct file *filp)
{
	tgstate_t * tg_state;
	kernel_mutex_keeper_t * keeper;
	struct hlist_node * tmp;
	system_mutex_state_t * sys_state = &mutex_dev->sysmstate;

	spin_lock(&sys_state->wlock);
	tg_state = tg_search(DEFAULT);
	if (sys_state == NULL) {
		spin_unlock(&sys_state->wlock);
		return -EINVAL;
	}
	hlist_del_rcu(&tg_state->list);
	spin_unlock(&sys_state->wlock);

	spin_lock(&tg_state->wlock);
	hlist_for_each_entry_safe(keeper, tmp, &tg_state->mutexes, list) {
		mutex_shedule_release(keeper);
	}
	spin_unlock(&tg_state->wlock);

	tg_shedule_destroy(tg_state);


    pr_notice(LOG_TAG " closed\n");
    return 0;
}

static long mutex_ioctl_destroy(mutex_ioctl_destroy_arg_t __user *uarg)  {
	mutex_ioctl_destroy_arg_t arg;
	tgstate_t * tg_state;
	kernel_mutex_keeper_t * keeper;
	long rc = 0;


	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;


	rcu_read_lock(); /* for tgstates list */
	tg_state = tg_search(RCU);
	if (tg_state == NULL) {
		rc = -EFAULT;
		goto out;
	}

	spin_lock(&tg_state->wlock);
	keeper = mutex_search(tg_state, arg.id, DEFAULT);
	if (keeper == NULL) {
		rc = -EFAULT;
		goto out_spin;
	}

	keeper->destroying = 1;
	wake_up_all(&keeper->q);
	mutex_shedule_release(keeper);
out_spin:
	spin_unlock(&tg_state->wlock);
out:
 	rcu_read_unlock();
 	return rc;
}

static long mutex_ioctl_create(mutex_ioctl_create_arg_t __user *uarg)  {
	mutex_ioctl_create_arg_t arg;
	tgstate_t * tg_state;
	kernel_mutex_keeper_t * keeper;
	long rc = 0;
	int new_id = 0;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	rcu_read_lock(); /* for tgstates list */
	tg_state = tg_search(RCU);
	if (tg_state == NULL) {
		rc = -EFAULT;
		goto out;
	}

	spin_lock(&tg_state->wlock);
	new_id = tg_state->last_id++;
	keeper = mutex_create(new_id, arg.queue_empty, arg.completed);
	hlist_add_tail_rcu(&keeper->list, &tg_state->mutexes);
	spin_unlock(&tg_state->wlock);

out:
 	rcu_read_unlock();
 	if (!rc && copy_to_user(arg.mutex_id, &new_id, sizeof(new_id))) {
 		rc = -EFAULT;
 	}
 	return rc;
}

static void mutex_update_user(kernel_mutex_keeper_t * keeper, int dec) {
	int val;

	spin_lock(&keeper->user);
	val = *keeper->queue_empty + dec;
	mb();
	*keeper->queue_empty = val;
	mb();
	spin_unlock(&keeper->user);
}

static void mutex_wait_compeleted(kernel_mutex_keeper_t * keeper) {
	mutex_update_user(keeper, 1);
	mb();
	/* condition in wait_event_exclusive_cmd
	 * checks before sleep - don't go to sleep if crit section
	 * owner exitedv - this is part of avoiding of race described in
	 * mutex_lib.c
	 */
	wait_event_exclusive_cmd(keeper->q, (*keeper->completed) , ; , ;);
	mutex_update_user(keeper, -1);
}

static void mutex_wake_single(kernel_mutex_keeper_t * keeper) {
	/* wake_up - __wake_up with nr = 1 - wakes single exclusive task */
	wake_up(&keeper->q);
}

static long mutex_ioctl_lock(mutex_ioctl_lock_arg_t __user *uarg) {
	mutex_ioctl_lock_arg_t arg;
	tgstate_t * state;
	kernel_mutex_keeper_t * keeper;
	int rc = 0;


	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	rcu_read_lock();
	state = tg_search(RCU);
	if (state == NULL) {
		rc = -EFAULT;
		goto lock_out;
	}
	keeper = mutex_search(state, arg.id, RCU);
	if (keeper == NULL) {
		rc = -EFAULT;
		goto lock_out;
	}
	mutex_wait_compeleted(keeper);
	/* flag sets before wake_up_all, flag checks after wake -
	 * not need additional locking here
	 */
	rc = keeper->destroying ? -EFAULT : 0;
lock_out:
	rcu_read_unlock();
	return rc;
}

static long mutex_ioctl_unlock(mutex_ioctl_unlock_arg_t __user *uarg) {
	mutex_ioctl_unlock_arg_t arg;
	tgstate_t * state;
	kernel_mutex_keeper_t * keeper;
	int rc = 0;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	rcu_read_lock();
	state = tg_search(RCU);
	if (state == NULL) {
		rc = -EFAULT;
		goto unlock_out;
	}
	keeper = mutex_search(state, arg.id, RCU);
	if (keeper == NULL) {
		rc = -EFAULT;
		goto unlock_out;
	}
	mutex_wake_single(keeper);
unlock_out:
	rcu_read_unlock();
	return rc;
}


static long mutex_dev_ioctl(struct file *filp, unsigned int cmd,
        unsigned long arg)
{
	switch(cmd) {
		case MUTEX_IOCTL_CREATE:
			return mutex_ioctl_create((mutex_ioctl_create_arg_t __user*)arg);
			break;
		case MUTEX_IOCTL_DESTROY:
			return mutex_ioctl_destroy((mutex_ioctl_destroy_arg_t __user*)arg);
			break;
		case MUTEX_IOCTL_LOCK:
			return mutex_ioctl_lock((mutex_ioctl_lock_arg_t __user*)arg);
			break;
		case MUTEX_IOCTL_UNLOCK:
			return mutex_ioctl_unlock((mutex_ioctl_unlock_arg_t __user*)arg);
			break;
		default:
			break;
	}
    return 0;
}

static struct file_operations mutex_dev_fops = {
    .owner = THIS_MODULE,
    .open = mutex_dev_open,
    .release = mutex_dev_release,
    .unlocked_ioctl = mutex_dev_ioctl
};

static int __init mutex_module_init(void)
{
    int ret = 0;
    mutex_dev = (mutex_dev_t*)
        kzalloc(sizeof(*mutex_dev), GFP_KERNEL);
    if (!mutex_dev) {
        ret = -ENOMEM;
        pr_warn(LOG_TAG "Can't allocate memory\n");
        goto error_alloc;
    }
    mutex_dev->mdev.minor = MISC_DYNAMIC_MINOR;
    mutex_dev->mdev.name = "mutex";
    mutex_dev->mdev.fops = &mutex_dev_fops;
    mutex_dev->mdev.mode = S_IRUSR | S_IRGRP | S_IROTH
        | S_IWUSR| S_IWGRP | S_IWOTH;
    init_system_mutex_state(&mutex_dev->sysmstate);

    if ((ret = misc_register(&mutex_dev->mdev)))
        goto error_misc_reg;

    pr_notice(LOG_TAG "Mutex dev with MINOR %u"
        " has started successfully\n", mutex_dev->mdev.minor);
    return 0;

error_misc_reg:
    kfree(mutex_dev);
    mutex_dev = NULL;
error_alloc:
    return ret;
}

static void __exit mutex_module_exit(void)
{
    pr_notice(LOG_TAG "Removing mutex device %s\n", mutex_dev->mdev.name);
    misc_deregister(&mutex_dev->mdev);
    deinit_system_mutex_state(&mutex_dev->sysmstate);
    kfree(mutex_dev);
    mutex_dev = NULL;
}

module_init(mutex_module_init);
module_exit(mutex_module_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AU user space mutex kernel side support module");
MODULE_AUTHOR("Kernel hacker!");
