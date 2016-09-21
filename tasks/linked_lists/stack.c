#include "stack.h"
#include <linux/slab.h>
#include <linux/gfp.h>

stack_entry_t* create_stack_entry(void *data)
{
	stack_entry_t * entry = kmalloc(sizeof(stack_entry_t), GFP_KERNEL);
	if (!entry)
		return NULL;
    entry->data = data;
    INIT_LIST_HEAD(&entry->lh);
    return entry;
}

void delete_stack_entry(stack_entry_t *entry)
{
    list_del(&entry->lh);
    kfree(entry);
}

void stack_push(struct list_head *stack, stack_entry_t *entry)
{
	list_add_tail(&entry->lh, stack);
}

stack_entry_t* stack_pop(struct list_head *stack) {
	stack_entry_t * entry = list_entry(stack->prev, stack_entry_t, lh);
	list_del(&entry->lh);
	return entry;
}
