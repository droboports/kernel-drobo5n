/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef KERNEL_FS_NOTIFYFS_ARRAY_LIST_H_
#define KERNEL_FS_NOTIFYFS_ARRAY_LIST_H_

#include <linux/gfp.h>
#include <linux/sort.h>
#include <linux/bsearch.h>

typedef struct int_list_t {
	int size;	/* available positions in the list */
	int count;	/* occupied positions in the list */
	int sorted;	/* is the data sorted? */
	int *data;	/* list data */
} int_list_t;

int int_list_alloc(struct int_list_t *list, const int size);

void int_list_free(struct int_list_t *list);

int int_list_count(struct int_list_t *list, int *count);

int int_list_size(struct int_list_t *list, int *size);

int int_list_is_sorted(struct int_list_t *list);

int int_list_add(struct int_list_t *list, const int value);

int int_list_get(struct int_list_t *list, const int index, int *value);

int int_list_delete(struct int_list_t *list, const int index, int *old_value);

int int_list_remove(struct int_list_t *list, const int value);

int int_list_clear(struct int_list_t *list);

int int_list_sort(struct int_list_t *list);

int int_list_indexof(struct int_list_t *list, const int value, int *index);

int int_list_contains(struct int_list_t *list, const int value);

#endif /* KERNEL_FS_NOTIFYFS_ARRAY_LIST_H_ */
