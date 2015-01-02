/*
 * Copyright (c) 2014-2015 Ricardo Padilha for Drobo Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/err.h>	/* for IS_ERR_OR_NULL and co. */
#include <linux/slab.h>	/* for kzalloc, kcalloc */
#include "array_list.h"

int int_list_alloc(struct int_list_t *list, const int size) {
	int err = 0;

	if (!list || size < 1) {
		err = -EINVAL;
		goto out;
	}

	list->data = (int *) kcalloc(size, sizeof(int), GFP_KERNEL);
	if (IS_ERR_OR_NULL(list->data)) {
		err = !(list->data) ? -ENOMEM : PTR_ERR(list->data);
		goto out_free;
	}

	list->size = size;
	list->count = 0;
	list->sorted = 1;
	goto out;

out_free:
	kfree(list);
out:
	return err;
}

void int_list_free(struct int_list_t *list) {
	if (IS_ERR_OR_NULL(list)) {
		return;
	}
	kfree(list->data);
}

int int_list_count(struct int_list_t *list, int *count) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	*count = list->count;

out:
	return err;
}

int int_list_size(struct int_list_t *list, int *size) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	*size = list->size;

out:
	return err;
}

int int_list_is_sorted(struct int_list_t *list) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	err = list->sorted;

out:
	return err;
}

/*
 * double the capacity of the list
 * private function
 */
int int_list_resize(struct int_list_t *list) {
	int err = 0;
	int new_size = list->size << 1;
	int *new_data;

	new_data = krealloc(list->data, new_size * sizeof(int), GFP_KERNEL);
	if (IS_ERR_OR_NULL(new_data)) {
		err = !(new_data) ? -ENOMEM : PTR_ERR(new_data);
		goto out;
	}
	list->data = new_data;
	list->size = new_size;

out:
	return err;
}

/*
 * make sure that an additional n integers can be added to the list
 * private function
 */
int int_list_ensure_capacity(struct int_list_t *list, const int n) {
	if (list->count + n > list->size) {
		return int_list_resize(list);
	}
	return 0;
}

/*
 * add an integer to the list
 * public function
 */
int int_list_add(struct int_list_t *list, const int value) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	err = int_list_ensure_capacity(list, 1);
	if (err) {
		goto out;
	}

	BUG_ON(!list->data);
	list->data[list->count] = value;
	list->count += 1;
	list->sorted = 0;

out:
	return err;
}

/*
 * get an integer from the list
 * public function
 */
int int_list_get(struct int_list_t *list, const int index, int *value) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}
	if (index >= list->count || index < 0) {
		err = -EINVAL;
		goto out;
	}

	BUG_ON(!list->data);
	*value = list->data[index];

out:
	return err;
}

/*
 * remove an index from the list
 * public function
 */
int int_list_delete(struct int_list_t *list, const int index, int *old_value) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}
	if (index >= list->count || index < 0) {
		err = -EINVAL;
		goto out;
	}

	BUG_ON(!list->data);
	*old_value = list->data[index];
	list->count -= 1;
	memmove(list->data + index, list->data + (index + 1) * sizeof(int), (list->count - index) * sizeof(int));

out:
	return err;
}

/*
 * remove an integer from the list
 * public function
 */
int int_list_remove(struct int_list_t *list, const int value) {
	int err = 0;
	int index = 0;
	int old_value = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	err = int_list_indexof(list, value, &index);
	if (err) {
		goto out;
	}

	err = int_list_delete(list, index, &old_value);

out:
	return err;
}

/*
 * clear the list, i.e., remove all data
 * public function
 */
int int_list_clear(struct int_list_t *list) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	list->count = 0;
	list->sorted = 1;

out:
	return err;
}

/*
 * compare two ints
 * private function
 */
int cmpint(const void *a, const void *b) {
	return *(int *) a - *(int *) b;
}

/*
 * sort the list
 * public function
 */
int int_list_sort(struct int_list_t *list) {
	int err = 0;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	BUG_ON(!list->data);
	sort(list->data, list->count, sizeof(int), cmpint, NULL);
	list->sorted = 1;

out:
	return err;
}

/*
 * get an integer from the list
 * public function
 */
int int_list_indexof(struct int_list_t *list, const int value, int *index) {
	int err = 0;
	void *result;
	int i,k;

	if (IS_ERR_OR_NULL(list)) {
		err = !(list) ? -EINVAL : PTR_ERR(list);
		goto out;
	}

	BUG_ON(!list->data);
	*index = -1;
	if (list->sorted) {
		result = bsearch(&value, list->data, list->count, sizeof(int), cmpint);
		if (IS_ERR(result)) {
			err = PTR_ERR(result);
			goto out;
		}
		if (result) {
			*index = (int *)result - list->data;
		}
	} else { // !list->sorted
		for (i = 0, k = list->count; i < k; i++) {
			if (cmpint(&(list->data[i]), &value) == 0) {
				*index = i;
				break;
			}
		}
	}
	return 0;

out:
	return err;
}

/*
 * get an integer from the list
 * public function
 */
int int_list_contains(struct int_list_t *list, const int value) {
	int err = 0;
	int index = 0;

	err = int_list_indexof(list, value, &index);
	if (err) {
		return err;
	}
	return (index >= 0);
}

