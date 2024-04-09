#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "inner.h"

struct sge_array {
    size_t size;
    fn_array_key fn_key;
    void* data[];
};

void _adjust(struct sge_array* arr, int i, int length) {
    int child;
    void* tmp;

    for (tmp = arr->data[i]; 2 * i + 1 < length; i = child) {
        child = 2 * i + 1;

        if (child != length - 1 &&
            arr->fn_key(arr->data[child + 1]) > arr->fn_key(arr->data[child])) {
            child += 1;
        }
        if (arr->fn_key(tmp) < arr->fn_key(arr->data[child])) {
            arr->data[i] = arr->data[child];
        } else {
            break;
        }
    }
    arr->data[i] = tmp;
}

struct sge_array* sge_create_array(size_t size, fn_array_key fn_key) {
    size_t alloc_size = 0;
    struct sge_array* arr = NULL;

    alloc_size = sizeof(struct sge_array) + sizeof(void*) * size;
    arr = sge_malloc(alloc_size);
    if (NULL == arr) {
        return NULL;
    }
    arr->fn_key = fn_key;
    arr->size = 0;

    return arr;
}

int sge_insert_array(struct sge_array* arr, void* data) {
    arr->data[arr->size++] = data;
    return SGE_OK;
}

int sge_sort_array(struct sge_array* arr) {
    int i = 0;
    void* tmp = NULL;

    for (i = arr->size / 2; i >= 0; i--) {
        _adjust(arr, i, arr->size);
    }
    for (i = arr->size - 1; i > 0; i--) {
        tmp = arr->data[0];
        arr->data[0] = arr->data[i];
        arr->data[i] = tmp;

        _adjust(arr, 0, i);
    }

    return SGE_OK;
}

int sge_find_array(struct sge_array* arr, int key, void** data) {
    int left = 0;
    int right = arr->size;
    int i = arr->size / 2;
    int data_key = 0;

    while (i >= left && i < right) {
        data_key = arr->fn_key(arr->data[i]);
        if (data_key == key) {
            *data = arr->data[i];
            return SGE_OK;
        }

        if (data_key < key) {
            left = i + 1;
            i = (i + right) / 2;
        } else {
            right = i;
            i = (left + right) / 2;
        }
    }

    *data = NULL;
    return SGE_ERROR;
}

int sge_destroy_array(struct sge_array* arr) {
    if (NULL == arr) {
        return SGE_ERROR;
    }

    sge_free(arr);
    return SGE_OK;
}

void sge_print_array(struct sge_array* arr) {
    int i = 0;
    if (NULL == arr) {
        return;
    }

    for (i = 0; i < arr->size; ++i) {
        printf("block id(%d)\n", arr->fn_key(arr->data[i]));
    }
}
