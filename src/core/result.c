#include <string.h>

#include "inner.h"

int sge_append_result(struct sge_proto_result *r, const uint8_t *str, size_t len) {
    uint8_t *tmp = NULL;

    if (NULL == r->data) {
        r->data = sge_malloc(sizeof(char) * SGE_INIT_RESULT_DATA_LEN);
        if (NULL == r->data) {
            return SGE_ERROR;
        }
        r->cap = SGE_INIT_RESULT_DATA_LEN;
        r->len = 0;
    } else if ((len + r->len) > r->cap) {
        tmp = sge_realloc(r->data, len + r->len + SGE_INIT_RESULT_DATA_LEN);
        if (NULL == tmp) {
            return SGE_ERROR;
        }
        r->data = tmp;
        r->cap += len + SGE_INIT_RESULT_DATA_LEN;
    }

    memcpy(r->data + r->len, str, len);
    r->len += len;

    return SGE_OK;
}

int sge_destroy_result(struct sge_proto_result *r) {
    if (NULL == r) {
        return SGE_ERROR;
    }
    if (NULL == r->data) {
        return SGE_ERROR;
    }
    sge_free(r->data);
    r->data = NULL;
    r->cap = r->len = 0;

    return SGE_OK;
}
