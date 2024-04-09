#include <stdarg.h>
#include <stdio.h>

#include "inner.h"

static const char *ERROR_MSG[] = {"SUCCESS",      "FILE NOT FOUND",       "MEMORY NOT ENOUGH",
                                  "PARSER ERROR", "BLOCK NAME NOT FOUND", "ENCODE ERROR",
                                  "DECODE ERROR", "ARGUMENT ERROR"};

static struct sge_proto *_alloc_proto(void) {
    struct sge_proto *p = NULL;

    p = sge_malloc(sizeof(struct sge_proto));
    p->count = 0;
    p->err.code = 0;
    p->block_tree = sge_create_radix();
    if (NULL == p->block_tree) {
        sge_free(p);
        return NULL;
    }
    p->blocks = NULL;

    return p;
}

struct sge_proto *sge_parse_protocol(const char *content, size_t len) {
    struct sge_proto *p = NULL;

    if (NULL == content || len == 0) {
        return NULL;
    }

    p = _alloc_proto();
    return sge_parse_content(p, content, len, NULL);
}

struct sge_proto *sge_parse_protocol_file(const char *filename) {
    int ret = 0;
    struct sge_proto *p = NULL;

    if (NULL == filename) {
        return NULL;
    }

    p = _alloc_proto();
    return sge_parse_content(p, NULL, 0, filename);
}

int sge_encode_protocol(struct sge_proto *proto, const char *name, const void *ud,
                        sge_fn_get fn_get, uint8_t *buffer, size_t *buffer_len) {
    int ret = 0;
    size_t buflen = 0;
    uint8_t *encode_buffer = NULL;

    if (NULL == proto || NULL == name || NULL == ud || NULL == fn_get || NULL == buffer ||
        NULL == buffer_len) {
        return SGE_ERROR;
    }

    ret = sge_encode_proto(proto, name, ud, fn_get, &encode_buffer, &buflen);
    if (SGE_OK != ret) {
        return ret;
    }

    ret = sge_compress_protocol(encode_buffer, buflen, buffer, buffer_len);
    if (SGE_OK != ret) {
        *buffer_len = 0;
        sge_free(encode_buffer);
        return ret;
    }

    sge_free(encode_buffer);
    return SGE_OK;
}
int sge_decode_protocol(struct sge_proto *proto, uint8_t *buffer, size_t len, void *ud,
                        sge_fn_set fn_set) {
    int ret = 0;
    uint8_t *proto_buf = NULL;
    size_t proto_buf_len = 0;

    if (NULL == proto || NULL == buffer || NULL == ud || NULL == fn_set) {
        return SGE_ERROR;
    }

    ret = sge_decompress_protocol(buffer, len, &proto_buf, &proto_buf_len);
    if (SGE_OK != ret) {
        return ret;
    }

    ret = sge_decode_proto(proto, proto_buf, proto_buf_len, ud, fn_set);
    sge_free(proto_buf);

    return ret;
}

int sge_protocol_error(struct sge_proto *p, const char **err) {
    if (NULL == p) {
        return SGE_ERROR;
    }

    *err = p->err.msg;
    return p->err.code;
}

void sge_print_protocol(struct sge_proto *p) {
    int i = 0, ret = 0;
    struct sge_block *bp = NULL;
    sge_radix_iter iter;

    sge_init_radix_iter(p->block_tree, &iter);
    while (sge_next_radix_iter(&iter)) {
        bp = (struct sge_block *)iter.data;
        printf("%s %d %d\n", bp->name, bp->id, bp->count);
        for (i = 0; i < bp->count; ++i) {
            printf("\tname(%s) id(%d) tid(%d) type(%d) flags(%d)\n", bp->fields[i].name,
                   bp->fields[i].id, bp->fields[i].tid, bp->fields[i].type, bp->fields[i].flags);
        }
    }
    sge_destroy_radix_iter(&iter);
}

void sge_destroy_protocol(struct sge_proto *proto) {
    if (NULL == proto) {
        return;
    }

    if (proto->blocks) {
        sge_destroy_array(proto->blocks);
    }

    if (proto->block_tree) {
        sge_destroy_radix(proto->block_tree);
    }

    sge_free(proto);
}

void sge_format_error(struct sge_proto *p, int code, const char *fmt, ...) {
    size_t len;
    va_list ap;
    char *iter = NULL;

    if (NULL == p) {
        return;
    }

    len = 0;
    p->err.code = code;
    iter = p->err.msg;
    len = snprintf(iter, SGE_PROTO_ERROR_MSG_LEN, "%s: ", ERROR_MSG[code]);
    iter = iter + len;
    if (fmt) {
        va_start(ap, fmt);
        len += vsnprintf(iter, SGE_PROTO_ERROR_MSG_LEN - len, fmt, ap);
        va_end(ap);
    }

    p->err.msg[len] = '\0';
}
