#include <string.h>

#include "inner.h"

#define SGE_CHECK_PROTO_RESULT() \
    {                            \
        if (SGE_OK != ret) {     \
            goto err;            \
        }                        \
    }

struct sge_encoder {
    struct sge_proto *proto;
    struct sge_block *b;
    const void *ud;
    sge_fn_get get;
    struct sge_proto_result result;
};

static int _do_encode(struct sge_encoder *encoder);

static void _destroy_proto_result(struct sge_proto_result *r) { sge_destroy_result(r); }

static int _encode_string(struct sge_proto_result *r, const uint8_t *str, size_t len) {
    return sge_append_result(r, str, len);
}

static int _encode_integer(struct sge_proto_result *r, long long value) {
    uint8_t c = 0;
    int step = 0, size = SGE_INTEGER_SIZE;
    unsigned int mask = 0xFF;
    unsigned long long v = value;

    for (step = 0; step < size; ++step) {
        c = (v >> (step * 8)) & mask;
        _encode_string(r, &c, 1);
    }

    return SGE_OK;
}

static int _encode_value(struct sge_encoder *encoder, struct sge_field *f, struct sge_value *v) {
    int ret = SGE_OK;
    const void *old_ud = NULL;
    struct sge_block *old_b = NULL, *b = NULL;

    switch (v->t) {
    case FIELD_TYPE_INTEGER:
        _encode_integer(&encoder->result, FIELD_TYPE_INTEGER);
        _encode_integer(&encoder->result, v->v.i);
        break;

    case FIELD_TYPE_STRING:
        _encode_integer(&encoder->result, FIELD_TYPE_STRING);
        _encode_integer(&encoder->result, v->v.s.l);
        _encode_string(&encoder->result, v->v.s.s, v->v.s.l);
        break;

    case FIELD_TYPE_UNKNOWN:
        _encode_integer(&encoder->result, FIELD_TYPE_UNKNOWN);
        break;

    case FIELD_TYPE_CUSTOM:
        ret = sge_find_array(encoder->proto->blocks, f->tid, (void **)&b);
        if (SGE_OK != ret) {
            SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR,
                                "unknown field(%s:%s) type(%d).", encoder->b->name, f->name,
                                f->tid);
            return SGE_ERROR;
        }

        old_b = encoder->b;
        old_ud = encoder->ud;

        encoder->ud = v->v.a;
        encoder->b = b;
        _encode_integer(&encoder->result, FIELD_TYPE_CUSTOM);
        ret = _do_encode(encoder);
        if (SGE_OK != ret) {
            return SGE_ERROR;
        }

        encoder->b = old_b;
        encoder->ud = old_ud;
        break;

    default:
        SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR, "unknown field(%s:%s) type(%d).",
                            encoder->b->name, f->name, v->t);
    }

    return ret;
}

static int _encode_by_key(struct sge_encoder *encoder, struct sge_field *f, struct sge_key *k) {
    int ret = 0;
    struct sge_value v;
    int real_type = f->type & (~FIELD_TYPE_LIST);

    k->name.s = f->name;
    k->name.l = strlen(f->name);

    ret = encoder->get(encoder->ud, k, &v);
    if (SGE_OK != ret) {
        SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR, "get field(%s:%s) error.",
                            encoder->b->name, f->name);
        return SGE_ERROR;
    }

    if (f->flags & FLAG_REQUIRED) {
        // required but got nil
        if (v.t == FIELD_TYPE_UNKNOWN) {
            SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR,
                                "required field(%s:%s) but got nil.", encoder->b->name, f->name);
            return SGE_ERROR;
        }
    } else if (f->flags & FLAG_OPTIONAL && v.t == FIELD_TYPE_UNKNOWN) {
        return _encode_value(encoder, f, &v);
    }

    if (v.t != real_type) {
        SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR,
                            "field(%s:%s) type not match expect %s:%d got %d.", encoder->b->name,
                            f->name, f->name, real_type, v.t);
        return SGE_ERROR;
    }

    return _encode_value(encoder, f, &v);
}

static int _encode_list(struct sge_encoder *encoder, struct sge_field *f) {
    int ret = 0, idx = 0;
    struct sge_key k;
    struct sge_value v;

    k.t = FIELD_TYPE_LIST;
    k.name.s = f->name;
    k.name.l = strlen(f->name);

    ret = encoder->get(encoder->ud, &k, &v);
    if (SGE_OK != ret) {
        SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR, "get field(%s:%s) error.",
                            encoder->b->name, f->name);
        return SGE_ERROR;
    }

    if (f->flags & FLAG_REQUIRED) {
        if (v.t != FIELD_TYPE_INTEGER) {
            SGE_PROTO_ERROR_ARG(encoder->proto, SGE_ERR_ENCODE_ERROR,
                                "get field(%s:%s) element size error. value type must be integer.",
                                encoder->b->name, f->name);
            return SGE_ERROR;
        }
    }
    _encode_value(encoder, f, &v);

    if (v.t == FIELD_TYPE_INTEGER) {
        k.t = f->type;
        for (idx = 0; idx < v.v.i; ++idx) {
            k.idx = idx;
            ret = _encode_by_key(encoder, f, &k);
            if (ret != SGE_OK) {
                return SGE_ERROR;
            }
        }
    }

    return SGE_OK;
}

static int _encode_field(struct sge_encoder *encoder, struct sge_field *f) {
    struct sge_key k;

    if (f->type & FIELD_TYPE_LIST) {
        return _encode_list(encoder, f);
    } else {
        k.t = f->type;
        return _encode_by_key(encoder, f, &k);
    }
}

static int _do_encode(struct sge_encoder *encoder) {
    int i = 0;
    int ret = 0;
    struct sge_field *f = NULL;
    struct sge_block *b = encoder->b;

    ret = _encode_integer(&encoder->result, b->id);
    SGE_CHECK_PROTO_RESULT();

    for (i = 0; i < b->count; ++i) {
        f = &b->fields[i];
        ret = _encode_field(encoder, f);
        SGE_CHECK_PROTO_RESULT();
    }
err:
    return ret;
}

int sge_encode_proto(struct sge_proto *proto, const unsigned char *name, const void *ud,
                     sge_fn_get fn_get, uint8_t **buffer, size_t *len) {
    int ret = 0, i = 0;
    uint8_t crc_high, crc_low;
    long long crc16 = 0;
    struct sge_block *block = NULL;
    struct sge_encoder encoder;
    uint8_t ver = SGE_PROTO_VERSION;

    block = sge_find_radix(proto->block_tree, (unsigned char *)name, strlen(name));
    if (NULL == block) {
        SGE_PROTO_ERROR_ARG(proto, SGE_ERR_PARSER_ERROR, "count not found protocol name(%s)", name);
        return SGE_ERROR;
    }

    encoder.proto = proto;
    encoder.b = block;
    encoder.ud = ud;
    encoder.get = fn_get;
    encoder.result.data = NULL;
    encoder.result.len = 0;

    // crc16 placehold
    ret = _encode_string(&encoder.result, "  ", 2);
    SGE_CHECK_PROTO_RESULT();

    ret = _encode_string(&encoder.result, &ver, 1);
    SGE_CHECK_PROTO_RESULT();

    ret = _do_encode(&encoder);
    SGE_CHECK_PROTO_RESULT();

    for (i = 0; i < encoder.result.len % 8; ++i) {
        _encode_string(&encoder.result, "\0", 1);
    }
    *len = encoder.result.len;
    *buffer = encoder.result.data;

    crc16 = _crc16(encoder.result.data + 2, encoder.result.len - 2);
    encoder.result.len = 0;
    crc_high = (crc16 >> 8) & 0xFF;
    crc_low = crc16 & 0xFF;
    _encode_string(&encoder.result, &crc_low, 1);
    _encode_string(&encoder.result, &crc_high, 1);

    return SGE_OK;
err:
    _destroy_proto_result(&encoder.result);
    return ret;
}
