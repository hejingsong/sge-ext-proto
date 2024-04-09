#include <string.h>

#include "inner.h"

struct sge_decoder {
    struct sge_proto *proto;
    struct sge_block *b;
    const uint8_t *bin;
    size_t len;
    size_t cursor;
    void *ud;
    sge_fn_set set;
};

static int _do_decode(struct sge_decoder *decoder);

static int _verify_crc(const uint8_t *bin, size_t len) {
    uint16_t crc16 = 0;

    crc16 = _crc16(bin + 2, len - 2);
    if (0 == memcmp(bin, &crc16, 2)) {
        return SGE_OK;
    } else {
        return SGE_ERROR;
    }
}

static void _fill_key(struct sge_key *k, struct sge_field *f) {
    k->name.s = f->name;
    k->name.l = strlen(f->name);
}

static long long _decode_integer(struct sge_decoder *decoder) {
    unsigned char c = 0;
    long long i = 0;
    unsigned long long mask = 0;
    int bit = 0;

    while (bit < SGE_INTEGER_SIZE && decoder->cursor < decoder->len) {
        c = (unsigned char)decoder->bin[decoder->cursor];
        mask = c;
        mask <<= (bit * 8);
        i |= mask;
        bit += 1;
        decoder->cursor += 1;
    }

    return i;
}

static int _decode_string(struct sge_decoder *decoder, const unsigned char **data, size_t *len) {
    long long l = 0;

    l = _decode_integer(decoder);

    *len = l;
    *data = decoder->bin + decoder->cursor;
    decoder->cursor += l;

    return SGE_OK;
}

static int _decode_normal(struct sge_decoder *decoder, struct sge_field *f, struct sge_key *k) {
#define encode_type(type)                                                                         \
    {                                                                                             \
        long long __t = _decode_integer(decoder);                                                 \
        if (__t != (type)) {                                                                      \
            if (f->flags & FLAG_REQUIRED) {                                                       \
                SGE_PROTO_ERROR_ARG(decoder->proto, SGE_ERR_ENCODE_ERROR,                         \
                                    "field(%s:%s) type not match decode value(%lld) expect(%d).", \
                                    decoder->b->name, f->name, __t, type);                        \
                return SGE_ERROR;                                                                 \
            } else {                                                                              \
                v.t = __t;                                                                        \
                break;                                                                            \
            }                                                                                     \
        }                                                                                         \
    }

    int ret = SGE_OK;
    void *ud = NULL, *old_ud = NULL;
    unsigned int t = f->type & (~FIELD_TYPE_LIST);
    struct sge_value v;

    _fill_key(k, f);
    v.t = t;
    switch (t) {
    case FIELD_TYPE_INTEGER:
        encode_type(FIELD_TYPE_INTEGER);
        v.v.i = _decode_integer(decoder);
        break;

    case FIELD_TYPE_STRING:
        encode_type(FIELD_TYPE_STRING);
        _decode_string(decoder, &v.v.s.s, &v.v.s.l);
        break;

    case FIELD_TYPE_UNKNOWN:
        encode_type(FIELD_TYPE_UNKNOWN);
        v.t = FIELD_TYPE_UNKNOWN;
        break;

    case FIELD_TYPE_CUSTOM:
        encode_type(FIELD_TYPE_CUSTOM);
        if (NULL == (ud = decoder->set(decoder->ud, k, &v))) {
            return SGE_ERROR;
        }
        old_ud = decoder->ud;
        decoder->ud = ud;
        ret = _do_decode(decoder);
        decoder->ud = old_ud;
        return ret;

    default:
        SGE_PROTO_ERROR_ARG(decoder->proto, SGE_ERR_ENCODE_ERROR, "unknown field(%s:%s) type(%d).",
                            decoder->b->name, f->name, v.t);
        return SGE_ERROR;
    }

    if (NULL == decoder->set(decoder->ud, k, &v)) {
        return SGE_ERROR;
    }

    return SGE_OK;
}

static int _decode_list(struct sge_decoder *decoder, struct sge_field *f) {
    int ret = SGE_ERROR;
    struct sge_value v;
    struct sge_key k;
    long long i = 0, len = 0, type = 0;
    void *ud = NULL, *old_ud = NULL;

    _fill_key(&k, f);
    k.t = FIELD_TYPE_LIST;

    type = _decode_integer(decoder);
    if (type == FIELD_TYPE_UNKNOWN) {
        v.t = FIELD_TYPE_UNKNOWN;
        decoder->set(decoder->ud, &k, &v);
        return SGE_OK;
    }

    if (type == FIELD_TYPE_INTEGER) {
        len = _decode_integer(decoder);
        v.t = FIELD_TYPE_LIST;
        v.v.i = len;
        if (NULL == (ud = decoder->set(decoder->ud, &k, &v))) {
            SGE_PROTO_ERROR_ARG(decoder->proto, SGE_ERR_ENCODE_ERROR, "get field(%s:%s) error.",
                                decoder->b->name, f->name);
            return SGE_ERROR;
        }

        old_ud = decoder->ud;
        decoder->ud = ud;
        k.t = f->type;
        for (i = 0; i < len; ++i) {
            k.idx = i;
            if (SGE_OK != (ret = _decode_normal(decoder, f, &k))) {
                return ret;
            }
        }
        decoder->ud = old_ud;
    }

    return ret;
}

static int _decode_field(struct sge_decoder *decoder, struct sge_field *field) {
    struct sge_key k;

    if (field->type & FIELD_TYPE_LIST) {
        return _decode_list(decoder, field);
    } else {
        k.t = field->type;
        return _decode_normal(decoder, field, &k);
    }
}

static int _do_decode(struct sge_decoder *decoder) {
    int ret = 0;
    int i = 0;
    long long bid = 0;
    struct sge_proto *p = decoder->proto;
    struct sge_block *bp = NULL, *old_bp = NULL;
    struct sge_field *f = NULL;

    bid = _decode_integer(decoder);
    ret = sge_find_array(p->blocks, bid, (void **)&bp);
    if (SGE_OK != ret) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_DECODE_ERROR, "not found block by bid(%lld).", bid);
        return SGE_ERROR;
    }

    old_bp = decoder->b;
    decoder->b = bp;
    for (i = 0; i < bp->count; ++i) {
        f = &bp->fields[i];
        if (SGE_OK != _decode_field(decoder, f)) {
            return SGE_ERROR;
        }
    }
    decoder->b = old_bp;

    return SGE_OK;
}

int sge_decode_proto(struct sge_proto *proto, uint8_t *bin, size_t len, void *ud,
                     sge_fn_set fn_set) {
    int ret = SGE_OK;
    struct sge_decoder decoder;

    if (NULL == proto || NULL == bin || len <= 0) {
        return SGE_ERROR;
    }

    if (SGE_OK != _verify_crc(bin, len)) {
        SGE_PROTO_ERROR_ARG(proto, SGE_ERR_DECODE_ERROR, "crc not match");
        return SGE_ERROR;
    }

    if (bin[2] != SGE_PROTO_VERSION) {
        SGE_PROTO_ERROR_ARG(proto, SGE_ERR_DECODE_ERROR, "version not match expect %d, got %d",
                            SGE_PROTO_VERSION, bin[2]);
        return SGE_ERROR;
    }

    decoder.b = NULL;
    decoder.proto = proto;
    decoder.cursor = 3;
    decoder.bin = bin;
    decoder.len = len;
    decoder.set = fn_set;
    decoder.ud = ud;

    return _do_decode(&decoder);
}
