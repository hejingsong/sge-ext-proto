#include <string.h>

#include "inner.h"

int sge_compress_protocol(uint8_t* in, size_t inlen, uint8_t* out, size_t* outlen) {
    unsigned int move_step = 0;
    uint8_t* mask = out;
    uint8_t* cursor = out + 1;

    if (in == NULL || inlen == 0 || out == NULL) {
        return SGE_ERROR;
    }

    *mask = 0;
    while (inlen-- > 0) {
        if (move_step == PACK_UNIT_SIZE) {
            move_step = 0;
            mask = cursor;
            *mask = 0;
            cursor++;
        }
        if (*in) {
            *cursor = *in;
            cursor++;
            *mask |= (1 << move_step);
        }
        in++;
        move_step++;
    }

    *outlen = cursor - out;
    return SGE_OK;
}

int sge_decompress_protocol(uint8_t* in, size_t inlen, uint8_t** out, size_t* outlen) {
    int move_step = 0;
    uint8_t mask = *in;
    const uint8_t* in_cursor = in + 1;
    unsigned char c = 0;
    struct sge_proto_result result = {.data = NULL, .cap = 0, .len = 0};

    if (in == NULL || inlen == 0) {
        return SGE_ERROR;
    }

    while ((in_cursor - in) <= inlen) {
        c = mask & (0x01 << move_step);
        if (c) {
            sge_append_result(&result, in_cursor, 1);
            in_cursor++;
        } else {
            sge_append_result(&result, "\0", 1);
        }
        move_step++;
        if (move_step == PACK_UNIT_SIZE) {
            move_step = 0;
            mask = *in_cursor;
            in_cursor++;
        }
    }

    *outlen = result.len;
    *out = result.data;

    return SGE_OK;
}
