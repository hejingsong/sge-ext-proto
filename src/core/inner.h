#ifndef SGE_PROTOCOL_INNER_H_
#define SGE_PROTOCOL_INNER_H_

#include "array.h"
#include "list.h"
#include "protocol.h"
#include "rax.h"
#include "sge.h"

// version
#define SGE_PROTO_MAJOR_VERSION 1
#define SGE_PROTO_MINOR_VERSION 1
#define SGE_PROTO_VERSION ((SGE_PROTO_MAJOR_VERSION << 4) | SGE_PROTO_MINOR_VERSION)

#define base_filename(f) strrchr((f), '/')

// protocol error
#define HAS_ERROR(p) ((p)->code != 0)
#define SGE_PROTO_ERROR_MSG_LEN 128
#define SGE_PROTO_ERROR(p, c) sge_format_error((p), (c), NULL, NULL)
#define SGE_PROTO_ERROR_ARG(p, c, err, ...) \
    sge_format_error((p), (c), "%s:%d: " err, base_filename(__FILE__), __LINE__, ##__VA_ARGS__)

// protocol define
#define SGE_BLOCK_MAX_BIT 30
#define SGE_BLOCK_MAX_NUMBER (1 << SGE_BLOCK_MAX_BIT)
#define SGE_FIELD_MAX_BIT 8
#define SGE_FIELD_MAX_NUMBER (1 << SGE_FIELD_MAX_BIT)

struct sge_field {
    unsigned int id : SGE_FIELD_MAX_BIT;   // field id
    unsigned int flags : 8;                // options
    unsigned int type : 8;                 // type
    unsigned int tid : SGE_BLOCK_MAX_BIT;  // custom block id
    unsigned int unused : 10;              // unused
    const unsigned char *name;             // field name
};

struct sge_block {
    unsigned int id : SGE_BLOCK_MAX_BIT;  // block id
    unsigned int count : 8;               // number of field
    unsigned int unused : 26;             // unused
    const unsigned char *name;            // block name
    struct sge_field *fields;             // field array
};

#define SGE_SERVICE_KEYWORD "service"
#define SGE_MESSAGE_KEYWORD "message"
#define SGE_RPC_KEYWORD "rpc"
struct sge_method {
    struct sge_block *req;   // request block
    struct sge_block *resp;  // response block
    unsigned char name[0];   // method name
};

struct sge_service {
    sge_radix *methods;     // methods radix tree
    unsigned char name[0];  // service name
};

enum sge_block_type { BLOCK_TYPE_MESSAGE = 1, BLOCK_TYPE_SERVICE = 2 };

struct sge_proto {
    unsigned int count;        // block number
    struct sge_array *blocks;  // block array
    sge_radix *block_tree;     // block radix tree
    sge_radix *service_tree;   // service radix tree
    struct {
        int code;
        char msg[SGE_PROTO_ERROR_MSG_LEN];
    } err;  // error info
};

enum sge_field_flag { FLAG_REQUIRED = 1 << 0, FLAG_OPTIONAL = 1 << 1, FLAG_UNKNOWN = 1 << 15 };

struct sge_proto *sge_parse_content(struct sge_proto *p, const unsigned char *content, size_t len,
                                    const char *filename);

void sge_format_error(struct sge_proto *p, int code, const char *fmt, ...);

struct sge_block *sge_find_block(struct sge_proto *p, const unsigned char *name, size_t len);

// encode/decode
#define SGE_INTEGER_SIZE 8
int sge_encode_proto(struct sge_proto *proto, const unsigned char *name, const void *ud,
                     sge_fn_get fn_get, uint8_t **buffer, size_t *len);
int sge_decode_proto(struct sge_proto *proto, uint8_t *bin, size_t len, void *ud,
                     sge_fn_set fn_set);

// compress/decompress
#define PACK_UNIT_SIZE 8
int sge_compress_protocol(uint8_t *in, size_t inlen, uint8_t *out, size_t *outlen);
int sge_decompress_protocol(uint8_t *in, size_t inlen, uint8_t **out, size_t *outlen);

// crc16
static uint16_t _crc16(const uint8_t *data, size_t len) {
    static const int POLYNOMIAL = 0x1021;
    size_t i = 0, j = 0;
    int val = 0;
    uint16_t crc16 = 0;

    for (i = 0; i < len; i++) {
        val = data[i] << 8;
        for (j = 0; j < 8; j++) {
            if ((crc16 ^ val) & 0x8000) {
                crc16 = (crc16 << 1) ^ POLYNOMIAL;
            } else {
                crc16 <<= 1;
            }
            val <<= 1;
        }
    }

    return crc16;
}

// protocol result
#define SGE_INIT_RESULT_DATA_LEN 64
struct sge_proto_result {
    uint8_t *data;
    size_t cap;
    size_t len;
};
int sge_append_result(struct sge_proto_result *r, const uint8_t *str, size_t len);
int sge_destroy_result(struct sge_proto_result *r);

// service
int sge_encode_service(struct sge_proto *proto, const unsigned char *service,
                       const unsigned char *method, const void *ud, sge_fn_get fn_get,
                       enum sge_encode_type encode_type, uint8_t **buffer, size_t *len);
int sge_decode_service(struct sge_proto *proto, uint8_t *bin, size_t len, void *ud,
                       sge_fn_set fn_set, unsigned char *service, unsigned char *method);
#endif
