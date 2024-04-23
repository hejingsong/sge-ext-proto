#ifndef SGE_PROTOCOL_INNER_H_
#define SGE_PROTOCOL_INNER_H_

#include "protocol.h"
#include "rax.h"

#define sge_malloc malloc
#define sge_realloc realloc
#define sge_free(p) free((void *)(p))

// version
#define SGE_PROTO_MAJOR_VERSION 1
#define SGE_PROTO_MINOR_VERSION 1
#define SGE_PROTO_VERSION ((SGE_PROTO_MAJOR_VERSION << 4) | SGE_PROTO_MINOR_VERSION)

struct list {
    struct list *next;
    struct list *prev;
};

#define sge_list_init(l) (l)->next = (l)->prev = (l)
#define sge_list_add(l, n)     \
    {                          \
        (n)->next = (l);       \
        (n)->prev = (l)->prev; \
        (l)->prev->next = (n); \
        (l)->prev = (n);       \
    }
#define sge_list_remove(node)              \
    {                                      \
        (node)->prev->next = (node)->next; \
        (node)->next->prev = (node)->prev; \
    }
#define sge_list_empty(l) (l)->next == (l)
#define sge_container_of(ptr, type, member) \
    (type *)((void *)(ptr) - (void *)(&(((type *)0)->member)))
#define sge_list_foreach(iter, list) \
    for ((iter) = (list)->next; (iter) != (list); (iter) = (iter)->next)
#define sge_list_foreach_safe(iter, next, list)                          \
    for ((iter) = (list)->next, (next) = (iter)->next; (iter) != (list); \
         (iter) = (next), (next) = (next)->next)

#define base_filename(f) strrchr((f), '/')

// radix tree
typedef struct rax sge_radix;
#define sge_create_radix raxNew
#define sge_radix_size(r) raxSize((r))
#define sge_insert_radix(r, s, l, d) raxInsert((r), (s), (l), (d), NULL)
#define sge_remove_radix(r, s, l) raxRemove((r), (s), (l), NULL)
#define sge_find_radix(r, s, l) raxFind((r), (s), (l))
#define sge_destroy_radix(r) raxFree((r))

// radix iter
typedef struct raxIterator sge_radix_iter;
#define sge_init_radix_iter(r, i)   \
    {                               \
        raxStart((i), (r));         \
        raxSeek((i), "^", NULL, 0); \
    }
#define sge_next_radix_iter(i) raxNext((i))
#define sge_destroy_radix_iter(i) raxStop((i))
#define sge_radix_size(r) raxSize((r))

// array
typedef int (*fn_array_key)(void *);
struct sge_array;
struct sge_array *sge_create_array(size_t size, fn_array_key fn_key);
int sge_insert_array(struct sge_array *arr, void *data);
int sge_sort_array(struct sge_array *arr);
int sge_find_array(struct sge_array *arr, int key, void **data);
int sge_destroy_array(struct sge_array *arr);
void sge_print_array(struct sge_array *arr);

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

struct sge_proto {
    unsigned int count;        // block number
    struct sge_array *blocks;  // block array
    sge_radix *block_tree;     // block radix tree
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

#endif
