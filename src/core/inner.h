#ifndef SGE_PROTOCOL_INNER_H_
#define SGE_PROTOCOL_INNER_H_

#include "protocol.h"

#define sge_malloc malloc
#define sge_free(p) free((void *)(p))

struct list
{
    struct list *next;
    struct list *prev;
};

#define sge_list_init(l) (l)->next = (l)->prev = (l)
#define sge_list_add(l, n)                                                                                             \
    {                                                                                                                  \
        (n)->next = (l);                                                                                               \
        (n)->prev = (l)->prev;                                                                                         \
        (l)->prev->next = (n);                                                                                         \
        (l)->prev = (n);                                                                                               \
    }
#define sge_list_remove(node)                                                                                          \
    {                                                                                                                  \
        (node)->prev->next = (node)->next;                                                                             \
        (node)->next->prev = (node)->prev;                                                                             \
    }
#define sge_list_empty(l) (l)->next == (l)
#define sge_container_of(ptr, type, member) (type *)((void *)(ptr) - (void *)(&(((type *)0)->member)))
#define sge_list_foreach(iter, list) for ((iter) = (list)->next; (iter) != (list); (iter) = (iter)->next)
#define sge_list_foreach_safe(iter, next, list)                                                                        \
    for ((iter) = (list)->next, (next) = (iter)->next; (iter) != (list); (iter) = (next), (next) = (next)->next)

#define base_filename(f) strrchr((f), '/')

// protocol error
#define HAS_ERROR(p) ((p)->code != 0)
#define SGE_PROTO_ERROR_MSG_LEN 128
#define SGE_PROTO_ERROR(p, c) sge_format_error((p), (c), NULL, NULL)
#define SGE_PROTO_ERROR_ARG(p, c, err, ...)                                                                            \
    sge_format_error((p), (c), "%s:%d: " err, base_filename(__FILE__), __LINE__, ##__VA_ARGS__)

// protocol define
#define SGE_BLOCK_MAX_BIT 30
#define SGE_BLOCK_MAX_NUMBER (1 << SGE_BLOCK_MAX_BIT)
#define SGE_FIELD_MAX_BIT 8
#define SGE_FIELD_MAX_NUMBER (1 << SGE_FIELD_MAX_BIT)

struct sge_radix;
struct sge_radix_iter
{
    struct sge_radix *rax;
};

struct sge_field
{
    unsigned int id : SGE_FIELD_MAX_BIT;  // field id
    unsigned int flags : 8;               // options
    unsigned int type : 8;                // type
    unsigned int tid : SGE_BLOCK_MAX_BIT; // custom block id
    unsigned int unused : 10;             // unused
    const char *name;                     // field name
};

struct sge_block
{
    unsigned int id : SGE_BLOCK_MAX_BIT; // block id
    unsigned int count : 8;              // number of field
    unsigned int unused : 26;            // unused
    const char *name;                    // block name
    struct sge_field *fields;            // field array
};

struct sge_proto
{
    int count;                    // block number
    struct sge_block **blocks;    // block array
    struct sge_radix *block_tree; // block radix tree
    struct
    {
        int code;
        char msg[SGE_PROTO_ERROR_MSG_LEN];
    } err; // error info
};

enum sge_field_flag
{
    FLAG_REQUIRED = 1 << 0,
    FLAG_OPTIONAL = 1 << 1,
    FLAG_UNKNOWN = 1 << 15
};

struct sge_proto *sge_parse_content(struct sge_proto *p, const char *content, size_t len, const char *filename);

void sge_format_error(struct sge_proto *p, int code, const char *fmt, ...);

struct sge_block *sge_find_block(struct sge_proto *p, const char *name, size_t len);

// radix
struct sge_radix *sge_create_radix(void);
int sge_insert_radix(struct sge_radix *rax, const char *s, size_t len, void *data);
int sge_remove_radix(struct sge_radix *rax, const char *s, size_t len, void **old);
void *sge_find_radix(struct sge_radix *rax, const char *s, size_t len);
void sge_destroy_radix(struct sge_radix *rax);

// radix iter
void sge_init_radix_iter(struct sge_radix_iter *iter, struct sge_radix *rax);
void *sge_next_radix_iter(struct sge_radix_iter *iter);
#endif
