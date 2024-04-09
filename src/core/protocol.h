#ifndef SGE_PROTOCOL_H_
#define SGE_PROTOCOL_H_

#include <stdint.h>
#include <stdlib.h>

#define SGE_OK 0
#define SGE_ERROR -1

#if defined _WIN32 || defined __CYGWIN__
#ifdef BUILDING_DLL
#ifdef __GNUC__
#define DLL_PUBLIC __attribute__((dllexport))
#else
#define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
#endif
#else
#ifdef __GNUC__
#define DLL_PUBLIC __attribute__((dllimport))
#else
#define DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
#endif
#endif
#define DLL_LOCAL
#else
#if __GNUC__ >= 4
#define DLL_PUBLIC __attribute__((visibility("default")))
#define DLL_LOCAL __attribute__((visibility("hidden")))
#else
#define DLL_PUBLIC
#define DLL_LOCAL
#endif
#endif

DLL_PUBLIC struct sge_proto;

DLL_PUBLIC enum
{
    SGE_ERR_FILE_NOT_FOUND = 1,
    SGE_ERR_MEMORY_NOT_ENOUGH,
    SGE_ERR_PARSER_ERROR,
    SGE_ERR_BLOCK_NAME_NOT_FOUND,
    SGE_ERR_ENCODE_ERROR,
    SGE_ERR_DECODE_ERROR,
    SGE_ERR_ARG_ERROR
};

DLL_PUBLIC enum sge_field_type
{
    FIELD_TYPE_INTEGER = 1 << 0,
    FIELD_TYPE_STRING = 1 << 1,
    FIELD_TYPE_CUSTOM = 1 << 2,
    FIELD_TYPE_LIST = 1 << 6,
    FIELD_TYPE_UNKNOWN = 1 << 7
};

DLL_PUBLIC struct sge_value
{
    enum sge_field_type t; // field type
    union {
        long long i;
        struct
        {
            const char *s;
            size_t l;
        } s;
        void *a; // any
    } v;
};

DLL_PUBLIC struct sge_key
{
    unsigned char t;
    size_t idx;
    struct
    {
        const char *s;
        size_t l;
    } name;
};

typedef int (*sge_fn_get)(const void *, const struct sge_key *, struct sge_value *);
typedef void *(*sge_fn_set)(void *, const struct sge_key *, const struct sge_value *);

DLL_PUBLIC struct sge_proto *sge_parse(const char *content, size_t len);
DLL_PUBLIC struct sge_proto *sge_parse_file(const char *filename);
DLL_PUBLIC void sge_free_protocol(struct sge_proto *proto);

DLL_PUBLIC int sge_encode(struct sge_proto *proto, const char *name, const void *ud, sge_fn_get fn_get,
                          uint8_t *buffer);
DLL_PUBLIC int sge_decode(struct sge_proto *proto, uint8_t *bin, size_t len, void *ud, sge_fn_set fn_set);

// debug
DLL_PUBLIC int sge_protocol_error(struct sge_proto *proto, const char **err);
DLL_PUBLIC void sge_print_protocol(struct sge_proto *proto);

#endif
