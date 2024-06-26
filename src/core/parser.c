#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "inner.h"

#define NEWLINE_CHAR '\n'
#define COMMENT_CHAR '#'
#define UTF8_BOM_STR "\xEF\xBB\xBF"
#define LEFT_BODY_CHAR '{'
#define RIGHT_BODY_CHAR '}'
#define FIELD_DELIMITER ':'
#define FIELD_TERMINATOR ';'
#define UTF8_BOM_SIZE 3
#define REQ_LEFT_CHAR '('
#define REQ_RIGHT_CHAR ')'
#define RPC_RETURN_DELIMITER "->"

#define SGE_EOF(p) (*(p)->cursor == '\0')
#define VALID_NUMBER(c) ((c) >= 48 && (c) <= 57)
#define VALID_CHAR(c) (((c) >= 65 && (c) <= 90) || ((c) >= 97 && (c) <= 122) || ((c) == 95))
#define VERIFY_CHAR(c) (VALID_CHAR((c)) || VALID_NUMBER((c)))

#define APPEND_FIELD(h, f)                                                     \
    {                                                                          \
        struct list *__l = (struct list *)((char *)(f) - sizeof(struct list)); \
        sge_list_add((h), __l);                                                \
    }

#define DESTROY_FIELD(p, full)                                                           \
    {                                                                                    \
        struct sge_field *__f = (struct sge_field *)((char *)(p) + sizeof(struct list)); \
        _destroy_field(__f, (full));                                                     \
    }

static const char *FIELD_FLAGS[] = {"required", "optional", NULL};
static const char *FIELD_TYPES[] = {"integer", "string", NULL};

struct sge_parser {
    struct sge_proto *proto;
    const unsigned char *content;
    const unsigned char *cursor;
    const unsigned char *dir;
    const unsigned char *file;
    size_t size;
    size_t lineno;
};

static void _do_parse(struct sge_proto *p, const unsigned char *content, size_t len,
                      const char *filename);

static int _block_id(void *data) {
    struct sge_block *block = NULL;
    if (NULL == data) {
        return 0;
    }

    block = (struct sge_block *)data;
    return block->id;
}

struct sge_block *sge_find_block(struct sge_proto *p, const unsigned char *name, size_t len) {
    if (NULL == p || NULL == name || len == 0) {
        return NULL;
    }

    return (struct sge_block *)sge_find_radix(p->block_tree, (unsigned char *)name, len);
}

static void _move_cursor(struct sge_parser *parser) {
    char c = 0;

    parser->cursor++;
    c = *parser->cursor;
    if (c == NEWLINE_CHAR) {
        parser->lineno++;
        parser->cursor++;
    }
}

static void _filter_utf8_bom(struct sge_parser *parser) {
    if (strncmp(parser->cursor, UTF8_BOM_STR, UTF8_BOM_SIZE) == 0) {
        parser->cursor += UTF8_BOM_SIZE;
    }
}

static void _trim(struct sge_parser *parser) {
    char c = 0;

    while (!SGE_EOF(parser)) {
        c = *parser->cursor;
        if (c > 32) {
            break;
        }

        if (c == NEWLINE_CHAR) {
            parser->lineno++;
        }
        parser->cursor++;
    }
}

static void _filter_comment(struct sge_parser *parser) {
    char c = 0;
    char *p = NULL;

    while (!SGE_EOF(parser)) {
        _trim(parser);
        c = *parser->cursor;
        if (c == COMMENT_CHAR) {
            p = strchr(parser->cursor, NEWLINE_CHAR);
            if (p == NULL) {
                // the last line
                parser->cursor = parser->content + parser->size + 1;
                continue;
            }
            parser->cursor = p + 1;
            parser->lineno++;
        } else {
            break;
        }
    }
}

static size_t _parse_string(struct sge_parser *parser, const unsigned char **strp) {
    char c = 0;
    const unsigned char *p = NULL;
    size_t l = 0;

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        *strp = NULL;
        return l;
    }

    p = parser->cursor;
    c = *parser->cursor;
    while (c && VERIFY_CHAR(c)) {
        _move_cursor(parser);
        c = *parser->cursor;
    }

    l = parser->cursor - p;

    *strp = p;
    return l;
}

static struct sge_block *_alloc_block(int id, const char *name, size_t name_len, int nf,
                                      struct sge_field *fs) {
    struct sge_block *b = NULL;
    char *buf;

    buf = (char *)sge_malloc(name_len + 1);
    if (NULL == buf) {
        return NULL;
    }

    memcpy(buf, name, name_len);
    buf[name_len] = '\0';

    b = (struct sge_block *)sge_malloc(sizeof(*b));
    if (NULL == b) {
        goto err;
    }

    b->name = buf;
    b->fields = fs;
    b->count = nf;
    b->id = id;

    return b;
err:
    sge_free(buf);
    return NULL;
}

static void _destroy_block(struct sge_block *b) {
    int i = 0;

    if (NULL == b) {
        return;
    }

    for (i = 0; i < b->count; ++i) {
        sge_free(b->fields[i].name);
    }

    sge_free(b->fields);
    sge_free(b->name);
    sge_free(b);
}

static void _destroy_method(struct sge_method *method) {
    if (NULL == method) {
        return;
    }

    sge_free(method);
}

static void _destroy_service(struct sge_service *service) {
    sge_radix_iter rax_iter;
    struct sge_method *method = NULL;

    if (NULL == service) {
        return;
    }

    sge_init_radix_iter(service->methods, &rax_iter);
    while (sge_next_radix_iter(&rax_iter)) {
        method = (struct sge_method *)rax_iter.data;
        _destroy_method(method);
    }
    sge_destroy_radix_iter(&rax_iter);
    sge_free(service);
}

static int _alloc_service(struct sge_service **service, const unsigned char *name,
                          size_t name_len) {
    struct sge_service *s = NULL;
    size_t alloc_size = sizeof(struct sge_service) + sizeof(unsigned char) * (name_len + 1);

    s = sge_malloc(alloc_size);
    if (NULL == s) {
        return SGE_ERROR;
    }
    memset(s, 0, alloc_size);
    memcpy(s->name, name, name_len);

    s->methods = sge_create_radix();
    if (NULL == s->methods) {
        sge_free(s);
        return SGE_ERROR;
    }

    *service = s;
    return SGE_OK;
}

static int _alloc_method(struct sge_method **method, const unsigned char *name, size_t name_len) {
    struct sge_method *m = NULL;
    size_t alloc_size = sizeof(struct sge_method) + sizeof(unsigned char) * (name_len + 1);

    m = sge_malloc(alloc_size);
    if (NULL == m) {
        return SGE_ERROR;
    }
    memset(m, 0, alloc_size);
    memcpy(m->name, name, name_len);

    *method = m;
    return SGE_OK;
}

static int _field_flag(const unsigned char *flag, const size_t fl) {
    int i = 0;
    const unsigned char *p = NULL;

    if (0 == fl) {
        return FLAG_OPTIONAL;
    }

    while (FIELD_FLAGS[i]) {
        p = FIELD_FLAGS[i];
        if (0 == strncmp(p, flag, fl)) {
            return 1 << i;
        }
        ++i;
    }

    return FLAG_UNKNOWN;
}

static size_t _parse_block_name(struct sge_parser *parser, const unsigned char **namep) {
    char c = 0;
    size_t len = 0;
    const unsigned char *name = NULL;

    _filter_comment(parser);

    if (SGE_EOF(parser)) {
        goto out;
    }

    c = *parser->cursor;
    if (VALID_NUMBER(c)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid block name at line: %lu",
                            parser->lineno);
        goto out;
    }

    len = _parse_string(parser, &name);
    if (0 == len) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "can't found block name at line: %lu", parser->lineno);
        goto out;
    }

out:
    *namep = name;
    return len;
}

static void _parse_block_id(struct sge_parser *parser, int *idp) {
    char c = 0;
    int id = 0;
    size_t len = 0;
    const unsigned char *start = NULL;
    char s[24] = {0};

    _filter_comment(parser);

    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "incomplete block at line: %lu",
                            parser->lineno);
        goto out;
    }

    c = *parser->cursor;
    if (!VALID_NUMBER(c)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid block id at line: %lu",
                            parser->lineno);
        goto out;
    }

    start = parser->cursor;
    while (c && VALID_NUMBER(c)) {
        _move_cursor(parser);
        c = *parser->cursor;
    }

    if (start == parser->cursor) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "can't found block id at line: %lu", parser->lineno);
        goto out;
    }

    len = parser->cursor - start;
    memcpy(s, start, len);
    s[len] = '\0';
    id = atoi(s);

    if (id <= 0 || id > SGE_BLOCK_MAX_NUMBER) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "block id must be greater than 0 and less then %d at line: %lu",
                            parser->lineno, SGE_BLOCK_MAX_NUMBER);
        id = 0;
        goto out;
    }

out:
    *idp = id;
}

static int _field_type(const char *type, const size_t tl) {
    int i = 0;
    const char *p = NULL;

    if (0 == tl) {
        return FIELD_TYPE_UNKNOWN;
    }

    while (FIELD_TYPES[i]) {
        p = FIELD_TYPES[i];
        if (0 == strncmp(p, type, tl)) {
            return 1 << i;
        }
        i++;
    }

    return FIELD_TYPE_UNKNOWN;
}

static struct sge_field *_alloc_field(void) {
    struct list *f = NULL;

    f = (struct list *)sge_malloc(sizeof(struct list) + sizeof(struct sge_field));
    if (NULL == f) {
        return NULL;
    }

    sge_list_init(f);
    return (struct sge_field *)(f + 1);
}

static void _destroy_field(struct sge_field *f, int full) {
    void *p = NULL;
    if (NULL == f) {
        return;
    }

    if (full) {
        sge_free(f->name);
    }
    p = (struct list *)f - 1;
    sge_free(p);
}

static struct sge_field *_parse_field(struct sge_parser *parser) {
    int type = 0, flags = 0;
    char c = 0, is_arr = 0;
    struct sge_field *field = NULL;
    struct sge_block *block = NULL;
    struct sge_proto *p = parser->proto;
    size_t nl = 0, fl = 0, tl = 0;
    const unsigned char *name = NULL, *f = NULL, *t = NULL;
    unsigned char *str = NULL;

    // parse field name
    nl = _parse_string(parser, &name);
    if (0 == nl) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid field name at line: %lu",
                            parser->lineno);
        return NULL;
    }

    // parse field type
    tl = _parse_string(parser, &t);
    if (0 == tl) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid field type at line: %lu",
                            parser->lineno);
        return NULL;
    }

    type = _field_type(t, tl);
    if (type & FIELD_TYPE_UNKNOWN) {
        block = sge_find_block(p, t, tl);
        if (NULL == block) {
            SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "unknown field type: %.*s at line: %lu",
                                tl, t, parser->lineno);
            return NULL;
        }
        type = FIELD_TYPE_CUSTOM;
    }
    if (0 == strncmp(parser->cursor, "[]", 2)) {
        is_arr = 1;
        parser->cursor += 2;
    }
    if (is_arr) {
        type |= FIELD_TYPE_LIST;
    }

    // parse field flag
    // fl == 0 mean optional
    fl = _parse_string(parser, &f);
    flags = _field_flag(f, fl);
    if (flags == FLAG_UNKNOWN) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "unknown field flag at line: %lu",
                            parser->lineno);
        return NULL;
    }

    // parse field end
    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return NULL;
    }
    c = *parser->cursor;
    if (c != FIELD_TERMINATOR) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return NULL;
    }
    _move_cursor(parser);

    str = (unsigned char *)sge_malloc(nl + 1);
    if (NULL == str) {
        SGE_PROTO_ERROR(p, SGE_ERR_MEMORY_NOT_ENOUGH);
        return NULL;
    }
    memcpy(str, name, nl);
    str[nl] = '\0';

    field = _alloc_field();
    if (NULL == field) {
        sge_free(str);
        SGE_PROTO_ERROR(p, SGE_ERR_MEMORY_NOT_ENOUGH);
        return NULL;
    }

    field->name = str;
    field->flags = flags;
    field->type = type;
    field->id = 0;
    field->tid = 0;
    if (block) {
        field->tid = block->id;
    }

    return field;
}

static void _parse_message_body(struct sge_parser *parser, int *nfp, struct sge_field **fsp) {
    int nf = 0;
    char c = 0, fin = 0;
    struct sge_field *f = NULL, *farr = NULL;
    struct list fl, *iter = NULL, *next = NULL;

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "undefined block body at line: %lu", parser->lineno);
        return;
    }

    c = *parser->cursor;
    if (c != LEFT_BODY_CHAR) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return;
    }

    sge_list_init(&fl);
    _move_cursor(parser);
    while (!SGE_EOF(parser)) {
        _filter_comment(parser);
        c = *parser->cursor;
        if (c == RIGHT_BODY_CHAR) {
            fin = 1;
            _move_cursor(parser);
            break;
        }

        f = _parse_field(parser);
        if (NULL == f) {
            break;
        }

        f->id = nf;
        nf += 1;
        APPEND_FIELD(&fl, f);
    }

    if (fin == 0) {
        goto err;
    }

    if (nf > SGE_FIELD_MAX_NUMBER) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "field size must less then: %d, current %d", SGE_FIELD_MAX_NUMBER, nf);
        goto err;
    }

    *nfp = nf;
    if (nf == 0) {
        *fsp = NULL;
    } else {
        *fsp = farr = (struct sge_field *)sge_malloc(sizeof(struct sge_field) * nf);

        sge_list_foreach_safe(iter, next, &fl) {
            f = (struct sge_field *)((char *)iter + sizeof(struct list));
            memcpy(farr, f, sizeof(struct sge_field));
            farr += 1;

            sge_list_remove(iter);
            DESTROY_FIELD(iter, 0);
        }
        return;
    }

err:
    sge_list_foreach_safe(iter, next, &fl) {
        sge_list_remove(iter);
        DESTROY_FIELD(iter, 1);
    }

    *nfp = 0;
    *fsp = NULL;
}

static int _parse_service_method(struct sge_parser *parser, struct sge_method **method) {
    int type = 0, flags = 0, ret = 0;
    unsigned char c = 0;
    struct sge_proto *p = parser->proto;
    size_t len = 0, name_len = 0, req_block_len = 0, resp_block_len = 0;
    const unsigned char *name = NULL, *req_block_name = NULL, *resp_block_name = NULL;
    const unsigned char *str = NULL;
    struct sge_block *req_block = NULL, *resp_block = NULL;
    struct sge_method *mp = NULL;

    // parse rpc keyword
    len = _parse_string(parser, &str);
    if (0 == len) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return SGE_ERROR;
    }

    if (strncmp(str, SGE_RPC_KEYWORD, len) != 0) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "invalid syntax at %s(%lu), not found rpc keyword", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }

    // parse method name
    name_len = _parse_string(parser, &name);
    if (0 == name_len) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid method name at line: %lu",
                            parser->lineno);
        return SGE_ERROR;
    }

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }

    c = *parser->cursor;
    if (c != REQ_LEFT_CHAR) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }
    _move_cursor(parser);

    // parse request block name
    req_block_len = _parse_string(parser, &req_block_name);
    if (0 == req_block_len) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid request block name at line: %lu",
                            parser->lineno);
        return SGE_ERROR;
    }
    req_block = sge_find_radix(p->block_tree, (unsigned char *)req_block_name, req_block_len);
    if (NULL == req_block) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "block(%.*s) not found at %s:%lu",
                            req_block_len, req_block_name, parser->file, parser->lineno);
        return SGE_ERROR;
    }

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }

    c = *parser->cursor;
    if (c != REQ_RIGHT_CHAR) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }
    _move_cursor(parser);

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }

    if (strncmp(parser->cursor, RPC_RETURN_DELIMITER, 2) != 0) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }
    _move_cursor(parser);
    _move_cursor(parser);

    // parse response block name
    resp_block_len = _parse_string(parser, &resp_block_name);
    if (0 == resp_block_len) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid response block name at line: %lu",
                            parser->lineno);
        return SGE_ERROR;
    }

    resp_block = sge_find_radix(p->block_tree, (unsigned char *)resp_block_name, resp_block_len);
    if (NULL == resp_block) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "block(%.*s) not found at %s:%lu",
                            resp_block_len, resp_block_name, parser->file, parser->lineno);
        return SGE_ERROR;
    }

    // parse field end
    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }
    c = *parser->cursor;
    if (c != FIELD_TERMINATOR) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)", parser->file,
                            parser->lineno);
        return SGE_ERROR;
    }
    _move_cursor(parser);

    ret = _alloc_method(&mp, name, name_len);
    if (SGE_ERROR == ret) {
        SGE_PROTO_ERROR(p, SGE_ERR_MEMORY_NOT_ENOUGH);
        return SGE_ERROR;
    }
    mp->req = req_block;
    mp->resp = resp_block;
    *method = mp;

    return SGE_OK;
}

static int _parse_service_body(struct sge_parser *parser, struct sge_service *service) {
    int ret = 0;
    unsigned char c = 0, fin = 0;
    struct sge_method *method = NULL;

    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR,
                            "undefined block body at line: %lu", parser->lineno);
        return SGE_ERROR;
    }

    c = *parser->cursor;
    if (c != LEFT_BODY_CHAR) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return SGE_ERROR;
    }

    _move_cursor(parser);
    while (!SGE_EOF(parser)) {
        _filter_comment(parser);
        c = *parser->cursor;
        if (c == RIGHT_BODY_CHAR) {
            fin = 1;
            _move_cursor(parser);
            break;
        }

        ret = _parse_service_method(parser, &method);
        if (SGE_OK != ret) {
            return SGE_ERROR;
        }

        sge_insert_radix(service->methods, method->name, strlen(method->name), (void *)method);
    }
}

static struct sge_block *_parse_one_message(struct sge_parser *parser) {
    int block_id = 0;
    int nf = 0;
    size_t name_len = 0;
    const unsigned char *name = NULL;
    struct sge_field *fields = NULL;
    struct sge_block *block = NULL;
    struct sge_proto *p = parser->proto;

    name_len = _parse_block_name(parser, &name);
    if (HAS_ERROR(&p->err)) {
        return NULL;
    }

    if (sge_find_radix(p->block_tree, (unsigned char *)name, name_len)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "block(%.*s) already exists at %s:%lu",
                            name_len, name, parser->file, parser->lineno);
        return NULL;
    }

    _parse_block_id(parser, &block_id);
    if (HAS_ERROR(&p->err)) {
        return NULL;
    }

    _parse_message_body(parser, &nf, &fields);
    if (HAS_ERROR(&p->err)) {
        return NULL;
    }

    block = _alloc_block(block_id, name, name_len, nf, fields);
    if (NULL == block) {
        SGE_PROTO_ERROR(p, SGE_ERR_MEMORY_NOT_ENOUGH);
        return NULL;
    }

    return block;
}

static struct sge_service *_parse_one_service(struct sge_parser *parser) {
    int ret = 0;
    size_t name_len = 0;
    const unsigned char *name = NULL;
    struct sge_proto *p = parser->proto;
    struct sge_service *service = NULL;

    name_len = _parse_block_name(parser, &name);
    if (HAS_ERROR(&p->err)) {
        return NULL;
    }

    if (sge_find_radix(p->service_tree, (unsigned char *)name, name_len)) {
        SGE_PROTO_ERROR_ARG(p, SGE_ERR_PARSER_ERROR, "service(%.*s) already exists at %s:%lu",
                            name_len, name, parser->file, parser->lineno);
        return NULL;
    }

    ret = _alloc_service(&service, name, name_len);
    if (SGE_ERROR == ret) {
        SGE_PROTO_ERROR(p, SGE_ERR_MEMORY_NOT_ENOUGH);
        return NULL;
    }

    ret = _parse_service_body(parser, service);
    if (SGE_ERROR == ret) {
        _destroy_service(service);
        return NULL;
    }

    return service;
}

static int _parse_one_block(struct sge_parser *parser, struct sge_block **blockp,
                            struct sge_service **servicep) {
    size_t bt_len = 0;
    const unsigned char *bt = NULL;
    struct sge_block *block = NULL;
    struct sge_service *service = NULL;
    struct sge_proto *p = parser->proto;

    bt_len = _parse_block_name(parser, &bt);
    if (HAS_ERROR(&p->err)) {
        return SGE_ERROR;
    }

    if (strncmp(bt, SGE_SERVICE_KEYWORD, bt_len) == 0) {
        service = _parse_one_service(parser);
        if (NULL == service) {
            return SGE_ERROR;
        }
        *servicep = service;
        return BLOCK_TYPE_SERVICE;
    } else if (strncmp(bt, SGE_MESSAGE_KEYWORD, bt_len) == 0) {
        block = _parse_one_message(parser);
        if (NULL == block) {
            return SGE_ERROR;
        }
        *blockp = block;
        return BLOCK_TYPE_MESSAGE;
    } else {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "unknown block type(%.*s) at %s:%lu",
                            bt_len, bt, parser->file, parser->lineno);
        return SGE_ERROR;
    }
}

static void _parse_include(struct sge_parser *parser) {
    char c;
    int len = 0;
    const unsigned char *start = NULL;
    char filename[FILENAME_MAX];

    if (0 != strncmp(parser->cursor, "@include", 8)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return;
    }

    parser->cursor += 8;
    _filter_comment(parser);
    if (SGE_EOF(parser)) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return;
    }

    c = *parser->cursor;
    if ('\'' != c && '"' != c) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return;
    }

    parser->cursor += 1;
    start = parser->cursor;
    while (!SGE_EOF(parser)) {
        c = *parser->cursor;
        if ('\'' == c || '"' == c) {
            break;
        }
        _move_cursor(parser);
    }
    len = parser->cursor - start;
    if (len == 0) {
        SGE_PROTO_ERROR_ARG(parser->proto, SGE_ERR_PARSER_ERROR, "invalid syntax at %s(%lu)",
                            parser->file, parser->lineno);
        return;
    }

    _move_cursor(parser);
    if (*start == '/') {
        strncpy(filename, start, len);
    } else {
        len = snprintf(filename, FILENAME_MAX, "%s/%.*s", parser->dir, len, start);
    }
    filename[len] = '\0';

    _do_parse(parser->proto, NULL, 0, filename);
}

static void _do_parse(struct sge_proto *p, const unsigned char *content, size_t len,
                      const char *filename) {
    int ret = 0;
    int block_type = 0;
    struct stat s;
    FILE *fp = NULL;
    unsigned char *buffer = NULL;
    unsigned char *realfile = NULL;
    unsigned char curdir[FILENAME_MAX];
    const unsigned char *dir = NULL;
    struct sge_parser parser, *cur = NULL;
    struct sge_block *block = NULL;
    struct sge_service *service = NULL;
    sge_radix_iter rax_iter;

    if (filename) {
        realfile = strdup(filename);
        ret = stat(realfile, &s);
        if (ret != 0) {
            SGE_PROTO_ERROR(p, SGE_ERR_FILE_NOT_FOUND);
            return;
        }

        len = s.st_size;
        buffer = sge_malloc(len + 1);
        fp = fopen(realfile, "r");
        fread(buffer, len, 1, fp);
        fclose(fp);
        buffer[len] = '\0';

        parser.file = basename(realfile);
        if (realfile[0] == '/') {
            dir = dirname(realfile);
        } else {
            dir = getcwd(curdir, FILENAME_MAX);
            strcat(curdir, "/");
            strcat(curdir, dirname(realfile));
        }
        parser.dir = dir;
    } else {
        buffer = (unsigned char *)content;
    }

    if (NULL == buffer || len == 0) {
        SGE_PROTO_ERROR(p, SGE_ERR_ARG_ERROR);
        return;
    }

    parser.proto = p;
    parser.cursor = parser.content = (const unsigned char *)buffer;
    parser.lineno = 1;
    parser.size = len;
    cur = &parser;

    _filter_utf8_bom(cur);
    while (!SGE_EOF(cur) && !HAS_ERROR(&p->err)) {
        _filter_comment(cur);
        if (SGE_EOF(cur)) {
            break;
        }

        if ('@' == *cur->cursor) {
            _parse_include(cur);
        }

        _filter_comment(cur);
        if (SGE_EOF(cur)) {
            break;
        }

        block_type = _parse_one_block(cur, &block, &service);
        if (SGE_ERROR == block_type) {
            goto err;
        }

        if (BLOCK_TYPE_MESSAGE == block_type) {
            p->count += 1;
            sge_insert_radix(p->block_tree, (unsigned char *)block->name, strlen(block->name),
                             block);
        } else if (BLOCK_TYPE_SERVICE == block_type) {
            sge_insert_radix(p->service_tree, (unsigned char *)service->name, strlen(service->name),
                             service);
        }
    }

out:
    if (buffer != content) {
        sge_free(buffer);
    }
    if (realfile) {
        sge_free(realfile);
    }
    return;
err:
    sge_init_radix_iter(p->block_tree, &rax_iter);
    while (sge_next_radix_iter(&rax_iter)) {
        block = (struct sge_block *)rax_iter.data;
        _destroy_block(block);
    }
    sge_destroy_radix_iter(&rax_iter);

    sge_init_radix_iter(p->service_tree, &rax_iter);
    while (sge_next_radix_iter(&rax_iter)) {
        service = (struct sge_service *)rax_iter.data;
        _destroy_service(service);
    }
    sge_destroy_radix_iter(&rax_iter);
    goto out;
}

struct sge_proto *sge_parse_content(struct sge_proto *p, const unsigned char *content, size_t len,
                                    const char *filename) {
    struct sge_block *block = NULL;
    sge_radix_iter rax_iter;

    _do_parse(p, content, len, filename);

    if (SGE_OK == p->err.code) {
        p->blocks = sge_create_array(sge_radix_size(p->block_tree), _block_id);
        if (NULL == p->blocks) {
            goto out;
        }
        sge_init_radix_iter(p->block_tree, &rax_iter);
        while (sge_next_radix_iter(&rax_iter)) {
            block = (struct sge_block *)rax_iter.data;
            sge_insert_array(p->blocks, (void *)block);
        }
        sge_sort_array(p->blocks);
        sge_destroy_radix_iter(&rax_iter);
    }

out:
    return p;
}
