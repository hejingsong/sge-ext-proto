#include <stdio.h>
#include <string.h>

#include "inner.h"

#define raxPadding(nodesize) \
  ((sizeof(void *) - ((nodesize + 4) % sizeof(void *))) & (sizeof(void *) - 1))

struct sge_radix_node {
  unsigned int iskey : 1;
  unsigned int iscompr : 1;
  unsigned int size : 30;
  unsigned char data[];
};

struct sge_radix {
  struct sge_radix_node *head;
  unsigned int count;
};

static struct sge_radix_node *_radix_alloc_node(size_t children,
                                                int datafield) {
  struct sge_radix_node *node = NULL;
  size_t nodesize = sizeof(struct sge_radix_node) + children +
                    raxPadding(children) +
                    sizeof(struct sge_radix_node *) * children;
  if (datafield) {
    nodesize += sizeof(void *);
  }

  node = sge_malloc(nodesize);
  if (node == NULL) {
    return NULL;
  }

  node->iskey = 0;
  node->iscompr = 0;
  node->size = children;
  return node;
}

struct sge_radix *sge_create_radix(void) {
  struct sge_radix *rax = NULL;

  rax = sge_malloc(sizeof(struct sge_radix));
  rax->count = 0;
  rax->head = _radix_alloc_node(0, 0);

  return rax;
}

int sge_insert_radix(struct sge_radix *rax, const char *s, size_t len,
                     void *data) {}

int sge_remove_radix(struct sge_radix *rax, const char *s, size_t len,
                     void **old) {}

void *sge_find_radix(struct sge_radix *rax, const char *s, size_t len) {}

void sge_destroy_radix(struct sge_radix *rax) {}

void sge_init_radix_iter(struct sge_radix_iter *iter, struct sge_radix *rax) {}
void *sge_next_radix_iter(struct sge_radix_iter *iter) { return NULL; }
