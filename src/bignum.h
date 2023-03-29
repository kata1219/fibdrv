#ifndef __BIGNUM_H
#define __BIGNUM_H

#include <linux/module.h>
#include <linux/slab.h>

struct list_head *bignum_new(uint64_t value);

char *bignum_to_string(struct list_head *head);

void bignum_add(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res);
void bignum_sub(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res);

void bignum_mul(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res);

void bignum_lshift(struct list_head *head);

void bignum_swap(struct list_head *h1, struct list_head *h2);

char *bn_fast_doubling(long long fib);

#endif