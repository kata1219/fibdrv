#include "bignum.h"

typedef struct {
    size_t len;
    struct list_head link;
} bignum_head;

typedef struct {
    uint64_t value;
    struct list_head link;
} bignum_node;


#define NEW_NODE(head, val)                                           \
    ({                                                                \
        bignum_node *node = kmalloc(sizeof(bignum_node), GFP_KERNEL); \
        if (node) {                                                   \
            list_entry(head, bignum_head, link)->len++;               \
            node->value = val;                                        \
            list_add_tail(&node->link, head);                         \
        }                                                             \
    })

#define MAX_DIGITS 18
#define BOUND64 1000000000000000000UL

// input value should less than BOUND64
struct list_head *bignum_new(uint64_t value)
{
    bignum_head *big_head = kmalloc(sizeof(bignum_head), GFP_KERNEL);

    if (!big_head) {
        return NULL;
    }

    INIT_LIST_HEAD(&big_head->link);
    big_head->len = 0;
    NEW_NODE(&big_head->link, value);

    return &big_head->link;
}

void bignum_free(struct list_head *head)
{
    bignum_head *big_head = list_entry(head, bignum_head, link);
    for (struct list_head *tmp = head->next, *safe = tmp->next; tmp != head;
         tmp = safe, safe = safe->next) {
        bignum_node *n = list_entry(tmp, bignum_node, link);
        kfree(n);
    }
    kfree(big_head);
}

/*
 * output bignum to decimal string
 * Note: the returned string should be freed with kfree()
 */
char *bignum_to_string(struct list_head *head)
{
    int bignum_len = list_entry(head, bignum_head, link)->len;
    int first_size = snprintf(NULL, 0, "%llu",
                              list_entry(head->prev, bignum_node, link)->value);
    int digit = first_size + (bignum_len - 1) * 18;
    char *bignum_string = kmalloc(digit + 1, GFP_KERNEL);
    bignum_string[digit] = '\0';
    int bit_pos = digit - 1;

    bignum_node *n = NULL;
    list_for_each_entry (n, head, link) {
        uint64_t value = n->value;
        int size = (n == list_entry(head->prev, bignum_node, link))
                       ? first_size
                       : MAX_DIGITS;
        for (int count = 0; count < size; count++) {
            bignum_string[bit_pos--] = value % 10 + '0';
            if (value > 0)
                value /= 10;
        }
    }

    return bignum_string;
}

void bignum_add(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res)
{
    struct list_head **l = &lgr->next, **s = &slr->next, **r = &res->next;

    for (bool carry = 0;; l = &(*l)->next, s = &(*s)->next, r = &(*r)->next) {
        if (*l == lgr) {
            if (carry)
                NEW_NODE(res, 1);
            break;
        }

        uint64_t sml =
            (*s == slr) ? 0 : list_entry(*s, bignum_node, link)->value;
        uint64_t sum = list_entry(*l, bignum_node, link)->value + sml + carry;
        carry = 0;
        if (sum >= BOUND64) {
            sum -= BOUND64;
            carry = 1;
        }

        if (*r == res)
            NEW_NODE(res, 0);
        bignum_node *rentry = list_entry(*r, bignum_node, link);
        rentry->value = sum;
    }
}

void bignum_sub(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res)
{
    struct list_head **l = &lgr->next, **s = &slr->next, **r = &res->next;

    for (bool bank = 0;; l = &(*l)->next, s = &(*s)->next, r = &(*r)->next) {
        if (*l == lgr)
            break;

        uint64_t sum = list_entry(*l, bignum_node, link)->value - bank;
        uint64_t sml =
            (*s == slr) ? 0 : list_entry(*s, bignum_node, link)->value;

        if (sum == sml)
            break;

        bank = 0;
        if (sum < sml) {
            sum += (BOUND64 - sml);
            bank = 1;
        } else {
            sum -= sml;
        }

        if (*r == res)
            NEW_NODE(res, 0);
        bignum_node *rentry = list_entry(*r, bignum_node, link);
        rentry->value = sum;
    }
}

void bignum_mul(struct list_head *lgr,
                struct list_head *slr,
                struct list_head *res)
{
    struct list_head **l = &lgr->next, **s = &slr->next, **r = &res->next;

    for (uint64_t left_sum = 0, carry_sum = 0;;
         l = &(*l)->next, s = &(*s)->next, r = &(*r)->next) {
        if (*s == slr)
            break;

        bignum_node *n;
        int l_size = list_entry(lgr, bignum_head, link)->len;
        struct list_head *tmp_r = *r;

        list_for_each_entry (n, lgr, link) {
            uint64_t lge = n->value,
                     sml = list_entry(*s, bignum_node, link)->value;
            left_sum = 0;
            for (uint64_t last, mask = BOUND64, shift = 1; sml > 0;
                 shift *= 10, mask /= 10, sml /= 10) {
                last = (sml % 10) * lge;
                if (last >= mask) {
                    carry_sum += last / mask;
                    last %= mask;
                }
                left_sum += last * shift;
                if (left_sum >= BOUND64) {
                    carry_sum += left_sum / BOUND64;
                    left_sum %= BOUND64;
                }
            }

            bignum_node *rentry = list_entry(tmp_r, bignum_node, link);  // left
            rentry->value += left_sum;
            if (rentry->value >= BOUND64) {
                carry_sum += rentry->value / BOUND64;
                rentry->value %= BOUND64;
            }

            if ((--l_size > 0 || carry_sum > 0) && tmp_r->next == res)
                NEW_NODE(res, 0);

            bignum_node *centry =
                list_entry(tmp_r->next, bignum_node, link);  // carry
            centry->value += carry_sum;
            carry_sum = 0;
            if (centry->value >= BOUND64) {
                carry_sum = centry->value / BOUND64;
                centry->value %= BOUND64;
            }
            tmp_r = tmp_r->next;
        }
    }
}

void bignum_lshift(struct list_head *head)
{
    bool carry = 0;

    bignum_node *n = NULL;
    list_for_each_entry (n, head, link) {
        n->value = (n->value << 1) + carry;
        carry = 0;
        if (n->value >= BOUND64) {
            n->value -= BOUND64;
            carry = 1;
        }
    }
    if (carry) {
        NEW_NODE(head, 1);
    }
}

void bignum_swap(struct list_head *h1, struct list_head *h2)
{
    struct list_head *h1_prev = h1->prev;
    struct list_head *h2_prev = h2->prev;
    bignum_head *first = list_entry(h1, bignum_head, link);
    bignum_head *second = list_entry(h2, bignum_head, link);

    int tmp = first->len;
    first->len = second->len;
    second->len = tmp;

    list_del_init(h1);
    list_del_init(h2);
    list_add(h2, h1_prev);
    list_add(h1, h2_prev);
}

char *bn_fast_doubling(long long fib)
{
    long long f = fib;
    int clz = (fib == 0) ? 64 : __builtin_clzll(f);
    int left = 64 - clz;
    f <<= __builtin_clzll(f);
    struct list_head *a_n1 = bignum_new(0), *b_n1 = bignum_new(1);
    struct list_head *tmp[6];

    while (left--) {
        bool bit = (f & 0x8000000000000000);
        f <<= 1;

        for (int i = 0; i < 6; i++) {
            tmp[i] = bignum_new(0);
        }

        if (!bit)  // if bit == 0, a = n, b = n+1
        {
            bignum_mul(b_n1, b_n1, tmp[0]);
            bignum_mul(a_n1, a_n1, tmp[1]);
            bignum_add(tmp[0], tmp[1], tmp[2]);
            bignum_lshift(b_n1);
            bignum_sub(b_n1, a_n1, tmp[3]);
            bignum_mul(tmp[3], a_n1, tmp[4]);
            bignum_swap(b_n1, tmp[2]);
            bignum_swap(a_n1, tmp[4]);
        } else  // if bit == 1, a = n+1, b = n+2
        {
            bignum_mul(b_n1, b_n1, tmp[0]);
            bignum_mul(a_n1, a_n1, tmp[1]);
            bignum_add(tmp[0], tmp[1], tmp[2]);
            bignum_lshift(b_n1);
            bignum_sub(b_n1, a_n1, tmp[3]);
            bignum_mul(tmp[3], a_n1, tmp[4]);
            bignum_add(tmp[2], tmp[4], tmp[5]);
            bignum_swap(a_n1, tmp[2]);
            bignum_swap(b_n1, tmp[5]);
        }

        for (int i = 0; i < 6; i++) {
            bignum_free(tmp[i]);
        }
    }

    char *output = bignum_to_string(a_n1);
    printk(KERN_INFO "fib %lld: %s\n", fib, output);

    bignum_free(a_n1);
    bignum_free(b_n1);

    return output;
}