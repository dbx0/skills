#!/bin/bash
# GGUF Tensor Stride Integer Overflow — End-to-End PoC
# Replicates the exact vulnerable code paths from gguf.cpp and ggml.c
# to demonstrate integer overflow in tensor stride calculation.
#
# Usage: bash ggml_stride_overflow_poc.sh
# Output: PoC binary at /tmp/ggml_stride_overflow_poc

set -e

cat > /tmp/ggml_stride_overflow_poc.c << 'POCEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GGML_MAX_DIMS 4

enum ggml_type {
    GGML_TYPE_F32 = 0, GGML_TYPE_F16 = 1, GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_Q8_0 = 8, GGML_TYPE_COUNT,
};

struct ggml_tensor {
    enum ggml_type type;
    int64_t ne[GGML_MAX_DIMS];
    size_t  nb[GGML_MAX_DIMS];
};

static size_t ggml_type_size(enum ggml_type type) {
    switch (type) {
        case GGML_TYPE_F32: return 4;
        case GGML_TYPE_F16: return 2;
        case GGML_TYPE_Q8_0: return 34;
        default: return 4;
    }
}

static int64_t ggml_blck_size(enum ggml_type type) {
    switch (type) {
        case GGML_TYPE_F32: return 1;
        case GGML_TYPE_F16: return 1;
        case GGML_TYPE_Q8_0: return 32;
        default: return 1;
    }
}

static size_t ggml_row_size(enum ggml_type type, int64_t ne) {
    return ggml_type_size(type) * ne / ggml_blck_size(type);
}

static size_t ggml_nbytes(const struct ggml_tensor * t) {
    for (int i = 0; i < GGML_MAX_DIMS; ++i)
        if (t->ne[i] <= 0) return 0;
    size_t n = ggml_type_size(t->type);
    for (int i = 0; i < GGML_MAX_DIMS; ++i)
        n += (t->ne[i] - 1) * t->nb[i];
    return n;
}

static void gguf_calc_nb(struct ggml_tensor * t) {
    size_t ts = ggml_type_size(t->type);
    int64_t bs = ggml_blck_size(t->type);
    t->nb[0] = ts;
    t->nb[1] = t->nb[0] * (t->ne[0] / bs);
    for (int j = 2; j < GGML_MAX_DIMS; ++j)
        t->nb[j] = t->nb[j-1] * t->ne[j-1];
}

static size_t calc_data_size(enum ggml_type type, const int64_t ne[4], int nd) {
    size_t ds = ggml_row_size(type, ne[0]);
    for (int i = 1; i < nd; i++) ds *= ne[i];
    return ds;
}

static int gguf_overflow_check(const int64_t ne[4]) {
    for (int j = 0; j < 4; j++) if (ne[j] < 0) return 0;
    if ((INT64_MAX / ne[1] <= ne[0]) ||
        (INT64_MAX / ne[2] <= ne[0] * ne[1]) ||
        (INT64_MAX / ne[3] <= ne[0] * ne[1] * ne[2])) return 0;
    return 1;
}

void test(const char *name, enum ggml_type type, int64_t n0, int64_t n1, int64_t n2, int64_t n3) {
    printf("\n=== %s ===\n", name);
    int64_t ne[4] = {n0,n1,n2,n3};
    int64_t total = n0*n1*n2*n3;
    printf("  ne={%ld,%ld,%ld,%ld} type=%d total=%ld\n", (long)n0,(long)n1,(long)n2,(long)n3, type, (long)total);
    if (!gguf_overflow_check(ne)) { printf("  REJECTED by parser\n"); return; }
    struct ggml_tensor t; memset(&t,0,sizeof(t)); t.type=type; memcpy(t.ne,ne,sizeof(ne));
    gguf_calc_nb(&t);
    size_t ds = calc_data_size(type,ne,4), nb = ggml_nbytes(&t);
    printf("  nb={%zu,%zu,%zu,%zu} data_size=%zu nbytes=%zu\n", t.nb[0],t.nb[1],t.nb[2],t.nb[3], ds, nb);
    if ((ds==0 || nb==0) && total>0) printf("  *** VULNERABLE: overflow to 0! ***\n");
    else if (t.nb[2]==0 && n0>1 && n1>1) printf("  *** VULNERABLE: nb[2] overflow! ***\n");
    else if (t.nb[3]==0 && n0>1 && n1>1 && n2>1) printf("  *** VULNERABLE: nb[3] overflow! ***\n");
    else printf("  safe\n");
}

int main() {
    printf("=== GGUF Stride Integer Overflow PoC ===\n");
    test("Normal F32 256x256", GGML_TYPE_F32, 256, 256, 1, 1);
    test("VULNERABLE F32 2^31x2^31x1x1", GGML_TYPE_F32, 1LL<<31, 1LL<<31, 1, 1);
    test("VULNERABLE F32 2^21x2^21x2^20x1 (nb[3])", GGML_TYPE_F32, 1LL<<21, 1LL<<21, 1LL<<20, 1);
    test("VULNERABLE F32 2^16x2^16x2^15x2^15 (4D)", GGML_TYPE_F32, 1LL<<16, 1LL<<16, 1LL<<15, 1LL<<15);
    test("F16 2^31x2^31 (type_size=2, safe)", GGML_TYPE_F16, 1LL<<31, 1LL<<31, 1, 1);
    test("Q8_0 2^31x2^31 (blck=32, safe)", GGML_TYPE_Q8_0, 1LL<<31, 1LL<<31, 1, 1);
    test("Rejected 2^22x2^22x2^22", GGML_TYPE_F32, 1LL<<22, 1LL<<22, 1LL<<22, 1);
    return 0;
}
POCEOF

gcc -o /tmp/ggml_stride_overflow_poc /tmp/ggml_stride_overflow_poc.c -lm -Wall && \
/tmp/ggml_stride_overflow_poc
