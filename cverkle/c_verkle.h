#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Context Context;

Context *context_new(void);
void context_free(Context *ctx);
void pedersen_hash(Context *ctx,
                   const uint8_t *address,
                   const uint8_t *tree_index_le,
                   uint8_t *out);
void multi_scalar_mul(Context *ctx, const uint8_t *scalars, uintptr_t len, uint8_t *out);
void create_proof(Context *ctx, const uint8_t *input, uintptr_t len, uint8_t *out);
void create_proof_uncompressed(Context *ctx, const uint8_t *input, uintptr_t len, uint8_t *out);
bool verify_proof(Context *ctx, const uint8_t *input, uintptr_t len);
bool verify_proof_uncompressed(Context *ctx, const uint8_t *input, uintptr_t len);
