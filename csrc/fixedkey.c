/* ECDSA verification against one known key, with signed 8-bit window tables for the key
 * and the generator, on libsecp256k1's own field, scalar and group code. */

#include "util.h"
#include "int128_impl.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"

#define P(name) rustsecp256k1_v0_14_##name

typedef P(fe) fe;
typedef P(ge) ge;
typedef P(gej) gej;
typedef P(ge_storage) ge_storage;
typedef P(scalar) scalar;

#define W 8
#define ROWS (256 / W + 1)
#define HALF (1 << (W - 1))

static const fe ORDER = SECP256K1_FE_CONST(0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL,
    0xFFFFFFFEUL, 0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL);
static const fe P_MINUS_ORDER = SECP256K1_FE_CONST(0, 0, 0, 1, 0x45512319UL, 0x50B75FC4UL,
    0x402DA172UL, 0x2FC9BAEEUL);

size_t rhfeed_fixedkey_table_size(void) {
    return sizeof(ge_storage) * ROWS * HALF;
}

/* Row i holds 1..HALF times key * 2^(W*i). Returns 0 for a key that isn't on the curve. */
int rhfeed_fixedkey_build(ge_storage *table, const unsigned char *compressed) {
    fe x;
    ge point, row[HALF];
    gej base, multiples[HALF];
    int i, j;
    if ((compressed[0] != 2 && compressed[0] != 3) || !P(fe_set_b32_limit)(&x, compressed + 1) ||
        !P(ge_set_xo_var)(&point, &x, compressed[0] == 3)) {
        return 0;
    }
    P(gej_set_ge)(&base, &point);
    for (i = 0; i < ROWS; i++) {
        multiples[0] = base;
        for (j = 1; j < HALF; j++) {
            P(gej_add_var)(&multiples[j], &multiples[j - 1], &base, NULL);
        }
        P(ge_set_all_gej_var)(row, multiples, HALF);
        for (j = 0; j < HALF; j++) {
            P(ge_to_storage)(&table[i * HALF + j], &row[j]);
        }
        for (j = 0; j < W; j++) {
            P(gej_double_var)(&base, &base, NULL);
        }
    }
    return 1;
}

/* acc += k * key, with k's bytes as base-256 digits in -127..=128. */
static void mul_add(gej *acc, const ge_storage *table, const scalar *k) {
    unsigned char b[32];
    int row, digit, carry = 0;
    ge p;
    P(scalar_get_b32)(b, k);
    for (row = 0; row < ROWS; row++) {
        digit = carry + (row < 32 ? b[31 - row] : 0);
        carry = digit > HALF;
        digit -= carry << W;
        if (digit == 0) {
            continue;
        }
        P(ge_from_storage)(&p, &table[row * HALF + (digit > 0 ? digit : -digit) - 1]);
        if (digit < 0) {
            P(ge_neg)(&p, &p);
        }
        P(gej_add_ge_var)(acc, acc, &p, NULL);
    }
}

/* Accepts what libsecp256k1's verify accepts, plus a high s. */
int rhfeed_fixedkey_verify(const ge_storage *g, const ge_storage *key,
    const unsigned char *digest, const unsigned char *r32, const unsigned char *s32) {
    scalar r, s, z, u1, u2;
    gej acc;
    fe xr;
    int overflow;
    P(scalar_set_b32)(&r, r32, &overflow);
    if (overflow || P(scalar_is_zero)(&r)) {
        return 0;
    }
    P(scalar_set_b32)(&s, s32, &overflow);
    if (overflow || P(scalar_is_zero)(&s)) {
        return 0;
    }
    P(scalar_set_b32)(&z, digest, NULL);
    P(scalar_inverse_var)(&s, &s);
    P(scalar_mul)(&u1, &z, &s);
    P(scalar_mul)(&u2, &r, &s);
    P(gej_set_infinity)(&acc);
    mul_add(&acc, g, &u1);
    mul_add(&acc, key, &u2);
    if (P(gej_is_infinity)(&acc)) {
        return 0;
    }
    /* x = X / Z^2: compare without inverting, and try r + n while that is below p. */
    P(fe_set_b32_mod)(&xr, r32);
    if (P(gej_eq_x_var)(&xr, &acc)) {
        return 1;
    }
    if (P(fe_cmp_var)(&xr, &P_MINUS_ORDER) >= 0) {
        return 0;
    }
    P(fe_add)(&xr, &ORDER);
    return P(gej_eq_x_var)(&xr, &acc);
}
