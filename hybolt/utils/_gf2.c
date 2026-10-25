/*
 * GF(2)[x] arithmetic for moduli of degree 8 to 128, the hot path of the
 * Hy-SAIL MACs and tags (lambda = 127).
 *
 * Polynomials cross the boundary as bytes: dividends and big factors in the
 * big-endian order of galois.bytes_to_poly_int (the last byte holds x^0..x^7),
 * moduli and small operands as little-endian integers. Elements below the
 * modulus fit in two 64-bit words, so no compiler-specific 128-bit type is
 * needed.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

#define MIN_DEGREE 8
#define MAX_DEGREE 128
#define MODULUS_BYTES 17
#define ELEMENT_BYTES 16

typedef struct {
    uint64_t lo;
    uint64_t hi;
} u128;

typedef struct {
    int degree;
    u128 low;  /* the modulus without its leading term x^degree */
    u128 mask; /* 2^degree - 1 */
} modulus_t;

static inline u128 xor128(u128 a, u128 b) {
    u128 r = {a.lo ^ b.lo, a.hi ^ b.hi};
    return r;
}

static inline u128 and128(u128 a, u128 b) {
    u128 r = {a.lo & b.lo, a.hi & b.hi};
    return r;
}

static inline u128 shl128(u128 a, int bits) {
    u128 r;
    if (bits == 0) {
        return a;
    }
    if (bits >= 64) {
        r.hi = a.lo << (bits - 64);
        r.lo = 0;
    } else {
        r.hi = (a.hi << bits) | (a.lo >> (64 - bits));
        r.lo = a.lo << bits;
    }
    return r;
}

static inline u128 shr128(u128 a, int bits) {
    u128 r;
    if (bits == 0) {
        return a;
    }
    if (bits >= 64) {
        r.lo = a.hi >> (bits - 64);
        r.hi = 0;
    } else {
        r.lo = (a.lo >> bits) | (a.hi << (64 - bits));
        r.hi = a.hi >> bits;
    }
    return r;
}

static inline int bit128(u128 a, int index) {
    return index >= 64 ? (int)((a.hi >> (index - 64)) & 1) : (int)((a.lo >> index) & 1);
}

static u128 load_le(const unsigned char *bytes, Py_ssize_t length) {
    u128 r = {0, 0};
    for (Py_ssize_t i = 0; i < length && i < ELEMENT_BYTES; i++) {
        if (i < 8) {
            r.lo |= (uint64_t)bytes[i] << (8 * i);
        } else {
            r.hi |= (uint64_t)bytes[i] << (8 * (i - 8));
        }
    }
    return r;
}

static PyObject *element_to_bytes(u128 value) {
    unsigned char out[ELEMENT_BYTES];
    for (int i = 0; i < 8; i++) {
        out[i] = (unsigned char)(value.lo >> (8 * i));
        out[i + 8] = (unsigned char)(value.hi >> (8 * i));
    }
    return PyBytes_FromStringAndSize((const char *)out, ELEMENT_BYTES);
}

static int parse_modulus(const unsigned char *bytes, Py_ssize_t length, modulus_t *modulus) {
    int degree = -1;
    for (Py_ssize_t i = length - 1; i >= 0 && degree < 0; i--) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((bytes[i] >> bit) & 1) {
                degree = (int)(8 * i + bit);
                break;
            }
        }
    }
    if (degree < MIN_DEGREE || degree > MAX_DEGREE) {
        PyErr_Format(PyExc_ValueError, "modulus degree must be between %d and %d",
                     MIN_DEGREE, MAX_DEGREE);
        return -1;
    }
    modulus->degree = degree;
    modulus->low = load_le(bytes, length < ELEMENT_BYTES ? length : ELEMENT_BYTES);
    if (degree < MAX_DEGREE) {
        u128 one = {1, 0};
        u128 top = shl128(one, degree);
        modulus->low = xor128(modulus->low, and128(modulus->low, top));
        /* top - 1: every bit below x^degree */
        modulus->mask.lo = top.lo - 1;
        modulus->mask.hi = top.hi - (top.lo == 0 ? 1 : 0);
    } else {
        modulus->mask.lo = UINT64_MAX;
        modulus->mask.hi = UINT64_MAX;
    }
    return 0;
}

/* value * x mod P, for value below x^degree. */
static inline u128 mulx(u128 value, const modulus_t *modulus) {
    int carry = bit128(value, modulus->degree - 1);
    u128 shifted = and128(shl128(value, 1), modulus->mask);
    if (carry) {
        shifted = xor128(shifted, modulus->low);
    }
    return shifted;
}

/* table[t] = t(x) * x^degree mod P, for every byte t. */
static void reduction_table(const modulus_t *modulus, u128 table[256]) {
    u128 powers[8];
    powers[0] = modulus->low;
    for (int bit = 1; bit < 8; bit++) {
        powers[bit] = mulx(powers[bit - 1], modulus);
    }
    table[0].lo = 0;
    table[0].hi = 0;
    for (int value = 1; value < 256; value++) {
        int low_bit = value & -value;
        int index = 0;
        while ((1 << index) != low_bit) {
            index++;
        }
        table[value] = xor128(table[value ^ low_bit], powers[index]);
    }
}

static PyObject *gf2_mod(PyObject *self, PyObject *args) {
    Py_buffer data, modulus_bytes;
    if (!PyArg_ParseTuple(args, "y*y*", &data, &modulus_bytes)) {
        return NULL;
    }
    modulus_t modulus;
    if (parse_modulus(modulus_bytes.buf, modulus_bytes.len, &modulus) < 0) {
        PyBuffer_Release(&data);
        PyBuffer_Release(&modulus_bytes);
        return NULL;
    }

    u128 table[256];
    reduction_table(&modulus, table);
    const unsigned char *bytes = data.buf;
    u128 remainder = {0, 0};
    Py_BEGIN_ALLOW_THREADS
    for (Py_ssize_t i = 0; i < data.len; i++) {
        unsigned top = (unsigned)shr128(remainder, modulus.degree - 8).lo & 0xFF;
        remainder = and128(shl128(remainder, 8), modulus.mask);
        remainder = xor128(remainder, table[top]);
        remainder.lo ^= bytes[i];
    }
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&modulus_bytes);
    return element_to_bytes(remainder);
}

static PyObject *gf2_mulmod(PyObject *self, PyObject *args) {
    Py_buffer left_bytes, right_bytes, modulus_bytes;
    if (!PyArg_ParseTuple(args, "y*y*y*", &left_bytes, &right_bytes, &modulus_bytes)) {
        return NULL;
    }
    modulus_t modulus;
    PyObject *result = NULL;
    if (parse_modulus(modulus_bytes.buf, modulus_bytes.len, &modulus) == 0) {
        u128 left = and128(load_le(left_bytes.buf, left_bytes.len), modulus.mask);
        u128 right = and128(load_le(right_bytes.buf, right_bytes.len), modulus.mask);
        u128 product = {0, 0};
        /* Horner's rule over the bits of right, most significant first. */
        for (int bit = modulus.degree - 1; bit >= 0; bit--) {
            product = mulx(product, &modulus);
            if (bit128(right, bit)) {
                product = xor128(product, left);
            }
        }
        result = element_to_bytes(product);
    }
    PyBuffer_Release(&left_bytes);
    PyBuffer_Release(&right_bytes);
    PyBuffer_Release(&modulus_bytes);
    return result;
}

static PyObject *gf2_clmul(PyObject *self, PyObject *args) {
    Py_buffer data, factor_bytes;
    if (!PyArg_ParseTuple(args, "y*y*", &data, &factor_bytes)) {
        return NULL;
    }
    u128 factor = load_le(factor_bytes.buf, factor_bytes.len);

    /* products[t] = t(x) * factor(x): up to 135 bits, big-endian in 17 bytes. */
    unsigned char products[256][MODULUS_BYTES];
    memset(products, 0, sizeof(products));
    for (int bit = 0; bit < 8; bit++) {
        u128 shifted = shl128(factor, bit);
        unsigned char *row = products[1 << bit];
        row[0] = bit ? (unsigned char)(factor.hi >> (64 - bit)) : 0;
        for (int i = 0; i < 8; i++) {
            row[MODULUS_BYTES - 1 - i] = (unsigned char)(shifted.lo >> (8 * i));
            row[MODULUS_BYTES - 9 - i] = (unsigned char)(shifted.hi >> (8 * i));
        }
    }
    for (int value = 1; value < 256; value++) {
        int low_bit = value & -value;
        if (value == low_bit) {
            continue;
        }
        for (int i = 0; i < MODULUS_BYTES; i++) {
            products[value][i] = products[value ^ low_bit][i] ^ products[low_bit][i];
        }
    }

    Py_ssize_t length = data.len + ELEMENT_BYTES;
    PyObject *result = PyBytes_FromStringAndSize(NULL, length);
    if (result != NULL) {
        unsigned char *out = (unsigned char *)PyBytes_AS_STRING(result);
        const unsigned char *bytes = data.buf;
        memset(out, 0, length);
        Py_BEGIN_ALLOW_THREADS
        /* data[i] weighs x^(8 * (n - 1 - i)), so its product lands at out[i..i+16]. */
        for (Py_ssize_t i = 0; i < data.len; i++) {
            const unsigned char *row = products[bytes[i]];
            for (int j = 0; j < MODULUS_BYTES; j++) {
                out[i + j] ^= row[j];
            }
        }
        Py_END_ALLOW_THREADS
    }
    PyBuffer_Release(&data);
    PyBuffer_Release(&factor_bytes);
    return result;
}

static PyMethodDef methods[] = {
    {"mod", gf2_mod, METH_VARARGS,
     "mod(data, modulus) -> remainder: big-endian data, little-endian modulus and result."},
    {"mulmod", gf2_mulmod, METH_VARARGS,
     "mulmod(left, right, modulus) -> left * right mod modulus, all little-endian."},
    {"clmul", gf2_clmul, METH_VARARGS,
     "clmul(data, factor) -> big-endian product of big-endian data and a factor below 2^128."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_gf2", "Native GF(2)[x] arithmetic for HyBolt.", -1, methods,
};

PyMODINIT_FUNC PyInit__gf2(void) { return PyModule_Create(&module); }
