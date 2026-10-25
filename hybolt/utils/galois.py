import math
import secrets

import numpy as np

from hybolt.constant import POLYNOMIAL_LAMBDA
from hybolt.utils.decorators import start_record_timeit

try:
    from hybolt.utils import _gf2 as _native
except ImportError:  # pragma: no cover - built only where a C compiler exists
    _native = None

_BYTE_REDUCTION_TABLES = {}
# Moduli the C extension handles: lambda = 127 needs two 64-bit words.
_NATIVE_MIN_DEGREE = 8
_NATIVE_MAX_DEGREE = 128
_NATIVE_MODULUS_BYTES = 17
_NATIVE_ELEMENT_BYTES = 16


def bytes_to_poly_coeffs(message_block):
    bits = np.unpackbits(np.frombuffer(message_block, dtype=np.uint8))
    # Reverse to align index with power of x (index 0 = x^0)
    return bits[::-1].astype(int)


def _poly_coeffs_to_int(coeffs):
    coefficients = np.asarray(coeffs, dtype=np.uint8)
    packed = np.packbits(coefficients, bitorder="little")
    return int.from_bytes(packed.tobytes(), byteorder="little")


def _int_to_poly_coeffs(value, width):
    if width <= 0:
        return np.array([], dtype=np.uint8)

    return np.array([(value >> index) & 1 for index in range(width)], dtype=np.uint8)


def _reduce_polynomial(value, divisor):
    while value.bit_length() >= divisor.bit_length():
        value ^= divisor << (value.bit_length() - divisor.bit_length())
    return value


def _byte_reduction_table(divisor, divisor_degree):
    key = (divisor, divisor_degree)
    if key not in _BYTE_REDUCTION_TABLES:
        _BYTE_REDUCTION_TABLES[key] = [
            _reduce_polynomial(value << divisor_degree, divisor) for value in range(256)
        ]
    return _BYTE_REDUCTION_TABLES[key]


@start_record_timeit(runs=1)
def gf2_poly_mod(m_coeffs, p_coeffs):
    """
    Performs polynomial division m(x) % p(x) over GF(2).
    In GF(2), addition and subtraction are both XOR.
    """
    dividend_coeffs = np.asarray(m_coeffs, dtype=np.uint8)
    divisor_coeffs = np.trim_zeros(np.asarray(p_coeffs, dtype=np.uint8), "b")

    if not len(divisor_coeffs):
        raise ZeroDivisionError("Division by zero polynomial.")

    remainder = gf2_mod(
        _poly_coeffs_to_int(dividend_coeffs), _poly_coeffs_to_int(divisor_coeffs)
    )
    remainder_width = min(len(dividend_coeffs), len(divisor_coeffs) - 1)
    return _int_to_poly_coeffs(remainder, remainder_width)


def bytes_to_poly_int(message_block):
    """Integer form of bytes_to_poly_coeffs: bit i holds the coefficient of x^i."""
    return int.from_bytes(message_block, "big")


def gf2_mod(value, modulus):
    """value(x) mod modulus(x) over GF(2), both given as integers."""
    if _native_modulus(modulus):
        data = value.to_bytes((value.bit_length() + 7) // 8, "big")
        remainder = _native.mod(data, modulus.to_bytes(_NATIVE_MODULUS_BYTES, "little"))
        return int.from_bytes(remainder, "little")
    return _python_gf2_mod(value, modulus)


def _python_gf2_mod(value, modulus):
    degree = modulus.bit_length() - 1
    if degree < 8:
        return _gf2_reduce(value, modulus)

    table = _byte_reduction_table(modulus, degree)
    mask = (1 << degree) - 1
    remainder = 0
    for byte in value.to_bytes((value.bit_length() + 7) // 8, "big"):
        top_byte = remainder >> (degree - 8)
        remainder = ((remainder << 8) & mask) ^ table[top_byte] ^ byte
    return remainder


def gf2_clmul(left, right):
    """Carry-less product of two GF(2)[x] polynomials given as integers."""
    if left.bit_length() < right.bit_length():
        left, right = right, left
    if _native is not None and right.bit_length() <= 8 * _NATIVE_ELEMENT_BYTES:
        data = left.to_bytes((left.bit_length() + 7) // 8, "big")
        product = _native.clmul(data, right.to_bytes(_NATIVE_ELEMENT_BYTES, "little"))
        return int.from_bytes(product, "big")
    return _python_gf2_clmul(left, right)


def _python_gf2_clmul(left, right):
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        right >>= 1
    return product


def polynomial_degree(p_coeffs):
    return _poly_coeffs_to_int(p_coeffs).bit_length() - 1


def aggregate_remainders(remainders, p_coeffs, shifts=None):
    """Computes (sum of x^k_i * r_i(x)) mod p(x) as deg(p) coefficients.

    A plain XOR of remainders lets two check blocks corrupted with the same error
    pattern cancel out whatever p(x) is. Weighting each remainder by x^k_i, with
    secret distinct exponents, keeps the MAC homomorphic (x^k * c mod p equals
    x^k * (c mod p) mod p) while making such cancellations require
    x^k_1 = x^k_2 mod p, which a primitive p(x) rules out for k_i < 2^deg - 1.
    """
    modulus = _poly_coeffs_to_int(p_coeffs)
    degree = modulus.bit_length() - 1
    shifts = shifts if shifts is not None else [0] * len(remainders)

    aggregate = 0
    for remainder, shift in zip(remainders, shifts, strict=True):
        value = _poly_coeffs_to_int(remainder)
        if shift:
            weight = _gf2_pow_mod(0b10, shift, modulus)
            value = _gf2_mul_mod(value, weight, modulus)
        aggregate ^= value
    return _int_to_poly_coeffs(aggregate, degree)


@start_record_timeit(runs=5)
def generate_challenge_polynomial(degree=POLYNOMIAL_LAMBDA):
    """
    Generates a random primitive polynomial to serve as a challenge P_j(x).
    Hy-SAIL's 2-universal hashing argument (Theorem 1) requires P_j(x) to be
    primitive, so candidates are drawn uniformly and rejected until one passes.
    """
    while True:
        coeffs = [secrets.randbelow(2) for _ in range(degree + 1)]
        # Ensure the polynomial is at the target degree and non-zero at the constant
        coeffs[0] = 1
        coeffs[-1] = 1
        if is_primitive(coeffs):
            return np.array(coeffs)


def is_irreducible(p_coeffs):
    """Rabin's irreducibility test over GF(2)."""
    modulus = _poly_coeffs_to_int(p_coeffs)
    degree = modulus.bit_length() - 1
    if degree < 1:
        return False

    x = 0b10
    if _gf2_frobenius(x, degree, modulus) != _gf2_reduce(x, modulus):
        return False

    for prime in _prime_factors(degree):
        power = _gf2_frobenius(x, degree // prime, modulus)
        if _gf2_gcd(power ^ x, modulus) != 1:
            return False

    return True


def is_primitive(p_coeffs):
    """True when p(x) is irreducible and x generates the multiplicative group."""
    if not is_irreducible(p_coeffs):
        return False

    modulus = _poly_coeffs_to_int(p_coeffs)
    degree = modulus.bit_length() - 1
    group_order = (1 << degree) - 1
    # When 2^degree - 1 is prime (a Mersenne prime, as for lambda = 127) every
    # irreducible polynomial is primitive and the loop checks only x^1 != 1.
    return all(
        _gf2_pow_mod(0b10, group_order // prime, modulus) != 1
        for prime in _prime_factors(group_order)
    )


def _gf2_reduce(value, modulus):
    degree = modulus.bit_length() - 1
    while value.bit_length() > degree:
        value ^= modulus << (value.bit_length() - 1 - degree)
    return value


def _gf2_square_mod(value, modulus):
    if _native_modulus(modulus):
        return _gf2_mul_mod(value, value, modulus)
    # Squaring in GF(2)[x] spreads the coefficients: bit i moves to bit 2i.
    if value == 0:
        return 0
    return _gf2_reduce(int("0".join(bin(value)[2:]), 2), modulus)


def _gf2_mul_mod(left, right, modulus):
    if _native_modulus(modulus):
        degree = modulus.bit_length() - 1
        if left.bit_length() > degree:
            left = gf2_mod(left, modulus)
        if right.bit_length() > degree:
            right = gf2_mod(right, modulus)
        product = _native.mulmod(
            left.to_bytes(_NATIVE_ELEMENT_BYTES, "little"),
            right.to_bytes(_NATIVE_ELEMENT_BYTES, "little"),
            modulus.to_bytes(_NATIVE_MODULUS_BYTES, "little"),
        )
        return int.from_bytes(product, "little")
    return _python_gf2_mul_mod(left, right, modulus)


def _native_modulus(modulus):
    return (
        _native is not None
        and _NATIVE_MIN_DEGREE <= modulus.bit_length() - 1 <= _NATIVE_MAX_DEGREE
    )


def _python_gf2_mul_mod(left, right, modulus):
    product = 0
    while right:
        if right & 1:
            product ^= left
        left <<= 1
        right >>= 1
    return _gf2_reduce(product, modulus)


def _gf2_pow_mod(base, exponent, modulus):
    result = 1
    base = _gf2_reduce(base, modulus)
    while exponent:
        if exponent & 1:
            result = _gf2_mul_mod(result, base, modulus)
        base = _gf2_square_mod(base, modulus)
        exponent >>= 1
    return result


def _gf2_frobenius(value, times, modulus):
    """Computes value^(2^times) mod modulus by repeated squaring."""
    for _ in range(times):
        value = _gf2_square_mod(value, modulus)
    return value


def _gf2_gcd(left, right):
    while right:
        left, right = right, _gf2_reduce(left, right)
    return left


def _prime_factors(value):
    factors = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if current == 1:
            continue
        if _is_probable_prime(current):
            factors.add(current)
            continue
        divisor = _find_divisor(current)
        stack.extend([divisor, current // divisor])
    return sorted(factors)


_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)


def _is_probable_prime(value):
    if value < 2:
        return False
    for prime in _SMALL_PRIMES:
        if value % prime == 0:
            return value == prime

    exponent, shifts = value - 1, 0
    while exponent % 2 == 0:
        exponent //= 2
        shifts += 1

    # These bases make Miller-Rabin deterministic below 3.3 * 10^24 and leave a
    # negligible error probability for the larger 2^lambda - 1 values.
    for base in _SMALL_PRIMES:
        witness = pow(base, exponent, value)
        if witness in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            witness = pow(witness, 2, value)
            if witness == value - 1:
                break
        else:
            return False
    return True


def _find_divisor(value):
    for prime in _SMALL_PRIMES:
        if value % prime == 0:
            return prime

    # Pollard's rho with Brent-style restarts on failure.
    constant = 1
    while True:
        tortoise = hare = 2
        divisor = 1
        while divisor == 1:
            tortoise = (tortoise * tortoise + constant) % value
            hare = (hare * hare + constant) % value
            hare = (hare * hare + constant) % value
            divisor = math.gcd(abs(tortoise - hare), value)
        if divisor != value:
            return divisor
        constant += 1
