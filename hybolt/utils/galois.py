import numpy as np
import secrets

from hybolt.constant import POLYNOMIAL_LAMBDA
from hybolt.utils.decorators import start_record_timeit

_BYTE_REDUCTION_TABLES = {}


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
            _reduce_polynomial(value << divisor_degree, divisor)
            for value in range(256)
        ]
    return _BYTE_REDUCTION_TABLES[key]


def _byte_aligned_gf2_poly_mod(m_coeffs, divisor, divisor_degree):
    table = _byte_reduction_table(divisor, divisor_degree)
    mask = (1 << divisor_degree) - 1
    packed_message = np.packbits(
        np.asarray(m_coeffs, dtype=np.uint8)[::-1]
    ).tobytes()
    remainder = 0

    for byte in packed_message:
        top_byte = remainder >> (divisor_degree - 8)
        remainder = ((remainder << 8) & mask) ^ table[top_byte] ^ byte

    return remainder


@start_record_timeit(runs=1)
def gf2_poly_mod(m_coeffs, p_coeffs):
    """
    Performs polynomial division m(x) % p(x) over GF(2).
    In GF(2), addition and subtraction are both XOR.
    """
    dividend_coeffs = list(m_coeffs)
    divisor_coeffs = list(p_coeffs)

    while divisor_coeffs and divisor_coeffs[-1] == 0:
        divisor_coeffs.pop()

    if not divisor_coeffs:
        raise ZeroDivisionError("Division by zero polynomial.")

    divisor = _poly_coeffs_to_int(divisor_coeffs)
    divisor_degree = divisor.bit_length() - 1
    if divisor_degree >= 8 and len(dividend_coeffs) % 8 == 0:
        current_dividend = _byte_aligned_gf2_poly_mod(
            dividend_coeffs, divisor, divisor_degree
        )
    else:
        dividend = _poly_coeffs_to_int(dividend_coeffs)
        current_dividend = _reduce_polynomial(dividend, divisor)

    remainder_width = min(len(dividend_coeffs), len(divisor_coeffs) - 1)
    return _int_to_poly_coeffs(current_dividend, remainder_width)


@start_record_timeit(runs=5)
def generate_challenge_polynomial(degree=POLYNOMIAL_LAMBDA):
    """
    Generates a random polynomial to serve as a challenge P_j(x).
    Note: For true Hy-SAIL security, this should be a verified
    Primitive Polynomial, but a random odd polynomial is a starting point.
    """
    coeffs = [secrets.randbelow(2) for _ in range(degree + 1)]
    # Ensure the polynomial is at the target degree and non-zero at the constant
    coeffs[0] = 1
    coeffs[-1] = 1
    return np.array(coeffs)
