"""A MAC that is linear over RaptorQ's GF(256), evaluated in GF(2^128).

RaptorQ repair symbols are GF(256)-linear combinations of the source symbols,
applied with the same coefficient to every byte. Hy-SAIL's MAC, a reduction
in GF(2)[x], does not commute with those byte multiplications, so the client
has to keep a MAC for every packet.

This MAC interprets each byte c_i of a symbol as an element of GF(256),
embedded in GF(2^128) (8 divides 128, so GF(256) is a subfield), and
evaluates h_s(c) = sum(phi(c_i) * s^i) at a secret point s. Then
h(a * x + y) = phi(a) * h(x) + h(y) for every a in GF(256), and the MAC of any
encoding symbol is the same GF(256) combination of the source MACs. Writing a
MAC in coordinates over the embedded GF(256) turns it into a 16-byte symbol,
and running the RaptorQ encoder over the K source MAC symbols yields the MAC
of every ESI, including repair symbols generated later.
"""

import functools
import secrets
from dataclasses import dataclass, field

from raptorq import Encoder

from hybolt.utils.galois import gf2_clmul, gf2_mod

GF128_DEGREE = 128
# x^128 + x^7 + x^2 + x + 1, the GCM field polynomial.
GF128_MODULUS = (1 << GF128_DEGREE) | 0x87
# x^8 + x^4 + x^3 + x^2 + 1, RFC 6330's octet field (Section 5.7).
GF256_MODULUS = 0x11D
MAC_SYMBOL_SIZE = GF128_DEGREE // 8
# RaptorQ packets start with a 4-byte payload id: source block number and ESI.
PAYLOAD_ID_SIZE = 4

_GF128_ORDER = (1 << GF128_DEGREE) - 1
_GF256_ORDER = 255
_GF256_ORDER_FACTORS = (3, 5, 17)


def gf128_mul(left, right):
    return gf2_mod(gf2_clmul(left, right), GF128_MODULUS)


def gf128_pow(base, exponent):
    result = 1
    while exponent:
        if exponent & 1:
            result = gf128_mul(result, base)
        base = gf128_mul(base, base)
        exponent >>= 1
    return result


def gf256_mul(left, right):
    return gf2_mod(gf2_clmul(left, right), GF256_MODULUS)


@functools.cache
def _subfield_root():
    """A root of RFC 6330's octet polynomial inside GF(2^128).

    The nonzero elements of the GF(256) subfield are the powers of any element
    of order 255; the octet polynomial is irreducible of degree 8, so its eight
    roots are among them.
    """
    candidate = 2
    while True:
        generator = gf128_pow(candidate, _GF128_ORDER // _GF256_ORDER)
        if all(
            gf128_pow(generator, _GF256_ORDER // factor) != 1
            for factor in _GF256_ORDER_FACTORS
        ):
            break
        candidate += 1

    element = 1
    for _ in range(_GF256_ORDER):
        element = gf128_mul(element, generator)
        if _evaluate_octet_polynomial(element) == 0:
            return element
    raise ArithmeticError("the octet polynomial has no root in GF(2^128)")


def _evaluate_octet_polynomial(value):
    result = 0
    power = 1
    for degree in range(9):
        if (GF256_MODULUS >> degree) & 1:
            result ^= power
        power = gf128_mul(power, value)
    return result


@functools.cache
def subfield_embedding():
    """phi: byte -> GF(2^128), the field embedding of RFC 6330's GF(256).

    Bit j of a byte is the coefficient of alpha^j, alpha a root of the octet
    polynomial, so phi(byte) = sum(bit_j * theta^j) for a root theta.
    """
    root = _subfield_root()
    powers = [1]
    for _ in range(7):
        powers.append(gf128_mul(powers[-1], root))
    table = [0] * 256
    for value in range(1, 256):
        low_bit = value & -value
        table[value] = table[value ^ low_bit] ^ powers[low_bit.bit_length() - 1]
    return tuple(table)


@functools.cache
def _coordinate_basis():
    """Columns of the GF(2)-linear map from 16 subfield coordinates to GF(2^128).

    Column 8k + b is phi(2^b) * x^k: coordinate k is the subfield element
    multiplying x^k. x generates GF(2^128) over GF(2), so it lies in no proper
    subfield and {1, x, ..., x^15} is a basis over the embedded GF(256).
    """
    embedding = subfield_embedding()
    return tuple(
        gf128_mul(embedding[1 << bit], 1 << power)
        for power in range(MAC_SYMBOL_SIZE)
        for bit in range(8)
    )


@functools.cache
def _coordinate_inverse():
    """For each bit i of a GF(2^128) element, the coordinates of x^i."""
    pivots = {}
    for column_index, column in enumerate(_coordinate_basis()):
        vector, combination = column, 1 << column_index
        while vector:
            pivot = vector.bit_length() - 1
            if pivot not in pivots:
                pivots[pivot] = (vector, combination)
                break
            pivot_vector, pivot_combination = pivots[pivot]
            vector ^= pivot_vector
            combination ^= pivot_combination
        else:
            raise ArithmeticError("the coordinate basis is not linearly independent")

    # Back-substitute in increasing pivot order so each pivot becomes a unit vector.
    for pivot in sorted(pivots):
        vector, combination = pivots[pivot]
        remainder = vector ^ (1 << pivot)
        while remainder:
            bit = remainder.bit_length() - 1
            lower_vector, lower_combination = pivots[bit]
            vector ^= lower_vector
            combination ^= lower_combination
            remainder = vector ^ (1 << pivot)
        pivots[pivot] = (vector, combination)
    return tuple(pivots[bit][1] for bit in range(GF128_DEGREE))


def mac_to_symbol(mac):
    """The 16 subfield coordinates of `mac`, one byte each."""
    inverse = _coordinate_inverse()
    coordinates = 0
    while mac:
        low_bit = mac & -mac
        coordinates ^= inverse[low_bit.bit_length() - 1]
        mac ^= low_bit
    return coordinates.to_bytes(MAC_SYMBOL_SIZE, "little")


def symbol_to_mac(symbol):
    basis = _coordinate_basis()
    coordinates = int.from_bytes(symbol, "little")
    mac = 0
    while coordinates:
        low_bit = coordinates & -coordinates
        mac ^= basis[low_bit.bit_length() - 1]
        coordinates ^= low_bit
    return mac


@dataclass(frozen=True)
class LinearMacKey:
    """Secret evaluation point s of the MAC h_s(c) = sum(phi(c_i) * s^i)."""

    point: int
    _multiply_tables: tuple = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not 0 < self.point < (1 << GF128_DEGREE):
            raise ValueError("the MAC point must be a nonzero element of GF(2^128)")
        object.__setattr__(self, "_multiply_tables", _multiply_tables(self.point))

    @classmethod
    def generate(cls):
        point = 0
        while point == 0:
            point = secrets.randbits(GF128_DEGREE)
        return cls(point)

    def mac(self, symbol: bytes) -> int:
        """h_s(symbol), evaluated by Horner's rule from the last byte."""
        embedding = subfield_embedding()
        tables = self._multiply_tables
        accumulator = 0
        for byte in reversed(symbol):
            product = 0
            for table in tables:
                product ^= table[accumulator & 0xFF]
                accumulator >>= 8
            accumulator = product ^ embedding[byte]
        return accumulator

    def packet_mac(self, packet: bytes) -> int:
        """MAC of a RaptorQ packet's symbol, without its payload id."""
        return self.mac(packet[PAYLOAD_ID_SIZE:])


def _multiply_tables(point):
    """table[k][b] = (b * x^(8k)) * point, so v * point is 16 lookups."""
    tables = []
    power = point
    for _ in range(MAC_SYMBOL_SIZE):
        bit_products = []
        for _ in range(8):
            bit_products.append(power)
            power = gf2_mod(power << 1, GF128_MODULUS)
        table = [0] * 256
        for value in range(1, 256):
            low_bit = value & -value
            table[value] = (
                table[value ^ low_bit] ^ bit_products[low_bit.bit_length() - 1]
            )
        tables.append(tuple(table))
    return tuple(tables)


def derive_packet_macs(source_macs, repair_packets):
    """MACs of every ESI of a source block from the MACs of its K source symbols.

    `source_macs` holds the MACs of ESIs 0..K-1 in order; the result maps each
    ESI up to K + repair_packets - 1 to its MAC. The block must have been
    encoded as a single source block of K symbols, as HyBolt's chunks are.
    """
    if not source_macs:
        raise ValueError("at least one source MAC is required")
    symbols = b"".join(mac_to_symbol(mac) for mac in source_macs)
    packets = Encoder.with_defaults(symbols, MAC_SYMBOL_SIZE).get_encoded_packets(
        repair_packets
    )
    return {
        int.from_bytes(packet[1:PAYLOAD_ID_SIZE], "big"): symbol_to_mac(
            packet[PAYLOAD_ID_SIZE:]
        )
        for packet in packets
    }
