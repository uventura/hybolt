"""Raptor R10 fountain code (RFC 5053) over a single source block.

Every R10 operation is a XOR: the LDPC and Half pre-coding constraints and the
LT step all work in GF(2). The intermediate symbols C = A^-1 * D are therefore
XORs of source symbols, and so is every encoding symbol, repair symbols
included. This module represents each symbol by its support, a K-bit mask of
the source symbols whose XOR it is, which is Hy-SAIL's <i, x_i> structure:
encoding XORs the source symbols of a support, decoding solves the received
supports over GF(2), and a MAC that is linear over GF(2) commutes with both.
"""

import functools
import math
from dataclasses import dataclass

from hybolt.encryption import raptor_tables as tables

try:
    from hybolt.encryption import _raptor10
except ImportError:  # pragma: no cover - the C extension is optional
    _raptor10 = None

# Q in the triple generator (Section 5.4.4.4): the largest prime below 2^16.
_TRIPLE_PRIME = 65521
_DEGREE_RANGE = 1 << 20


@dataclass(frozen=True)
class Parameters:
    """K and the values derived from it in Sections 5.4.2.3 and 5.4.4.4."""

    source_symbols: int
    ldpc_symbols: int
    half_symbols: int
    half_weight: int
    intermediate_symbols: int
    intermediate_prime: int
    systematic_index: int


@functools.cache
def parameters(source_symbols: int) -> Parameters:
    k = source_symbols
    if not tables.MIN_SOURCE_SYMBOLS <= k <= tables.MAX_SOURCE_SYMBOLS:
        raise ValueError(
            f"Raptor R10 needs between {tables.MIN_SOURCE_SYMBOLS} and "
            f"{tables.MAX_SOURCE_SYMBOLS} source symbols, got {k}"
        )

    x = 1
    while x * (x - 1) < 2 * k:
        x += 1
    s = _next_prime(math.ceil(0.01 * k) + x)
    h = 1
    while math.comb(h, math.ceil(h / 2)) < k + s:
        h += 1
    length = k + s + h
    return Parameters(
        source_symbols=k,
        ldpc_symbols=s,
        half_symbols=h,
        half_weight=math.ceil(h / 2),
        intermediate_symbols=length,
        intermediate_prime=_next_prime(length),
        systematic_index=tables.SYSTEMATIC_INDICES[k - tables.MIN_SOURCE_SYMBOLS],
    )


def source_symbol_count(transfer_length: int, symbol_size: int) -> int:
    """K for a block: whole symbols, padded with zero symbols up to R10's minimum."""
    if transfer_length <= 0 or symbol_size <= 0:
        raise ValueError("transfer_length and symbol_size must be positive")
    count = max(tables.MIN_SOURCE_SYMBOLS, math.ceil(transfer_length / symbol_size))
    if count > tables.MAX_SOURCE_SYMBOLS:
        raise ValueError(
            f"{transfer_length} bytes need {count} symbols of {symbol_size} bytes, "
            f"more than R10's {tables.MAX_SOURCE_SYMBOLS}; use a larger block size"
        )
    return count


def rand(x: int, i: int, m: int) -> int:
    """Rand[X, i, m] of Section 5.4.4.1."""
    return (tables.V0[(x + i) % 256] ^ tables.V1[(x // 256 + i) % 256]) % m


def degree(v: int) -> int:
    """Deg[v] of Section 5.4.4.2."""
    for threshold, value in zip(tables.DEGREE_THRESHOLDS, tables.DEGREES):
        if v < threshold:
            return value
    raise ValueError(f"degree generator input out of range: {v}")


def triple(params: Parameters, esi: int) -> tuple[int, int, int]:
    """Trip[K, X] of Section 5.4.4.4."""
    j = params.systematic_index
    a_seed = (53591 + j * 997) % _TRIPLE_PRIME
    b_seed = 10267 * (j + 1) % _TRIPLE_PRIME
    y = (b_seed + esi * a_seed) % _TRIPLE_PRIME
    prime = params.intermediate_prime
    return (
        degree(rand(y, 0, _DEGREE_RANGE)),
        1 + rand(y, 1, prime - 1),
        rand(y, 2, prime),
    )


def lt_neighbours(params: Parameters, esi: int) -> tuple[int, ...]:
    """Intermediate symbols that LTEnc (Section 5.4.4.3) XORs for an ESI."""
    d, a, b = triple(params, esi)
    length, prime = params.intermediate_symbols, params.intermediate_prime
    while b >= length:
        b = (b + a) % prime
    neighbours = [b]
    for _ in range(min(d - 1, length - 1)):
        b = (b + a) % prime
        while b >= length:
            b = (b + a) % prime
        neighbours.append(b)
    return tuple(neighbours)


def constraint_rows(params: Parameters) -> list[int]:
    """The rows of A (Section 5.4.2.4.2) as L-bit masks: LDPC, Half, then G_LT."""
    k, s, h = params.source_symbols, params.ldpc_symbols, params.half_symbols

    ldpc = [1 << (k + row) for row in range(s)]
    for i in range(k):
        a = 1 + (i // s) % (s - 1)
        b = i % s
        for _ in range(3):
            ldpc[b] ^= 1 << i
            b = (b + a) % s

    half = [1 << (k + s + row) for row in range(h)]
    for j, code in enumerate(_gray_codes_with_weight(params.half_weight, k + s)):
        for row in range(h):
            if code >> row & 1:
                half[row] |= 1 << j

    lt = []
    for esi in range(k):
        mask = 0
        for neighbour in lt_neighbours(params, esi):
            mask ^= 1 << neighbour
        lt.append(mask)
    return ldpc + half + lt


@functools.cache
def intermediate_supports(source_symbols: int) -> tuple[int, ...]:
    """Support of each intermediate symbol: C = A^-1 * D with D = [0; I_K]."""
    params = parameters(source_symbols)
    padding = params.ldpc_symbols + params.half_symbols
    values = [0] * padding + [1 << i for i in range(source_symbols)]
    solution = solve(
        constraint_rows(params), values, params.intermediate_symbols, source_symbols
    )
    if solution is None:
        raise ArithmeticError(f"the R10 matrix A is singular for K = {source_symbols}")
    return tuple(solution)


@functools.lru_cache(maxsize=1 << 16)
def symbol_support(source_symbols: int, esi: int) -> int:
    """K-bit mask of the source symbols whose XOR is the encoding symbol `esi`."""
    if esi < source_symbols:
        # A has full rank, so the systematic symbols are the source symbols.
        return 1 << esi
    supports = intermediate_supports(source_symbols)
    mask = 0
    for neighbour in lt_neighbours(parameters(source_symbols), esi):
        mask ^= supports[neighbour]
    return mask


def support_indices(mask: int) -> list[int]:
    indices = []
    while mask:
        low_bit = mask & -mask
        indices.append(low_bit.bit_length() - 1)
        mask ^= low_bit
    return indices


def xor_symbols(symbols, mask: int) -> int:
    """XOR of the symbols (integers) selected by `mask`."""
    result = 0
    while mask:
        low_bit = mask & -mask
        result ^= symbols[low_bit.bit_length() - 1]
        mask ^= low_bit
    return result


class Gf2System:
    """Incremental Gaussian elimination of rows (bit masks) carrying XOR values."""

    def __init__(self, columns: int):
        self.columns = columns
        self._pivots = {}

    @property
    def rank(self) -> int:
        return len(self._pivots)

    def add(self, row: int, value: int = 0) -> bool:
        """Insert a row; False when it is a combination of the rows already held."""
        while row:
            column = row.bit_length() - 1
            pivot = self._pivots.get(column)
            if pivot is None:
                self._pivots[column] = (row, value)
                return True
            row ^= pivot[0]
            value ^= pivot[1]
        return False

    def reduce(self, row: int, value: int = 0) -> tuple[int, int]:
        """What remains of a row after eliminating it with the held pivots."""
        while row:
            pivot = self._pivots.get(row.bit_length() - 1)
            if pivot is None:
                break
            row ^= pivot[0]
            value ^= pivot[1]
        return row, value

    def solve(self) -> list[int] | None:
        if self.rank < self.columns:
            return None
        solution = [0] * self.columns
        # A pivot's other bits are lower columns, solved before it.
        for column in range(self.columns):
            row, value = self._pivots[column]
            solution[column] = value ^ xor_symbols(solution, row ^ (1 << column))
        return solution


def solve(rows, values, columns: int, value_bits: int) -> list[int] | None:
    """Solve rows * X = values over GF(2); None when the rows have rank < columns."""
    if _raptor10 is not None:
        return _solve_native(rows, values, columns, value_bits)
    system = Gf2System(columns)
    for row, value in zip(rows, values, strict=True):
        system.add(row, value)
    return system.solve()


def _solve_native(rows, values, columns, value_bits):
    row_bytes = (columns + 7) // 8
    value_bytes = (value_bits + 7) // 8
    solution = _raptor10.solve(
        [row.to_bytes(row_bytes, "little") for row in rows],
        [value.to_bytes(value_bytes, "little") for value in values],
        columns,
    )
    if solution is None:
        return None
    return [int.from_bytes(value, "little") for value in solution]


class Encoder:
    """Systematic R10 encoder: ESIs below K are the source symbols."""

    def __init__(self, data: bytes, symbol_size: int):
        if not data:
            raise ValueError("data cannot be empty")
        self.symbol_size = symbol_size
        self.transfer_length = len(data)
        self.source_symbols = source_symbol_count(len(data), symbol_size)
        padded = data.ljust(self.source_symbols * symbol_size, b"\0")
        self._sources = [
            int.from_bytes(padded[offset : offset + symbol_size], "big")
            for offset in range(0, len(padded), symbol_size)
        ]

    def support(self, esi: int) -> int:
        return symbol_support(self.source_symbols, esi)

    def symbol(self, esi: int) -> bytes:
        value = xor_symbols(self._sources, self.support(esi))
        return value.to_bytes(self.symbol_size, "big")

    def symbols(self, repair_symbols: int) -> list[tuple[int, bytes]]:
        """The K source symbols followed by `repair_symbols` repair symbols."""
        return [
            (esi, self.symbol(esi))
            for esi in range(self.source_symbols + repair_symbols)
        ]


class Decoder:
    """Collects encoding symbols until their supports span all K source symbols."""

    def __init__(self, transfer_length: int, symbol_size: int):
        self.transfer_length = transfer_length
        self.symbol_size = symbol_size
        self.source_symbols = source_symbol_count(transfer_length, symbol_size)
        self._system = Gf2System(self.source_symbols)

    def add(self, esi: int, symbol: bytes) -> bytes | None:
        """Feed one symbol; returns the decoded block once it is recoverable."""
        if len(symbol) != self.symbol_size:
            raise ValueError(
                f"symbol {esi} has {len(symbol)} bytes, expected {self.symbol_size}"
            )
        self._system.add(
            symbol_support(self.source_symbols, esi), int.from_bytes(symbol, "big")
        )
        sources = self._system.solve()
        if sources is None:
            return None
        data = b"".join(value.to_bytes(self.symbol_size, "big") for value in sources)
        return data[: self.transfer_length]


def _gray_codes_with_weight(weight: int, count: int) -> list[int]:
    """The first `count` elements of m[H'] in Section 5.4.2.3."""
    codes = []
    i = 0
    while len(codes) < count:
        i += 1
        code = i ^ (i >> 1)
        if code.bit_count() == weight:
            codes.append(code)
    return codes


def _next_prime(value: int) -> int:
    while not _is_prime(value):
        value += 1
    return value


def _is_prime(value: int) -> bool:
    if value < 2:
        return False
    return all(value % divisor for divisor in range(2, math.isqrt(value) + 1))
