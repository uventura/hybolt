"""Online Codes (Maymounkov, 2002), the fountain code of the original Hy-SAIL.

The outer code appends A auxiliary blocks to the K source blocks, each source
block being added to Q auxiliary blocks chosen at random. The inner code draws
every check block from the composite message of K + A blocks: a degree from
Maymounkov's distribution, then that many distinct composite blocks to XOR.
Every check block is therefore a XOR of source blocks, so this module, like
`raptor`, represents each one by its support, a K-bit mask, which is Hy-SAIL's
<i, x_i> structure. The graph depends only on K and the check block's index
(its ESI), so the client stores no more than it does for R10.

Decoding is the paper's belief-propagation (peeling) decoder over the
composite message, with each auxiliary block's relation as a check of value
zero. Online Codes are not systematic: every packet is a check block.
"""

import bisect
import functools
import math
import random
from dataclasses import dataclass

CODEC = "online"
SYSTEMATIC = False
# q in the paper: auxiliary blocks per source block.
QUALITY = 3
# Design epsilon; small K needs a larger one (see `parameters`).
DESIGN_EPSILON = 0.01
MIN_SOURCE_SYMBOLS = 1


@dataclass(frozen=True)
class Parameters:
    source_symbols: int
    epsilon: float
    auxiliary_symbols: int
    max_degree: int
    # cumulative[d - 1] = P(degree <= d).
    cumulative: tuple[float, ...]

    @property
    def composite_symbols(self) -> int:
        return self.source_symbols + self.auxiliary_symbols


def max_degree(epsilon: float) -> int:
    """F = ceil(ln(epsilon^2 / 4) / ln(1 - epsilon / 2))."""
    return math.ceil(math.log(epsilon**2 / 4) / math.log(1 - epsilon / 2))


def auxiliary_count(source_symbols: int, epsilon: float, quality=QUALITY) -> int:
    """A = ceil(0.55 q epsilon K)."""
    return max(1, math.ceil(0.55 * quality * epsilon * source_symbols))


def degree_distribution(epsilon: float) -> list[float]:
    """rho_1 = 1 - (1 + 1/F) / (1 + epsilon), rho_d = (1 - rho_1) F / ((F - 1) d (d - 1))."""
    f = max_degree(epsilon)
    rho_1 = 1 - (1 + 1 / f) / (1 + epsilon)
    return [rho_1] + [
        (1 - rho_1) * f / ((f - 1) * degree * (degree - 1))
        for degree in range(2, f + 1)
    ]


@functools.cache
def parameters(source_symbols: int) -> Parameters:
    """The smallest epsilon, from DESIGN_EPSILON, whose F fits in the composite message.

    Maymounkov's distribution assumes F < K + A; for small K the design epsilon
    has to grow until the largest degree can be drawn without repetition.
    """
    k = source_symbols
    if k < MIN_SOURCE_SYMBOLS:
        raise ValueError(f"Online Codes need at least one source symbol, got {k}")
    epsilon = DESIGN_EPSILON
    while max_degree(epsilon) > k + auxiliary_count(k, epsilon):
        epsilon *= 1.05
    cumulative = []
    total = 0.0
    for probability in degree_distribution(epsilon):
        total += probability
        cumulative.append(total)
    return Parameters(
        source_symbols=k,
        epsilon=epsilon,
        auxiliary_symbols=auxiliary_count(k, epsilon),
        max_degree=len(cumulative),
        cumulative=tuple(cumulative),
    )


def source_symbol_count(transfer_length: int, symbol_size: int) -> int:
    if transfer_length <= 0 or symbol_size <= 0:
        raise ValueError("transfer_length and symbol_size must be positive")
    return max(MIN_SOURCE_SYMBOLS, math.ceil(transfer_length / symbol_size))


@functools.cache
def auxiliary_members(source_symbols: int) -> tuple[tuple[int, ...], ...]:
    """Source blocks whose XOR is each auxiliary block (the outer code)."""
    params = parameters(source_symbols)
    count = params.auxiliary_symbols
    rng = random.Random(f"online-outer:{source_symbols}")
    members = [[] for _ in range(count)]
    for source in range(source_symbols):
        for auxiliary in rng.sample(range(count), min(QUALITY, count)):
            members[auxiliary].append(source)
    return tuple(tuple(sources) for sources in members)


@functools.cache
def composite_supports(source_symbols: int) -> tuple[int, ...]:
    supports = [1 << source for source in range(source_symbols)]
    for sources in auxiliary_members(source_symbols):
        mask = 0
        for source in sources:
            mask ^= 1 << source
        supports.append(mask)
    return tuple(supports)


@functools.lru_cache(maxsize=1 << 16)
def check_neighbours(source_symbols: int, esi: int) -> tuple[int, ...]:
    """Composite blocks that the check block `esi` XORs (the inner code)."""
    params = parameters(source_symbols)
    rng = random.Random(f"online-check:{source_symbols}:{esi}")
    degree = min(
        params.max_degree, 1 + bisect.bisect_right(params.cumulative, rng.random())
    )
    return tuple(rng.sample(range(params.composite_symbols), degree))


@functools.lru_cache(maxsize=1 << 16)
def symbol_support(source_symbols: int, esi: int) -> int:
    """K-bit mask of the source symbols whose XOR is the check block `esi`."""
    supports = composite_supports(source_symbols)
    mask = 0
    for neighbour in check_neighbours(source_symbols, esi):
        mask ^= supports[neighbour]
    return mask


class PeelingDecoder:
    """Belief propagation over the composite message.

    Symbols are integers; passing 0 for every value tracks only which composite
    blocks are known, which is the decoder's own success criterion.
    """

    def __init__(self, source_symbols: int):
        self.source_symbols = source_symbols
        composite = parameters(source_symbols).composite_symbols
        self._values = [None] * composite
        self._unknown = []
        self._check_values = []
        self._checks_of = [[] for _ in range(composite)]
        self._recovered = 0
        for auxiliary, sources in enumerate(auxiliary_members(source_symbols)):
            self._add_check([*sources, source_symbols + auxiliary], 0)

    @property
    def complete(self) -> bool:
        return self._recovered == self.source_symbols

    def add(self, esi: int, value: int = 0) -> bool:
        """Feed one check block; True once every source block is known."""
        self._add_check(check_neighbours(self.source_symbols, esi), value)
        return self.complete

    def sources(self) -> list[int] | None:
        if not self.complete:
            return None
        return self._values[: self.source_symbols]

    def _add_check(self, neighbours, value):
        unknown = set()
        for neighbour in neighbours:
            known = self._values[neighbour]
            if known is None:
                unknown.add(neighbour)
            else:
                value ^= known
        if not unknown:
            return
        index = len(self._unknown)
        self._unknown.append(unknown)
        self._check_values.append(value)
        for neighbour in unknown:
            self._checks_of[neighbour].append(index)
        if len(unknown) == 1:
            self._release([index])

    def _release(self, pending):
        while pending:
            index = pending.pop()
            unknown = self._unknown[index]
            if len(unknown) != 1:
                continue
            variable = unknown.pop()
            value = self._check_values[index]
            self._values[variable] = value
            if variable < self.source_symbols:
                self._recovered += 1
            for other in self._checks_of[variable]:
                remaining = self._unknown[other]
                if variable in remaining:
                    remaining.discard(variable)
                    self._check_values[other] ^= value
                    if len(remaining) == 1:
                        pending.append(other)
            self._checks_of[variable] = []


def recoverable(source_symbols: int, esis) -> bool:
    """Exact Online Codes check: does peeling the check blocks `esis` finish?"""
    decoder = PeelingDecoder(source_symbols)
    for esi in esis:
        if decoder.add(esi):
            return True
    return False


@functools.cache
def check_block_count(source_symbols: int, minimum: int) -> int:
    """Smallest n >= minimum such that the check blocks 0..n-1 decode.

    A stored chunk must decode while intact, and Online Codes need a random
    number of check blocks beyond K, so the encoder keeps adding blocks.
    """
    decoder = PeelingDecoder(source_symbols)
    count = 0
    while count < minimum or not decoder.complete:
        decoder.add(count)
        count += 1
    return count


class Encoder:
    """Online Codes encoder: check block `esi` XORs its composite neighbours."""

    def __init__(self, data: bytes, symbol_size: int):
        if not data:
            raise ValueError("data cannot be empty")
        self.symbol_size = symbol_size
        self.transfer_length = len(data)
        self.source_symbols = source_symbol_count(len(data), symbol_size)
        padded = data.ljust(self.source_symbols * symbol_size, b"\0")
        composite = [
            int.from_bytes(padded[offset : offset + symbol_size], "big")
            for offset in range(0, len(padded), symbol_size)
        ]
        for sources in auxiliary_members(self.source_symbols):
            value = 0
            for source in sources:
                value ^= composite[source]
            composite.append(value)
        self._composite = composite

    def support(self, esi: int) -> int:
        return symbol_support(self.source_symbols, esi)

    def symbol(self, esi: int) -> bytes:
        value = 0
        for neighbour in check_neighbours(self.source_symbols, esi):
            value ^= self._composite[neighbour]
        return value.to_bytes(self.symbol_size, "big")

    def symbols(self, repair_symbols: int) -> list[tuple[int, bytes]]:
        """At least K + `repair_symbols` check blocks, as many more as decoding needs."""
        count = check_block_count(
            self.source_symbols, self.source_symbols + repair_symbols
        )
        return [(esi, self.symbol(esi)) for esi in range(count)]


class Decoder:
    """Peels received check blocks until every source block is known."""

    def __init__(self, transfer_length: int, symbol_size: int):
        self.transfer_length = transfer_length
        self.symbol_size = symbol_size
        self.source_symbols = source_symbol_count(transfer_length, symbol_size)
        self._peeling = PeelingDecoder(self.source_symbols)

    def add(self, esi: int, symbol: bytes) -> bytes | None:
        """Feed one check block; returns the decoded block once it is recoverable."""
        if len(symbol) != self.symbol_size:
            raise ValueError(
                f"symbol {esi} has {len(symbol)} bytes, expected {self.symbol_size}"
            )
        if not self._peeling.add(esi, int.from_bytes(symbol, "big")):
            return None
        data = b"".join(
            value.to_bytes(self.symbol_size, "big") for value in self._peeling.sources()
        )
        return data[: self.transfer_length]
