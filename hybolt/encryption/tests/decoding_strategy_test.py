import hashlib

import numpy as np
import pytest

import hybolt.utils.galois as ga
from hybolt.encryption.block import Block, LocalBlock
from hybolt.encryption.decoding_strategy import (
    LtDecodingStrategy,
    Raptor10DecodingStrategy,
    create_decoding_strategy,
)
from hybolt.encryption.encode import Encode
from hybolt.encryption.encoding_metadata import (
    BlockMetadata,
    ChunkMetadata,
    EncodingMetadata,
    PacketMetadata,
)
from hybolt.encryption.retrievability import (
    DisabledRetrievabilityProof,
    PolynomialRetrievabilityProof,
)
from hybolt.utils.operators import xor_bytes

POLYNOMIAL = np.array([1, 0, 1, 1] + [0] * 12 + [1], dtype=np.uint8)


def _mac(data, polynomial=POLYNOMIAL):
    return ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(data), polynomial)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


class FakeServer:
    """Answers challenges over `stored` bytes and serves `served` bytes on download."""

    def __init__(self, stored: bytes, served: bytes | None = None, name="server"):
        self._storage_location = name
        self.stored = stored
        self.served = stored if served is None else served
        self.challenge_calls = 0
        self.download_calls = 0

    def receive_challenge(self, polynomial, check_block_index, packet_file=""):
        self.challenge_calls += 1
        return _mac(self.stored, polynomial)

    def download_block(self, block_index, packet_file=""):
        self.download_calls += 1
        return self.served


def _proof():
    return PolynomialRetrievabilityProof([POLYNOMIAL])


def _lt_metadata(source_blocks, packets):
    """`packets` is a list of (server_name, indices, packet_sha256) tuples."""
    return EncodingMetadata(
        polynomials=[POLYNOMIAL],
        blocks=[
            BlockMetadata(mac_value=_mac(data), block_index=index, polynomial_index=0)
            for index, data in enumerate(source_blocks)
        ],
        packets=[
            PacketMetadata(
                server=server_name,
                packet_index=packet_index,
                degree=len(indices),
                indices=list(indices),
                packet_sha256=packet_sha256,
            )
            for packet_index, (server_name, indices, packet_sha256) in enumerate(
                packets
            )
        ],
    )


def _lt_strategy(source_blocks, packets, servers, proof=None):
    return LtDecodingStrategy(
        _lt_metadata(source_blocks, packets),
        {server._storage_location: server for server in servers},
        proof or _proof(),
    )


def _in_memory_lt_strategy(local_blocks=None):
    strategy = LtDecodingStrategy(
        EncodingMetadata(polynomials=[], blocks=[], packets=[]),
        {},
        DisabledRetrievabilityProof(),
    )
    strategy._local_blocks = local_blocks or {}
    return strategy


# --- LT: peeling -------------------------------------------------------------


def test_given_local_blocks_when_finding_required_blocks_then_returns_total_count():
    strategy = _in_memory_lt_strategy(
        {1: [Block(0, 1, [0], b"A")], 2: [Block(1, 2, [0, 1], b"\x03")]}
    )

    assert strategy._find_num_blocks_to_retrieve() == 2


def test_given_partially_solved_block_when_counting_solvable_parts_then_returns_remaining_indices():
    block = Block(1, 2, [0, 1], b"\x03")
    strategy = _in_memory_lt_strategy()

    assert strategy._count_solvable_parts(block, set()) == 2
    assert strategy._count_solvable_parts(block, {0}) == 1
    assert strategy._count_solvable_parts(block, {0, 1}) == 0


def test_given_retrieved_block_when_solving_partial_block_then_reduces_packet():
    original = Block(1, 2, [0, 1], xor_bytes(b"A", b"B"))
    strategy = _in_memory_lt_strategy()

    partial = strategy._solve_partial_block(original, {0: Block(0, 1, [0], b"A")})

    assert partial.indices == [1]
    assert partial.data == b"B"
    assert partial.index == 1


def test_given_indexed_blocks_when_decoding_then_retrieves_blocks_in_index_order():
    strategy = _in_memory_lt_strategy(
        {
            1: [Block(0, 1, [0], b"A")],
            2: [Block(1, 2, [0, 1], xor_bytes(b"A", b"B"))],
        }
    )

    assert strategy.decode() == b"AB"


def test_given_padded_payload_when_decoding_then_removes_valid_padding():
    strategy = _in_memory_lt_strategy({1: [Block(0, 1, [0], b"DATA\x04\x04\x04\x04")]})

    assert strategy.decode() == b"DATA"


# --- LT: retrievability proof ------------------------------------------------


def test_given_combined_lt_block_when_challenging_then_expects_xor_of_source_macs():
    source_blocks = [b"ABCD", b"WXYZ"]
    server = FakeServer(xor_bytes(*source_blocks))
    strategy = _lt_strategy(source_blocks, [("server", [0, 1], "")], [server])
    block = strategy._local_blocks[2][0]

    assert strategy._proof.verify(server, block, strategy._expected_mac(block)) is True


def test_given_failed_challenge_when_solving_lt_block_then_skips_download():
    server = FakeServer(stored=b"EVIL")
    strategy = _lt_strategy([b"ABCD"], [("server", [0], "")], [server])

    result = strategy._solve_partial_block(strategy._local_blocks[1][0], {})

    assert result is None
    assert server.challenge_calls == 1
    assert server.download_calls == 0


def test_given_hash_mismatch_when_solving_lt_block_then_rejects_block():
    server = FakeServer(stored=b"ABCD", served=b"EVIL")
    strategy = _lt_strategy([b"ABCD"], [("server", [0], _sha256(b"ABCD"))], [server])

    result = strategy._solve_partial_block(strategy._local_blocks[1][0], {})

    assert result is None
    assert server.download_calls == 1


def test_given_valid_challenge_and_hash_when_solving_lt_block_then_returns_data():
    server = FakeServer(b"ABCD")
    strategy = _lt_strategy([b"ABCD"], [("server", [0], _sha256(b"ABCD"))], [server])

    result = strategy._solve_partial_block(strategy._local_blocks[1][0], {})

    assert result.data == b"ABCD"
    assert result.indices == [0]


def test_given_missing_hash_when_solving_lt_block_then_accepts_challenged_data():
    server = FakeServer(b"ABCD")
    strategy = _lt_strategy([b"ABCD"], [("server", [0], "")], [server])

    result = strategy._solve_partial_block(strategy._local_blocks[1][0], {})

    assert result.data == b"ABCD"


def test_given_lt_server_block_when_reducing_then_keeps_original_indices_for_challenges():
    source_blocks = [b"ABCD", b"WXYZ", b"MNOP"]
    combined = xor_bytes(
        xor_bytes(source_blocks[0], source_blocks[1]), source_blocks[2]
    )
    server = FakeServer(combined)
    strategy = _lt_strategy(source_blocks, [("server", [0, 1, 2], "")], [server])
    block = strategy._local_blocks[3][0]
    retrieved_data = {
        0: Block(0, 1, [0], source_blocks[0]),
        1: Block(1, 1, [1], source_blocks[1]),
    }

    partial = strategy._solve_partial_block(block, retrieved_data)

    assert partial.indices == [2]
    assert partial.data == source_blocks[2]
    assert block.indices == [0, 1, 2]
    assert strategy._proof.verify(server, block, strategy._expected_mac(block)) is True


def test_given_dishonest_server_and_redundant_lt_block_when_decoding_then_uses_verified_block():
    source_blocks = [b"ABCD", b"WXYZ"]
    dishonest = FakeServer(stored=b"EVIL", name="dishonest")
    honest_a = FakeServer(source_blocks[0], name="honest_a")
    honest_ab = FakeServer(xor_bytes(*source_blocks), name="honest_ab")
    strategy = _lt_strategy(
        source_blocks,
        [("dishonest", [0], ""), ("honest_a", [0], ""), ("honest_ab", [0, 1], "")],
        [dishonest, honest_a, honest_ab],
    )

    assert strategy.decode() == b"ABCDWXYZ"
    assert dishonest.challenge_calls == 1
    assert dishonest.download_calls == 0


def test_given_only_dishonest_lt_servers_when_decoding_then_raises_insufficient_blocks():
    source_blocks = [b"ABCD", b"WXYZ"]
    strategy = _lt_strategy(
        source_blocks,
        [("evil", [0], ""), ("honest", [0, 1], "")],
        [
            FakeServer(b"EVIL", name="evil"),
            FakeServer(xor_bytes(*source_blocks), name="honest"),
        ],
    )

    with pytest.raises(ValueError, match="Insufficient verified blocks"):
        strategy.decode()


def test_given_disabled_proof_when_decoding_lt_then_downloads_without_challenge():
    server = FakeServer(stored=b"EVIL", served=b"ABCD")
    strategy = _lt_strategy(
        [b"ABCD"], [("server", [0], "")], [server], DisabledRetrievabilityProof()
    )

    assert strategy.decode() == b"ABCD"
    assert server.challenge_calls == 0
    assert server.download_calls == 1


def test_given_lt_metadata_without_macs_when_proof_enabled_then_raises():
    metadata = EncodingMetadata(polynomials=[POLYNOMIAL], blocks=[], packets=[])

    with pytest.raises(ValueError, match="no source block MACs"):
        LtDecodingStrategy(metadata, {}, _proof())


# --- Raptor R10 -----------------------------------------------------------------


def _r10_chunk(original, block_size, proof, server_for_packet):
    """Encode `original`, returning chunk metadata and a server per packet."""
    encoded = Encode(original, block_size, proof=proof)
    servers = {}
    packets = []
    for packet in encoded.packets:
        server = server_for_packet(packet)
        server._storage_location = f"server_{packet.index}"
        servers[server._storage_location] = server
        packets.append(
            PacketMetadata(
                server=server._storage_location,
                packet_index=packet.index,
                degree=0,
                indices=[],
                packet_file=f"packet_{packet.index}.pkl",
                packet_sha256=_sha256(packet.data),
                macs=encoded.packet_macs.get(packet.index, []),
            )
        )

    chunk = ChunkMetadata(
        chunk_index=0,
        byte_size=len(original),
        polynomials=encoded.polynomials,
        blocks=[],
        packets=packets,
        codec="r10",
        transfer_length=encoded.total_block_bytes,
        symbol_size=encoded.symbol_size,
    )
    return chunk, servers


def test_given_honest_r10_servers_when_decoding_with_proof_then_reconstructs_data():
    original = b"R10 packets carry their own MACs here."
    chunk, servers = _r10_chunk(
        original, 8, _proof(), lambda packet: FakeServer(packet.data)
    )

    strategy = Raptor10DecodingStrategy(chunk, servers, _proof())

    assert strategy.decode() == original
    challenged = [server for server in servers.values() if server.challenge_calls]
    assert challenged
    assert all(server.download_calls == 1 for server in challenged)


def test_given_r10_server_failing_challenge_when_decoding_then_skips_packet_and_uses_repair():
    original = b"R10 packets carry their own MACs here."
    chunk, servers = _r10_chunk(
        original,
        8,
        _proof(),
        lambda packet: FakeServer(
            b"\x00" * len(packet.data) if packet.index == 0 else packet.data
        ),
    )

    strategy = Raptor10DecodingStrategy(chunk, servers, _proof())

    assert strategy.decode() == original
    assert servers["server_0"].challenge_calls == 1
    assert servers["server_0"].download_calls == 0


def test_given_r10_server_swapping_data_after_challenge_when_decoding_then_hash_rejects_packet():
    original = b"R10 packets carry their own MACs here."
    chunk, servers = _r10_chunk(
        original,
        8,
        _proof(),
        lambda packet: FakeServer(
            packet.data,
            served=b"\x00" * len(packet.data) if packet.index == 0 else None,
        ),
    )

    strategy = Raptor10DecodingStrategy(chunk, servers, _proof())

    assert strategy.decode() == original
    assert servers["server_0"].download_calls == 1


def test_given_all_r10_servers_dishonest_when_decoding_then_raises_insufficient_packets():
    original = b"R10 packets carry their own MACs here."
    chunk, servers = _r10_chunk(
        original, 8, _proof(), lambda packet: FakeServer(b"\x00" * len(packet.data))
    )

    strategy = Raptor10DecodingStrategy(chunk, servers, _proof())

    with pytest.raises(ValueError, match="Insufficient valid R10 packets"):
        strategy.decode()
    assert all(server.download_calls == 0 for server in servers.values())


def test_given_r10_metadata_without_macs_when_proof_enabled_then_raises():
    chunk, servers = _r10_chunk(
        b"no macs here", 4, DisabledRetrievabilityProof(), lambda p: FakeServer(p.data)
    )
    chunk.polynomials = [POLYNOMIAL]

    with pytest.raises(ValueError, match="no MAC for every polynomial"):
        Raptor10DecodingStrategy(chunk, servers, _proof())


def test_given_r10_metadata_without_polynomials_when_proof_enabled_then_raises():
    chunk, servers = _r10_chunk(
        b"no macs here", 4, DisabledRetrievabilityProof(), lambda p: FakeServer(p.data)
    )

    with pytest.raises(ValueError, match="no challenge polynomials"):
        Raptor10DecodingStrategy(chunk, servers, _proof())


def test_given_r10_metadata_without_macs_when_proof_disabled_then_decodes_without_challenge():
    original = b"no macs here"
    chunk, servers = _r10_chunk(
        original, 4, DisabledRetrievabilityProof(), lambda p: FakeServer(p.data)
    )

    strategy = Raptor10DecodingStrategy(chunk, servers, DisabledRetrievabilityProof())

    assert strategy.decode() == original
    assert all(server.challenge_calls == 0 for server in servers.values())


# --- Strategy selection ------------------------------------------------------


@pytest.mark.parametrize(
    ("codec", "expected"),
    [("lt", LtDecodingStrategy), ("r10", Raptor10DecodingStrategy)],
)
def test_given_codec_when_creating_strategy_then_selects_matching_strategy(
    codec, expected
):
    metadata = ChunkMetadata(
        chunk_index=0, byte_size=0, polynomials=[], blocks=[], packets=[], codec=codec
    )

    strategy = create_decoding_strategy(metadata, {}, DisabledRetrievabilityProof())

    assert type(strategy) is expected


def test_given_metadata_without_codec_when_creating_strategy_then_defaults_to_lt():
    metadata = EncodingMetadata(polynomials=[], blocks=[], packets=[])

    strategy = create_decoding_strategy(metadata, {}, DisabledRetrievabilityProof())

    assert type(strategy) is LtDecodingStrategy


def test_given_unknown_codec_when_creating_strategy_then_raises():
    metadata = ChunkMetadata(
        chunk_index=0, byte_size=0, polynomials=[], blocks=[], packets=[], codec="??"
    )

    with pytest.raises(ValueError, match="Unsupported codec"):
        create_decoding_strategy(metadata, {}, DisabledRetrievabilityProof())


def test_given_local_block_when_built_from_metadata_then_carries_packet_hash():
    server = FakeServer(b"ABCD")
    strategy = _lt_strategy([b"ABCD"], [("server", [0], _sha256(b"ABCD"))], [server])

    block = strategy._local_blocks[1][0]

    assert isinstance(block, LocalBlock)
    assert block.packet_sha256 == _sha256(b"ABCD")
