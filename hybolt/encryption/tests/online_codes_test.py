import json
import pickle
import random
from pathlib import Path

import pytest

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.encryption import online_codes
from hybolt.encryption.decode import Decode
from hybolt.encryption.encode import Encode
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode


def test_given_k_when_deriving_parameters_then_follows_maymounkov():
    params = online_codes.parameters(1000)

    # A = ceil(0.55 q epsilon K), F = ceil(ln(epsilon^2 / 4) / ln(1 - epsilon / 2)).
    assert params.auxiliary_symbols == online_codes.auxiliary_count(
        1000, params.epsilon
    )
    assert params.max_degree == online_codes.max_degree(params.epsilon)
    assert params.max_degree <= params.composite_symbols
    assert params.cumulative[-1] == pytest.approx(1)


def test_given_small_k_when_deriving_parameters_then_grows_epsilon_until_f_fits():
    for k in range(1, 200):
        params = online_codes.parameters(k)

        assert params.max_degree <= params.composite_symbols
        assert params.epsilon >= online_codes.DESIGN_EPSILON


def test_given_every_source_block_when_building_outer_code_then_joins_q_auxiliaries():
    members = online_codes.auxiliary_members(100)

    for source in range(100):
        assert sum(source in sources for sources in members) == online_codes.QUALITY


def test_given_any_esi_when_encoding_then_symbol_is_xor_of_its_source_support():
    data = random.Random(3).randbytes(50 * 16)
    encoder = online_codes.Encoder(data, 16)
    sources = [data[i * 16 : (i + 1) * 16] for i in range(50)]

    for esi in range(80):
        expected = 0
        for index in range(50):
            if encoder.support(esi) >> index & 1:
                expected ^= int.from_bytes(sources[index], "big")
        assert encoder.symbol(esi) == expected.to_bytes(16, "big")


def test_given_k_and_esi_when_drawing_check_block_then_graph_is_deterministic():
    online_codes.check_neighbours.cache_clear()
    first = online_codes.check_neighbours(100, 7)
    online_codes.check_neighbours.cache_clear()

    assert online_codes.check_neighbours(100, 7) == first


@pytest.mark.parametrize("k", [1, 4, 10, 100])
def test_given_encoded_block_when_decoding_in_random_order_then_recovers_data(k):
    data = random.Random(k).randbytes(k * 32 - 5)
    encoder = online_codes.Encoder(data, 32)
    symbols = encoder.symbols(k)
    random.Random(1).shuffle(symbols)
    decoder = online_codes.Decoder(len(data), 32)

    decoded = None
    for esi, symbol in symbols:
        decoded = decoder.add(esi, symbol)
        if decoded is not None:
            break

    assert decoded == data


def test_given_repair_count_when_encoding_then_adds_check_blocks_until_decodable():
    data = random.Random(5).randbytes(100 * 8)
    encoder = online_codes.Encoder(data, 8)

    symbols = encoder.symbols(1)

    assert len(symbols) >= 101
    assert online_codes.recoverable(100, [esi for esi, _ in symbols])
    assert not online_codes.recoverable(100, [esi for esi, _ in symbols[:-1]])


def test_given_too_few_check_blocks_when_decoding_then_returns_none():
    data = random.Random(6).randbytes(100 * 8)
    encoder = online_codes.Encoder(data, 8)
    decoder = online_codes.Decoder(len(data), 8)

    assert all(decoder.add(esi, encoder.symbol(esi)) is None for esi in range(99))


def test_given_online_codec_when_encoding_chunk_then_no_packet_is_systematic():
    data = random.Random(7).randbytes(100 * 8)

    encoded = Encode(data, 8, codec=online_codes.CODEC)

    assert encoded.codec == online_codes.CODEC
    assert encoded.num_blocks == 100
    assert encoded.repair_packets == len(encoded.packets) - 100
    assert encoded.repair_packets >= 25


def _encode_file(tmp_path, proof_scheme, seal_packets=True):
    random.seed(0)
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(random.Random(8).randbytes(3000))
    servers = [
        {"id": index, "storage_location": str(tmp_path / f"server_{index}")}
        for index in range(3)
    ]
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": servers}))
    HyboltEncode(
        str(input_file),
        block_size=30,
        server_list=servers,
        metadata_output=str(tmp_path),
        chunk_count=2,
        redundancy=0.5,
        proof_scheme=proof_scheme,
        seal_packets=seal_packets,
        codec=online_codes.CODEC,
    ).encode()
    return input_file, tmp_path / "input_metadata.pkl", server_file


@pytest.fixture
def small_polynomial_set(monkeypatch):
    monkeypatch.setattr("hybolt.encryption.retrievability.POLYNOMIAL_SET_SIZE", 4)


@pytest.mark.parametrize("proof_scheme", ["bounded", "compact"])
def test_given_online_codec_when_encoding_and_decoding_file_then_round_trips(
    tmp_path, small_polynomial_set, proof_scheme
):
    input_file, metadata_file, server_file = _encode_file(tmp_path, proof_scheme)

    metadata = EncodingMetadata.load(metadata_file)

    assert {chunk.codec for chunk in metadata.chunks} == {online_codes.CODEC}
    assert Decode(metadata_file, server_file).decode() == input_file.read_bytes()


@pytest.mark.parametrize("proof_scheme", ["bounded", "compact"])
def test_given_online_codec_when_auditing_intact_file_then_passes(
    tmp_path, small_polynomial_set, proof_scheme
):
    _, metadata_file, server_file = _encode_file(tmp_path, proof_scheme)

    report = Audit(metadata_file, server_file).run()

    assert report.passed
    assert all(chunk.retrievable for chunk in report.chunks)


def _corrupt(packet_metadata):
    path = Path(packet_metadata.server) / packet_metadata.packet_file
    with open(path, "rb") as file:
        packet = pickle.load(file)
    packet.data = bytes(len(packet.data))
    with open(path, "wb") as file:
        pickle.dump(packet, file)


@pytest.mark.parametrize("proof_scheme", ["bounded", "compact"])
def test_given_corrupted_online_packets_when_redistributing_then_file_decodes(
    tmp_path, small_polynomial_set, proof_scheme
):
    input_file, metadata_file, server_file = _encode_file(tmp_path, proof_scheme)
    chunk = EncodingMetadata.load(metadata_file).chunks[0]
    for packet in chunk.packets[:3]:
        _corrupt(packet)

    report = Audit(metadata_file, server_file).run()
    redistribution = Redistribution(
        metadata_file, server_file, report.corrupted_packets
    ).run()

    assert redistribution.succeeded
    assert Audit(metadata_file, server_file).run().passed
    repaired = EncodingMetadata.load(metadata_file).chunks[0]
    assert online_codes.recoverable(
        repaired.source_packets, [packet.packet_index for packet in repaired.packets]
    )
    assert Decode(metadata_file, server_file).decode() == input_file.read_bytes()
