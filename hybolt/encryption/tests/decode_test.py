import hashlib
import json
import pickle

import numpy as np
import pytest

import hybolt.utils.galois as ga
from hybolt.encryption.block import Block, LocalBlock
from hybolt.encryption.decode import Decode
from hybolt.encryption.encoding_metadata import (
    BlockMetadata,
    EncodingMetadata,
    PacketMetadata,
)
from hybolt.hybolt_encode import HyboltEncode
from hybolt.server.server import Server

POLYNOMIAL = np.array([1, 0, 1, 1] + [0] * 12 + [1], dtype=np.uint8)


def _mac(data):
    return ga.gf2_poly_mod(ga.bytes_to_poly_coeffs(data), POLYNOMIAL)


def _write_server_file(tmp_path, server_dirs):
    server_file = tmp_path / "servers.json"
    server_file.write_text(
        json.dumps(
            {
                "servers": [
                    {"id": index, "storage_location": str(server_dir)}
                    for index, server_dir in enumerate(server_dirs, start=1)
                ]
            }
        )
    )
    return server_file


def _write_lt_metadata(tmp_path, source_blocks):
    server_dir = tmp_path / "server1"
    server_dir.mkdir()
    for index, data in enumerate(source_blocks):
        with open(server_dir / f"payload_packet_{index}.pkl", "wb") as file:
            pickle.dump(Block(index, 1, [index], data), file)

    metadata = EncodingMetadata(
        polynomials=[POLYNOMIAL],
        blocks=[
            BlockMetadata(mac_value=_mac(data), block_index=index, polynomial_index=0)
            for index, data in enumerate(source_blocks)
        ],
        packets=[
            PacketMetadata(
                server=str(server_dir),
                packet_index=index,
                degree=1,
                indices=[index],
                packet_file=f"payload_packet_{index}.pkl",
                packet_sha256=hashlib.sha256(data).hexdigest(),
            )
            for index, data in enumerate(source_blocks)
        ],
        original_filename="payload.txt",
    )
    metadata_file = tmp_path / "payload_metadata.pkl"
    metadata.save(metadata_file)
    return server_dir, metadata_file, _write_server_file(tmp_path, [server_dir])


def _encode_raptorq(tmp_path, retrievability_proof):
    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"HyBolt proves retrievability before downloads.")
    server_dirs = [tmp_path / f"server_{index}" for index in range(2)]
    servers = [
        {"id": index, "storage_location": str(server_dir)}
        for index, server_dir in enumerate(server_dirs)
    ]
    HyboltEncode(
        str(input_file),
        block_size=8,
        server_list=servers,
        metadata_output=str(tmp_path),
        retrievability_proof=retrievability_proof,
    ).encode()
    return (
        input_file,
        tmp_path / "input_metadata.pkl",
        _write_server_file(tmp_path, server_dirs),
    )


def _forbid_challenges(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("receive_challenge must not be called")

    monkeypatch.setattr(Server, "receive_challenge", fail)


def test_given_lt_metadata_when_decoding_then_reconstructs_data(tmp_path):
    _, metadata_file, server_file = _write_lt_metadata(tmp_path, [b"ABCD", b"WXYZ"])

    decoder = Decode(metadata_file=metadata_file, server_file=server_file)

    assert decoder.decode() == b"ABCDWXYZ"


def test_given_tampered_lt_packet_on_disk_when_decoding_then_challenge_rejects_it(
    tmp_path,
):
    server_dir, metadata_file, server_file = _write_lt_metadata(
        tmp_path, [b"ABCD", b"WXYZ"]
    )
    with open(server_dir / "payload_packet_1.pkl", "wb") as file:
        pickle.dump(Block(1, 1, [1], b"EVIL"), file)

    decoder = Decode(metadata_file=metadata_file, server_file=server_file)

    with pytest.raises(ValueError, match="Insufficient verified blocks"):
        decoder.decode()


def test_given_lt_metadata_when_decoding_with_proof_disabled_then_skips_challenges(
    tmp_path, monkeypatch
):
    _, metadata_file, server_file = _write_lt_metadata(tmp_path, [b"ABCD", b"WXYZ"])
    _forbid_challenges(monkeypatch)

    decoder = Decode(metadata_file, server_file, retrievability_proof=False)

    assert decoder.decode() == b"ABCDWXYZ"


def test_given_raptorq_encoded_with_proof_when_decoding_then_challenges_and_reconstructs(
    tmp_path, monkeypatch
):
    input_file, metadata_file, server_file = _encode_raptorq(tmp_path, True)
    challenged = []
    original_receive_challenge = Server.receive_challenge

    def record(self, *args, **kwargs):
        challenged.append(args[1])
        return original_receive_challenge(self, *args, **kwargs)

    monkeypatch.setattr(Server, "receive_challenge", record)

    decoded = Decode(metadata_file, server_file).decode()

    assert decoded == input_file.read_bytes()
    assert challenged


def test_given_raptorq_packet_tampered_on_disk_when_decoding_then_uses_other_packets(
    tmp_path,
):
    input_file, metadata_file, server_file = _encode_raptorq(tmp_path, True)
    metadata = EncodingMetadata.load(metadata_file)
    tampered = metadata.chunks[0].packets[0]
    tampered_path = f"{tampered.server}/{tampered.packet_file}"
    with open(tampered_path, "rb") as file:
        packet = pickle.load(file)
    packet.data = bytes(len(packet.data))
    with open(tampered_path, "wb") as file:
        pickle.dump(packet, file)

    decoded = Decode(metadata_file, server_file).decode()

    assert decoded == input_file.read_bytes()


def test_given_raptorq_encoded_without_proof_when_decoding_with_proof_then_raises(
    tmp_path,
):
    _, metadata_file, server_file = _encode_raptorq(tmp_path, False)

    with pytest.raises(ValueError, match="cannot back the retrievability proof"):
        Decode(metadata_file, server_file).decode()


def test_given_raptorq_encoded_without_proof_when_decoding_without_proof_then_reconstructs(
    tmp_path, monkeypatch
):
    input_file, metadata_file, server_file = _encode_raptorq(tmp_path, False)
    _forbid_challenges(monkeypatch)

    decoded = Decode(metadata_file, server_file, retrievability_proof=False).decode()

    assert decoded == input_file.read_bytes()


def test_given_metadata_saved_before_packet_macs_when_loading_then_backfills_empty_macs(
    tmp_path,
):
    packet = PacketMetadata("server", 0, 1, [0])
    del packet.macs
    metadata = EncodingMetadata(polynomials=[], blocks=[], packets=[packet])
    metadata_file = tmp_path / "legacy_metadata.pkl"
    metadata.save(metadata_file)

    loaded = EncodingMetadata.load(metadata_file)

    assert loaded.packets[0].macs == []


def test_given_lt_metadata_when_loading_then_local_blocks_carry_packet_hashes(tmp_path):
    _, metadata_file, server_file = _write_lt_metadata(tmp_path, [b"ABCD"])
    decoder = Decode(metadata_file, server_file)

    strategy = decoder._create_strategy(decoder._metadata)

    block = strategy._local_blocks[1][0]
    assert isinstance(block, LocalBlock)
    assert block.packet_sha256 == hashlib.sha256(b"ABCD").hexdigest()
