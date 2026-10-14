import json
import time
from pathlib import Path

from hybolt.encryption.digest import chunk_size_for_lambda
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_decode import HyboltDecode
from hybolt.hybolt_encode import HyboltEncode
from hybolt.logger.progress import set_progress


EXAMPLES_DIRECTORY = Path(__file__).parents[2] / "examples"


def test_given_hello_example_when_encoding_then_uses_example_server_list(tmp_path):
    example_servers = json.loads(
        (EXAMPLES_DIRECTORY / "server_list_example.json").read_text(encoding="utf-8")
    )
    for server in example_servers["servers"]:
        server["storage_location"] = str(tmp_path / f"server_{server['id']}")

    metadata_directory = tmp_path / "metadata"
    metadata_directory.mkdir()
    hybolt_encode = HyboltEncode(
        str(EXAMPLES_DIRECTORY / "hello.txt"),
        block_size=4,
        server_list=example_servers["servers"],
        metadata_output=str(metadata_directory),
    )

    packet_count = hybolt_encode.encode()
    metadata = EncodingMetadata.load(metadata_directory / "hello_metadata.pkl")

    assert packet_count > 0
    assert metadata.chunks is not None
    assert sum(len(chunk.packets) for chunk in metadata.chunks) == packet_count
    assert metadata.original_filename == "hello.txt"
    assert metadata.original_file_hash
    assert hybolt_encode.average_chunk_encode_seconds > 0


def test_given_encoding_when_logging_then_records_phase_and_block_progress(
    tmp_path, monkeypatch
):
    input_file = tmp_path / "input.txt"
    input_file.write_text("HyBolt", encoding="utf-8")
    messages = []
    monkeypatch.setattr("hybolt.hybolt_encode.execution_logger.debug", messages.append)
    monkeypatch.setattr(
        "hybolt.encryption.encode.execution_logger.debug", messages.append
    )
    monkeypatch.setattr(
        "hybolt.server.packet_saver.execution_logger.debug", messages.append
    )

    HyboltEncode(
        str(input_file),
        block_size=3,
        server_list=[{"id": 1, "storage_location": str(tmp_path / "server")}],
        metadata_output=str(tmp_path),
    ).encode()

    assert any(message.startswith("Encoding input:") for message in messages)
    assert any(
        message.startswith("Generating ") and "RaptorQ packets" in message
        for message in messages
    )
    assert "Packet distribution completed" in messages
    assert "Encoding completed successfully" in messages


def test_given_chunked_file_when_encoding_and_decoding_then_reports_chunk_progress(
    tmp_path,
):
    class ProgressRecorder:
        def __init__(self):
            self.tasks = {}

        def add_task(self, description, total):
            task_id = len(self.tasks)
            self.tasks[task_id] = {
                "completed": 0,
                "description": description,
                "total": total,
            }
            return task_id

        def advance(self, task_id):
            self.tasks[task_id]["completed"] += 1

    input_file = tmp_path / "input.txt"
    input_file.write_bytes(b"HyBolt")
    server_path = tmp_path / "server"
    servers = [{"id": 1, "storage_location": str(server_path)}]
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": servers}), encoding="utf-8")
    progress = ProgressRecorder()

    set_progress(progress)
    try:
        HyboltEncode(
            str(input_file),
            block_size=3,
            server_list=servers,
            metadata_output=str(tmp_path),
        ).encode()
        HyboltDecode(
            str(tmp_path / "input_metadata.pkl"),
            str(server_file),
            str(tmp_path / "decoded.txt"),
        ).decode()
    finally:
        set_progress(None)

    chunk_tasks = [
        task
        for task in progress.tasks.values()
        if task["description"].endswith("chunks")
    ]
    assert {
        (task["description"], task["completed"], task["total"]) for task in chunk_tasks
    } == {
        ("Encoding chunks", 1, 1),
        ("Reconstructing chunks", 1, 1),
    }


def test_given_one_mebib_lorem_when_round_tripping_then_uses_chunked_metadata_within_runtime(
    tmp_path,
):
    input_file = EXAMPLES_DIRECTORY / "lorem_ipsum" / "1024kib.txt"
    assert input_file.stat().st_size >= 1024 * 1024

    server_paths = [tmp_path / f"server_{index}" for index in range(3)]
    servers = [
        {"id": index, "storage_location": str(server_path)}
        for index, server_path in enumerate(server_paths, start=1)
    ]
    server_file = tmp_path / "servers.json"
    server_file.write_text(json.dumps({"servers": servers}), encoding="utf-8")
    metadata_directory = tmp_path / "metadata"

    started_at = time.monotonic()
    packet_count = HyboltEncode(
        str(input_file),
        server_list=servers,
        metadata_output=str(metadata_directory),
    ).encode()
    metadata_file = metadata_directory / "1024kib_metadata.pkl"
    metadata = EncodingMetadata.load(metadata_file)
    output_file = tmp_path / "reconstructed.txt"
    reconstructed = HyboltDecode(
        str(metadata_file), str(server_file), str(output_file)
    ).decode()
    elapsed = time.monotonic() - started_at

    assert metadata.chunks is not None
    assert len(metadata.chunks) > 1
    assert all(chunk.byte_size <= chunk_size_for_lambda() for chunk in metadata.chunks)
    assert packet_count == sum(len(chunk.packets) for chunk in metadata.chunks)
    assert output_file.read_bytes() == input_file.read_bytes()
    assert reconstructed == output_file
    assert elapsed < 120
