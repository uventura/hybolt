import json
from pathlib import Path

from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.hybolt_encode import HyboltEncode


EXAMPLES_DIRECTORY = Path(__file__).parents[2] / "examples"


def test_hello_example_encodes_using_the_example_server_list(tmp_path):
    example_servers = json.loads(
        (EXAMPLES_DIRECTORY / "server_list_example.json").read_text(encoding="utf-8")
    )
    for server in example_servers["servers"]:
        server["storage_location"] = str(tmp_path / f"server_{server['id']}")

    metadata_directory = tmp_path / "metadata"
    metadata_directory.mkdir()
    packet_count = HyboltEncode(
        str(EXAMPLES_DIRECTORY / "hello.txt"),
        block_size=4,
        server_list=example_servers["servers"],
        metadata_output=str(metadata_directory),
    ).encode()

    metadata = EncodingMetadata.load(metadata_directory / "hello_metadata.pkl")

    assert packet_count > 0
    assert len(metadata.packets) == packet_count
    assert metadata.original_filename == "hello.txt"
    assert metadata.original_file_hash
