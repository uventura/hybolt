import json
from pathlib import Path

from hybolt.encryption.decoding_strategy import create_decoding_strategy
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import create_retrievability_proof
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import (
    advance_progress,
    create_progress_task,
    get_progress,
)
from hybolt.server.server import Server


class Decode:
    def __init__(self, metadata_file, server_file, retrievability_proof=True):
        self._servers = self._load_servers(server_file)
        self._server_cache = {
            server._storage_location: server for server in self._servers
        }
        self._retrievability_proof = retrievability_proof
        self._metadata = EncodingMetadata.load(Path(metadata_file))
        execution_logger.debug(
            f"Loaded metadata from {metadata_file}: "
            f"chunks={len(self._metadata.chunks or [])}, "
            f"retrievability_proof={retrievability_proof}"
        )

    def decode(self):
        chunks = self._metadata.chunks
        if chunks is None:
            return self._create_strategy(self._metadata).decode()

        decoded_chunks = []
        sorted_chunks = sorted(chunks, key=lambda item: item.chunk_index)
        progress = get_progress()
        chunk_task_id = create_progress_task(
            progress,
            "Reconstructing chunks",
            total=len(sorted_chunks),
        )
        for chunk in sorted_chunks:
            execution_logger.debug(
                f"Reconstructing chunk {chunk.chunk_index + 1}/{len(chunks)}"
            )
            strategy = self._create_strategy(chunk)
            decoded_chunks.append(strategy.decode()[: chunk.byte_size])
            advance_progress(progress, chunk_task_id)
        return b"".join(decoded_chunks)

    def _create_strategy(self, metadata):
        proof = create_retrievability_proof(
            self._retrievability_proof, metadata.polynomials
        )
        return create_decoding_strategy(metadata, self._server_cache, proof)

    def _load_servers(self, server_file):
        with open(server_file, "r") as file:
            data = json.load(file)

        servers = [
            Server(server_dict["storage_location"])
            for server_dict in data.get("servers", [])
        ]

        execution_logger.debug(f"Loaded {len(servers)} servers from {server_file}")
        for server in servers:
            execution_logger.debug(
                f"Generated server: storage_location={server._storage_location}"
            )

        return servers
