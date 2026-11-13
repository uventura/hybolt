import json
from pathlib import Path

from hybolt.encryption.decoding_strategy import create_decoding_strategy
from hybolt.encryption.encoding_metadata import EncodingMetadata
from hybolt.encryption.retrievability import (
    BOUNDED_SCHEME,
    COMPACT_SCHEME,
    ChallengeLedger,
    create_retrievability_proof,
)
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
        self._metadata_file = Path(metadata_file)
        self._metadata = EncodingMetadata.load(self._metadata_file)
        execution_logger.debug(
            f"Loaded metadata from {metadata_file}: "
            f"chunks={len(self._metadata.chunks or [])}, "
            f"retrievability_proof={retrievability_proof}"
        )

    def decode(self):
        chunks = self._metadata.chunks
        if chunks is None:
            strategy, proof = self._create_strategy(self._metadata)
            self._reveal_one_challenge([proof])
            return strategy.decode()

        sorted_chunks = sorted(chunks, key=lambda item: item.chunk_index)
        # Build every strategy first so metadata that cannot back the proof fails
        # before a challenge polynomial is spent.
        strategies = [self._create_strategy(chunk) for chunk in sorted_chunks]
        self._reveal_one_challenge([proof for _, proof in strategies])

        decoded_chunks = []
        progress = get_progress()
        chunk_task_id = create_progress_task(
            progress,
            "Reconstructing chunks",
            total=len(sorted_chunks),
        )
        for chunk, (strategy, _) in zip(sorted_chunks, strategies):
            execution_logger.debug(
                f"Reconstructing chunk {chunk.chunk_index + 1}/{len(chunks)}"
            )
            decoded_chunks.append(strategy.decode()[: chunk.byte_size])
            advance_progress(progress, chunk_task_id)
        return b"".join(decoded_chunks)

    def _create_strategy(self, metadata):
        proof = self._create_proof(metadata)
        strategy = create_decoding_strategy(
            metadata, self._server_cache, proof, self._metadata.sealing_keys
        )
        return strategy, proof

    def _create_proof(self, metadata):
        if self._retrievability_proof and self._metadata.proof_scheme == COMPACT_SCHEME:
            if self._metadata.compact_keys is None:
                raise ValueError(
                    "compact metadata cannot back the retrievability proof: "
                    "missing client keys"
                )
            return create_retrievability_proof(
                True,
                scheme=COMPACT_SCHEME,
                keys=self._metadata.compact_keys,
                chunk_index=getattr(metadata, "chunk_index", 0),
            )
        return create_retrievability_proof(
            self._retrievability_proof,
            metadata.polynomials,
            scheme=self._metadata.proof_scheme or BOUNDED_SCHEME,
        )

    def _reveal_one_challenge(self, proofs):
        """Spend a single polynomial for the whole session (bounded model)."""
        if not proofs or not proofs[0].single_use_challenges:
            return

        ledger = ChallengeLedger(
            self._metadata, self._metadata_file, len(proofs[0].polynomials)
        )
        challenge_index = ledger.draw()
        for proof in proofs:
            proof.challenge_index = challenge_index

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
