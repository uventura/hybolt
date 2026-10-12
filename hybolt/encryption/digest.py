from collections.abc import Iterator
from pathlib import Path

from hybolt.constant import POLYNOMIAL_LAMBDA

_BYTES_PER_LAMBDA_UNIT = 512


def chunk_size_for_lambda(lambda_value: int = POLYNOMIAL_LAMBDA) -> int:
    if lambda_value <= 0:
        raise ValueError("lambda_value must be a positive integer")

    return lambda_value * _BYTES_PER_LAMBDA_UNIT


class Digest:
    """Reads a source file as independently encodable chunks."""

    def __init__(
        self,
        input_path: str | Path,
        lambda_value: int = POLYNOMIAL_LAMBDA,
        chunk_count: int | None = None,
    ):
        self.input_path = Path(input_path)
        self.chunk_size = chunk_size_for_lambda(lambda_value)
        self._chunk_count = chunk_count
        self._chunk_sizes = self._determine_chunk_sizes()

    def chunks(self) -> Iterator[tuple[int, bytes]]:
        with self.input_path.open("rb") as source:
            for index, chunk_size in enumerate(self._chunk_sizes):
                yield index, source.read(chunk_size)

    @property
    def chunk_count(self) -> int:
        return len(self._chunk_sizes)

    def _determine_chunk_sizes(self) -> list[int]:
        file_size = self.input_path.stat().st_size
        if self._chunk_count is None:
            return [
                min(self.chunk_size, file_size - offset)
                for offset in range(0, file_size, self.chunk_size)
            ]

        if self._chunk_count <= 0:
            raise ValueError("chunk_count must be a positive integer")
        if self._chunk_count > file_size:
            raise ValueError("chunk_count cannot exceed the input file size in bytes")

        base_size, extra_bytes = divmod(file_size, self._chunk_count)
        return [
            base_size + (1 if index < extra_bytes else 0)
            for index in range(self._chunk_count)
        ]
