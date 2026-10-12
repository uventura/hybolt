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

    def __init__(self, input_path: str | Path, lambda_value: int = POLYNOMIAL_LAMBDA):
        self.input_path = Path(input_path)
        self.chunk_size = chunk_size_for_lambda(lambda_value)

    def chunks(self) -> Iterator[tuple[int, bytes]]:
        with self.input_path.open("rb") as source:
            for index in range(self.chunk_count):
                chunk = source.read(self.chunk_size)
                if not chunk:
                    break
                yield index, chunk

    @property
    def chunk_count(self) -> int:
        file_size = self.input_path.stat().st_size
        return (file_size + self.chunk_size - 1) // self.chunk_size
