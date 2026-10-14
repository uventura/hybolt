import json
from pathlib import Path

ENCODE_RUNTIME_FILE_NAME = "encode_runtime.json"


def load_runtime_records(path: str | Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as records_file:
        records = json.load(records_file)
    if not isinstance(records, list):
        raise ValueError(f"{path} must contain a JSON list of runtime records")
    return records


def append_runtime_record(
    log_dir: str | Path,
    file_path: str | Path,
    file_size: int,
    runtime: float,
    block_size: float,
    polynomial_division_runtime: float,
) -> Path:
    records_path = Path(log_dir) / ENCODE_RUNTIME_FILE_NAME
    records = load_runtime_records(records_path) if records_path.exists() else []
    records.append(
        {
            "file_path": str(file_path),
            "file_size": file_size,
            "runtime": runtime,
            "block_size": block_size,
            "polynomial_division_runtime": polynomial_division_runtime,
        }
    )
    records_path.parent.mkdir(parents=True, exist_ok=True)
    with records_path.open("w", encoding="utf-8") as records_file:
        json.dump(records, records_file, indent=2)
    return records_path


def plot_runtime_records(records_path: str | Path, output_path: str | Path) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    records = load_runtime_records(records_path)
    if not records:
        raise ValueError(f"{records_path} contains no runtime records")

    records = sorted(records, key=lambda record: record["file_size"])
    figure, axis = plt.subplots()
    axis.plot(
        [record["file_size"] for record in records],
        [record["runtime"] for record in records],
        marker="o",
        linewidth=2,
    )
    axis.set_title("Encode runtime by file size")
    axis.set_xlabel("file size (bytes)")
    axis.set_ylabel("runtime (s)")
    axis.grid(True, linestyle="--", alpha=0.4)
    figure.tight_layout()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path)
    plt.close(figure)
    return output_path


def plot_polynomial_division_runtime(
    records_path: str | Path, output_path: str | Path
) -> Path:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    records = [
        record
        for record in load_runtime_records(records_path)
        if "block_size" in record and "polynomial_division_runtime" in record
    ]
    if not records:
        raise ValueError(
            f"{records_path} contains no polynomial division runtime records"
        )

    records.sort(key=lambda record: record["block_size"])
    figure, axis = plt.subplots()
    axis.plot(
        [record["block_size"] for record in records],
        [record["polynomial_division_runtime"] for record in records],
        marker="o",
        linewidth=2,
    )
    axis.set_title("Polynomial division runtime by block size")
    axis.set_xlabel("average block size (bytes)")
    axis.set_ylabel("average polynomial division runtime (s)")
    axis.grid(True, linestyle="--", alpha=0.4)
    figure.tight_layout()
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output_path)
    plt.close(figure)
    return output_path
