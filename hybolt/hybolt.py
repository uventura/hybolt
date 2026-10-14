import json
import os
import time

import click
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from hybolt.hybolt_decode import HyboltDecode
from hybolt.hybolt_encode import HyboltEncode
from hybolt.constant import MAX_MAC_THREADS
from hybolt.encryption.digest import Digest
from hybolt.logger.logger import execution_logger
from hybolt.logger.progress import set_progress
from hybolt.utils.debug import set_debugging
from hybolt.utils.runtime_records import (
    append_runtime_record,
    plot_polynomial_division_runtime,
    plot_runtime_records,
)


def _create_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
    )


def _enable_debug_mode(debug):
    if debug:
        set_debugging(True)


@click.group()
def main():
    pass


@main.command("encode")
@click.argument("input_file", type=click.Path(exists=True))
@click.option(
    "--block-size",
    type=int,
    default=None,
    help="Block size for encoding; if omitted, uses 10% of the file size",
)
@click.option(
    "--server-list",
    type=click.Path(exists=True),
    required=True,
    help="JSON file with server list schema: {'servers': [{'id': <number>, 'storage_location': <location>}, ...]}",
)
@click.option(
    "--metadata-output",
    type=click.Path(),
    default="./",
    show_default=True,
    help="Path where the metadata file will be written",
)
@click.option(
    "--max-threads",
    type=click.IntRange(1, MAX_MAC_THREADS),
    default=MAX_MAC_THREADS,
    show_default=True,
    help="Maximum worker threads used to calculate MAC blocks",
)
@click.option(
    "--chunk-count",
    type=click.IntRange(1),
    default=None,
    help="Split the input into exactly this many chunks",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode with detailed execution logs and timing instrumentation",
)
@click.option(
    "--log-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default="logs",
    show_default=True,
    help="Directory where execution.log is written",
)
def encode_command(
    input_file,
    block_size,
    server_list,
    metadata_output,
    max_threads,
    chunk_count,
    debug,
    log_dir,
):
    with open(server_list, "r") as f:
        data = json.load(f)
    servers = data["servers"]
    if chunk_count is not None:
        try:
            Digest(input_file, chunk_count=chunk_count)
        except ValueError as error:
            raise click.BadParameter(str(error), param_hint="--chunk-count") from error

    execution_logger.set_log_directory(log_dir)
    _enable_debug_mode(debug)

    with _create_progress() as progress:
        set_progress(progress)
        hybolt_encode = HyboltEncode(
            input_file,
            block_size,
            servers,
            metadata_output,
            max_threads,
            chunk_count,
        )
        encode_started_at = time.perf_counter()
        packet_count = hybolt_encode.encode()
        encoding_runtime = time.perf_counter() - encode_started_at
        set_progress(None)

    append_runtime_record(
        log_dir,
        input_file,
        os.path.getsize(input_file),
        encoding_runtime,
        hybolt_encode.average_block_size,
        hybolt_encode.average_polynomial_division_seconds,
    )
    click.echo(
        f"Encoded {packet_count} packets distributed to {len(servers)} servers. "
        f"Average chunk encoding time: "
        f"{hybolt_encode.average_chunk_encode_seconds:.3f}s. "
        f"Total encoding runtime: {encoding_runtime:.3f}s"
    )


@main.command("decode")
@click.argument("metadata_file", type=click.Path(exists=True))
@click.option(
    "--server-file",
    type=click.Path(exists=True),
    required=True,
    help="JSON file with server information for decoding",
)
@click.option(
    "--output-file",
    type=click.Path(),
    default="./",
    show_default=True,
    help="Path where the decoded file will be written",
)
@click.option(
    "--debug",
    is_flag=True,
    help="Enable debug mode with detailed execution logs and timing instrumentation",
)
@click.option(
    "--log-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default="logs",
    show_default=True,
    help="Directory where execution.log is written",
)
def decode_command(metadata_file, server_file, output_file, debug, log_dir):
    execution_logger.set_log_directory(log_dir)
    _enable_debug_mode(debug)

    with _create_progress() as progress:
        set_progress(progress)
        hybolt_decode = HyboltDecode(metadata_file, server_file, output_file)
        output_path = hybolt_decode.decode()
        set_progress(None)

    click.echo(f"Decoded file written to {output_path}")


@main.command("plot")
@click.argument("runtime_file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--output",
    type=click.Path(dir_okay=False),
    default="encode_runtime.png",
    show_default=True,
    help="Path of the generated plot image",
)
@click.option(
    "--polynomial-division-output",
    type=click.Path(dir_okay=False),
    default="polynomial_division_runtime.png",
    show_default=True,
    help="Path of the polynomial division runtime plot image",
)
def plot_command(runtime_file, output, polynomial_division_output):
    try:
        output_path = plot_runtime_records(runtime_file, output)
        polynomial_division_output_path = plot_polynomial_division_runtime(
            runtime_file, polynomial_division_output
        )
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    click.echo(f"Runtime plot written to {output_path}")
    click.echo(
        "Polynomial division runtime plot written to "
        f"{polynomial_division_output_path}"
    )


if __name__ == "__main__":
    main()
