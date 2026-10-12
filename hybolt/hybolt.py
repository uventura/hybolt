import json

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
from hybolt.logger.progress import set_progress
from hybolt.utils.debug import set_debugging


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
    "--debug",
    is_flag=True,
    help="Enable debug mode with detailed execution logs and timing instrumentation",
)
def encode_command(
    input_file, block_size, server_list, metadata_output, max_threads, debug
):
    with open(server_list, "r") as f:
        data = json.load(f)
    servers = data["servers"]

    _enable_debug_mode(debug)

    with _create_progress() as progress:
        set_progress(progress)
        hybolt_encode = HyboltEncode(
            input_file,
            block_size,
            servers,
            metadata_output,
            max_threads,
        )
        packet_count = hybolt_encode.encode()
        set_progress(None)

    click.echo(f"Encoded {packet_count} packets distributed to {len(servers)} servers")


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
def decode_command(metadata_file, server_file, output_file, debug):
    _enable_debug_mode(debug)

    with _create_progress() as progress:
        set_progress(progress)
        hybolt_decode = HyboltDecode(metadata_file, server_file, output_file)
        output_path = hybolt_decode.decode()
        set_progress(None)

    click.echo(f"Decoded file written to {output_path}")


if __name__ == "__main__":
    main()
