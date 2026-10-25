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

from hybolt.audit.audit import Audit
from hybolt.audit.redistribution import Redistribution
from hybolt.hybolt_decode import HyboltDecode
from hybolt.hybolt_encode import HyboltEncode
from hybolt.constant import DEFAULT_REDUNDANCY, MAX_MAC_THREADS
from hybolt.encryption.digest import Digest
from hybolt.encryption.retrievability import BOUNDED_SCHEME, COMPACT_SCHEME
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
    help="R10 symbol size in bytes; if omitted, each chunk is split into "
    "100 symbols",
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
    "--retrievability-proof/--no-retrievability-proof",
    default=True,
    show_default=True,
    help="Compute per-packet polynomial MACs so servers can be challenged before downloads",
)
@click.option(
    "--proof-scheme",
    type=click.Choice([COMPACT_SCHEME, BOUNDED_SCHEME]),
    default=COMPACT_SCHEME,
    show_default=True,
    help="compact: unbounded audits with server-side tags; "
    "bounded: Hy-SAIL's single-use challenges with client-side MACs",
)
@click.option(
    "--seal-packets/--no-seal-packets",
    default=True,
    show_default=True,
    help="Encrypt packets and give them opaque names so servers cannot see "
    "which packets belong to the same chunk",
)
@click.option(
    "--redundancy",
    type=click.FloatRange(min=0, min_open=True),
    default=DEFAULT_REDUNDANCY,
    show_default=True,
    help="Repair packets generated per source packet of each chunk",
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
    retrievability_proof,
    proof_scheme,
    seal_packets,
    redundancy,
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
            retrievability_proof,
            redundancy,
            proof_scheme,
            seal_packets,
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
    "--retrievability-proof/--no-retrievability-proof",
    default=True,
    show_default=True,
    help="Challenge each server with a polynomial division before downloading its packet",
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
def decode_command(
    metadata_file, server_file, output_file, retrievability_proof, debug, log_dir
):
    execution_logger.set_log_directory(log_dir)
    _enable_debug_mode(debug)

    with _create_progress() as progress:
        set_progress(progress)
        hybolt_decode = HyboltDecode(
            metadata_file, server_file, output_file, retrievability_proof
        )
        output_path = hybolt_decode.decode()
        set_progress(None)

    click.echo(f"Decoded file written to {output_path}")


@main.command("audit")
@click.argument("metadata_file", type=click.Path(exists=True))
@click.option(
    "--server-file",
    type=click.Path(exists=True),
    required=True,
    help="JSON file with server information for auditing",
)
@click.option(
    "--sample-size",
    type=click.IntRange(1),
    default=None,
    help="Packets challenged per server in this round; all of them if omitted",
)
@click.option(
    "--tau-maximum",
    type=click.IntRange(0),
    default=0,
    show_default=True,
    help="Corrupted packets tolerated per server before it fails the audit",
)
@click.option(
    "--redistribute",
    is_flag=True,
    help="Replace corrupted packets with fresh repair packets on other servers",
)
@click.option(
    "--extra-repair",
    type=click.IntRange(0),
    default=0,
    show_default=True,
    help="Additional repair packets added to each redistributed chunk",
)
@click.option(
    "--log-dir",
    type=click.Path(file_okay=False, dir_okay=True),
    default="logs",
    show_default=True,
    help="Directory where execution.log is written",
)
def audit_command(
    metadata_file,
    server_file,
    sample_size,
    tau_maximum,
    redistribute,
    extra_repair,
    log_dir,
):
    execution_logger.set_log_directory(log_dir)
    try:
        report = Audit(metadata_file, server_file, sample_size, tau_maximum).run()
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    if report.polynomial_index is None:
        click.echo(f"{report.scheme.capitalize()} audit (unbounded challenges)")
    else:
        click.echo(
            f"Challenge polynomial {report.polynomial_index} "
            f"({report.remaining_challenges} challenges remaining)"
        )
    for server in report.servers:
        status = "OK" if server.passed else "FAILED"
        click.echo(
            f"  server {server.server}: {server.checked_packets}/"
            f"{server.stored_packets} packets checked, tau_provider="
            f"{server.tau_provider} (tau_maximum={server.tau_maximum}) [{status}]"
        )
    for chunk in report.chunks:
        if chunk.corrupted:
            status = "retrievable" if chunk.retrievable else "AT RISK"
            click.echo(
                f"  chunk {chunk.chunk_index}: {chunk.corrupted} corrupted, "
                f"{chunk.tolerated_losses} tolerated [{status}]"
            )

    if report.passed and not report.corrupted_packets:
        click.echo("Audit passed")
        return

    click.echo(
        f"Audit found {len(report.corrupted_packets)} corrupted packets", err=True
    )
    if not redistribute or not report.corrupted_packets:
        raise SystemExit(1)

    try:
        redistribution = Redistribution(
            metadata_file, server_file, report.corrupted_packets, extra_repair
        ).run()
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    for replaced in redistribution.replaced:
        click.echo(
            f"  chunk {replaced.chunk_index}: packet {replaced.old_packet_index} "
            f"({replaced.from_server}) replaced by new packet "
            f"{replaced.new_packet_index} ({replaced.to_server})"
        )
    for added in redistribution.added:
        click.echo(
            f"  chunk {added.chunk_index}: added packet {added.packet_index} "
            f"({added.server})"
        )
    for chunk_index, reason in redistribution.failed_chunks.items():
        click.echo(f"  chunk {chunk_index} not redistributed: {reason}", err=True)

    click.echo(
        f"Replaced {len(redistribution.replaced)} packets and added "
        f"{len(redistribution.added)} repair packets"
    )
    if not redistribution.succeeded:
        raise SystemExit(1)


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
