# HyBolt

HyBolt is a Python implementation of the cryptographic core of the HySAIL
storage protocol. It encodes a file into redundant packets, distributes those
packets across storage locations, and reconstructs the original data from the
packet metadata.

The implementation uses RaptorQ (RFC 6330) fountain coding and stores a
SHA-256 integrity hash for every encoded packet.

## Requirements

- Python 3.10 or newer
- `make` (optional, for the shortcuts below)

## Setup

Create and activate the project environment:

```sh
python3 -m venv hybolt-env
source hybolt-env/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv hybolt-env
.\hybolt-env\Scripts\Activate.ps1
```

Install HyBolt in editable mode:

```sh
python -m pip install -e .
```

The equivalent Makefile target is:

```sh
make environment
```

## Core usage

The supplied server-list example describes three local packet-storage
directories. Encode one of the supplied example files with:

```sh
hybolt encode \
  --server-list examples/server_list_example.json \
  --metadata-output output \
  examples/hello.txt
```

This creates packet files in the configured storage locations and writes
`output/hello_metadata.pkl`. Keep the metadata file: it contains the packet
locations, local MAC data, source filename, and integrity hashes required for
recovery.

Recover the original file using that metadata and the same server list:

```sh
hybolt decode \
  --server-file examples/server_list_example.json \
  --output-file output/hello_decoded.txt \
  output/hello_metadata.pkl
```

HyBolt reads a source file in independent chunks sized from the security
parameter (`POLYNOMIAL_LAMBDA × 512` bytes; 65,024 bytes with the default
lambda). Each chunk is encoded, distributed, and represented separately in
metadata, allowing reconstruction to decode each chunk before joining them in
their original order. Use `--block-size` on `encode` to select the RaptorQ
symbol size inside each chunk. If omitted, HyBolt chooses a size equal to 10%
of that chunk, with a minimum of one byte.

Use `--chunk-count` to divide a file into an exact number of balanced chunks,
for example `hybolt encode --chunk-count 8 ...`. The command prints the
average MAC-and-packet-generation time per chunk after encoding completes.

### Proof of retrievability

By default, `encode` generates a set of challenge polynomials per chunk and
stores, for every packet, its remainder modulo each polynomial (a polynomial
MAC over GF(2)). Before `decode` downloads a packet, it challenges the server
with a random polynomial and only downloads the packet when the server's
remainder matches the stored MAC; the downloaded bytes are then checked against
the packet's SHA-256 hash. Packets that fail either check are skipped, and
decoding continues with the remaining redundant packets.

Disable the proof with `--no-retrievability-proof` on either command. Encoding
without it skips the MAC computation (much faster on large files) and produces
metadata that can only be decoded with `--no-retrievability-proof`; decoding
such metadata with the proof enabled fails with an explicit error. The SHA-256
check after each download stays active either way.

Each `encode` appends `file_path`, `file_size` (bytes), total `runtime`
(seconds) and average `block_size` (bytes) to `encode_runtime.json` in the log
directory (`logs/` by default). Plot runtime against file size with:

```sh
hybolt plot logs/encode_runtime.json \
  --output encode_runtime.png \
  --polynomial-division-output polynomial_division_runtime.png
```

Pass `--debug` to either command to collect detailed execution timing and
diagnostic logs under `logs/`. Use `--log-dir <directory>` to write
`execution.log` to a different directory, for example
`hybolt encode --debug --log-dir output/logs ...`. For long encodes, the
`logs/execution.log` file records the input size, block and packet counts, the
MAC-calculation progress for each block, packet distribution, and metadata
output. Debug instrumentation is disabled by default.

## Development

```sh
make format
make test
make lorem_example
make big_lorem_example
make all_lorem_ipsum_sizes
make binary_example
```

`make test` runs the `hybolt-test` command. The tests use the shipped
`examples/hello.txt` and `examples/server_list_example.json` fixtures while
redirecting storage to temporary directories.

`make lorem_example` and `make lorem_example_debug` encode the 3 KiB lorem
example, decode it into `output/3kib_decoded.txt`, and verify the decoded bytes
against the original file. They print `Passed` on an exact match and exit with
a failure status if the files differ.

`make big_lorem_example` and `make big_lorem_example_debug` run the same
round-trip verification for the 1 MiB
[`examples/lorem_ipsum/1024kib.txt`](examples/lorem_ipsum/1024kib.txt) fixture.
`make all_lorem_ipsum_sizes` encodes each lorem ipsum fixture smaller than
1,024 KiB in [`examples/lorem_ipsum/`](examples/lorem_ipsum/), then writes the
file-size/runtime and block-size/polynomial-division plots under `logs/`.

`make binary_example` compiles [examples/hello_world.c](examples/hello_world.c),
encodes and decodes the generated executable, compares the binary bytes, then
runs the decoded executable. A C compiler is required.

Benchmark RaptorQ encoding and recovery after packet loss with:

```sh
python scripts/fountain_codes_tests.py
```

The script writes `logs/fountain_codes_runtime.png`. Use `--sizes`,
`--samples`, and `--loss-count` to change its workload.