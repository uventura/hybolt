# HyBolt

HyBolt is a Python implementation of the cryptographic core of the HySAIL
storage protocol. It encodes a file into redundant packets, distributes those
packets across storage locations, and reconstructs the original data from the
packet metadata.

The implementation uses Raptor R10 (RFC 5053) fountain coding, stores a SHA-256
integrity hash for every encoded packet, and implements Hy-SAIL's polynomial
MAC proof of retrievability with auditing and redistribution of corrupted
packets.

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
their original order. Use `--block-size` on `encode` to select the R10
symbol size inside each chunk. If omitted, HyBolt chooses a size equal to 10%
of that chunk, with a minimum of one byte. R10 codes between 4 and 8,192 source
symbols per block: shorter chunks are padded with zero symbols, and a block
size that would need more than 8,192 symbols is rejected.

### Raptor R10

[`hybolt/encryption/raptor.py`](hybolt/encryption/raptor.py) implements the
systematic Raptor code of RFC 5053. All of its constraints (LDPC, Half and LT)
are XORs, so every packet, repair packets included, is the XOR of a subset of
the chunk's source symbols, which `raptor.symbol_support(K, esi)` returns as a
bit mask. Packets are stored without a header: the client metadata already
holds each packet's ESI. Repair symbols match those of
[gofountain](https://github.com/google/gofountain), an independent RFC 5053
implementation.

Use `--chunk-count` to divide a file into an exact number of balanced chunks,
for example `hybolt encode --chunk-count 8 ...`. The command prints the
average MAC-and-packet-generation time per chunk after encoding completes.

### Redundancy

Each chunk is encoded into its K source packets plus `ceil(redundancy * K)`
R10 repair packets. Set the ratio with `--redundancy` on `encode` (default
`0.25`). Unlike RaptorQ, R10 is not close to an MDS code: K received packets
decode a chunk only some of the time, and a few extra packets are needed for a
reliable recovery, so a chunk does not always survive the loss of all of its
repair packets.

### Proof of retrievability

`encode` supports two proof schemes, chosen with `--proof-scheme`:

- `compact` (default): unbounded audits in the style of Shacham and Waters'
  private-key PoR. The client keeps a secret primitive polynomial P of degree
  127, a PRF key and a file id. Each server stores, next to every packet, the
  tag `(packet mod P) xor PRF(file, chunk, ESI)`. An audit sends random
  coefficients; the server answers with the combination of the sampled packets
  and of their tags, and the client checks it with P, which never leaves the
  client. Decoding checks every downloaded packet against its tag.
- `bounded`: Hy-SAIL's original model. The client stores one MAC per source
  block for each of 40 primitive challenge polynomials, and derives the MAC of
  any packet as the XOR of the MACs of its support (plus the MAC of its
  keystream when packets are sealed). Each audit round reveals one
  unused polynomial, which is never reused, because a server that knows it
  could keep only the remainders. The set therefore supports 40 challenges
  (audits and decodes) per encode. Aggregates are weighted by secret powers of
  x so that packets corrupted with the same error cannot cancel out.

Audit the stored packets without downloading them:

```sh
hybolt audit \
  --server-file examples/server_list_example.json \
  output/hello_metadata.pkl
```

Each round challenges a random sample of every server's packets
(`--sample-size`, all packets by default). When a server's answer fails, the
sampled packets are checked individually to locate the corrupted ones. A server
fails when it holds more than `--tau-maximum` corrupted packets (default `0`),
and a chunk is at risk when the supports of its remaining packets no longer
span its K source blocks.
The command exits with status 1 when it finds corruption.

Add `--redistribute` to replace the corrupted or lost packets. As in Hy-SAIL,
the chunk is not decoded: each lost packet is replaced by a fresh R10 repair
packet with a never-used ESI, computed as the XOR of healthy packets whose
supports combine into the new packet's support. Only those packets are
downloaded and checked against their SHA-256, and the new packet is stored on
the least-loaded server of the chunk. `--extra-repair N` adds N more repair
packets to each repaired chunk to widen its margin. A server missing from the
server file has all of its packets reported lost, and decoding continues
without it.

With packets balanced over N servers, losing f of them is tolerated while
`redundancy >= f / (N - f)`. With three servers, for example, `--redundancy
0.5` is needed to survive one server leaving.

Disable the proof with `--no-retrievability-proof` on `encode` or `decode`.
The SHA-256 check after each download stays active either way.

### Hiding the code structure

By default, packets are sealed before distribution. Each one is encrypted
with a keystream bound to its file, chunk and ESI, and stored under an opaque
name. Servers cannot read the systematic source symbols,
and cannot tell which packets belong to the same chunk. Without sealing, a
server could destroy a file by corrupting `r + 1` packets of a single chunk.
Use `--no-seal-packets` to store plain packets.

The client must keep the metadata file private: it holds the challenge
polynomials, the PRF key and the sealing key.

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

Benchmark R10 encoding and recovery after packet loss with:

```sh
python scripts/fountain_codes_tests.py
```

The script writes `logs/fountain_codes_runtime.png`. Use `--sizes`,
`--samples`, and `--loss-count` to change its workload.

Reproduce the measurements and figures of the thesis results chapter with:

```sh
python scripts/thesis_benchmarks.py all
```

Raw data goes to `logs/thesis/` and PDF figures to `doc/thesis/img/resultados/`.
Name experiments to run a subset (`degrees`, `mac`, `overhead`, `loss`,
`pipeline`, `detection`, `hysail`), pass `--quick` for tiny workloads, or
`replot` to redraw the slow experiments from the saved data. The full run
encodes files of up to 500 MB and takes about 15 minutes.