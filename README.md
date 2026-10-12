# HyBolt

HyBolt is a Python implementation of the cryptographic core of the HySAIL
storage protocol. It encodes a file into redundant packets, distributes those
packets across storage locations, and reconstructs the original data from the
packet metadata.

The implementation uses fountain-style packet encoding, XOR operations over
finite fields, and local MACs for packet integrity challenges.

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

Use `--block-size` on `encode` to select a block size in bytes. If it is
omitted, HyBolt chooses a size equal to 10% of the input file, with a minimum
of one byte.

MAC calculation uses up to eight worker threads by default. Use
`--max-threads` to select a lower limit between 1 and 8, for example:

```sh
hybolt encode --max-threads 4 --server-list examples/server_list_example.json examples/hello.txt
```

Pass `--debug` to either command to collect detailed execution timing and
diagnostic logs under `logs/`. Debug instrumentation is disabled by default.

## Development

```sh
make format
make test
make lorem_example
```

`make test` runs the `hybolt-test` command. The tests use the shipped
`examples/hello.txt` and `examples/server_list_example.json` fixtures while
redirecting storage to temporary directories.