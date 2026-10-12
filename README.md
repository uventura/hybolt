# HyBoat

HyBoat is a Python implementation of the cryptographic core of the HySAIL
storage protocol. It encodes a file into redundant packets, distributes those
packets across storage locations, and reconstructs the original data from the
packet metadata.

The implementation uses fountain-style packet encoding, XOR operations over
finite fields, and local MACs for packet integrity challenges. It is a
cryptographic storage toolkit only: it has no blockchain, smart-contract, or
DApp components.

## Requirements

- Python 3.10 or newer
- `make` (optional, for the shortcuts below)

## Setup

Create and activate the project environment:

```sh
python3 -m venv hyboat-env
source hyboat-env/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv hyboat-env
.\hyboat-env\Scripts\Activate.ps1
```

Install HyBoat in editable mode:

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
hyboat encode \
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
hyboat decode \
  --server-file examples/server_list_example.json \
  --output-file output/hello_decoded.txt \
  output/hello_metadata.pkl
```

Use `--block-size` on `encode` to select a block size in bytes. If it is
omitted, HyBoat chooses a size equal to 10% of the input file, with a minimum
of one byte.

Pass `--debug` to either command to collect detailed execution timing and
diagnostic logs under `logs/`. Debug instrumentation is disabled by default.

## Development

```sh
make format
make test
make lorem_example
```

`make test` runs the `hyboat-test` command. The tests use the shipped
`examples/hello.txt` and `examples/server_list_example.json` fixtures while
redirecting storage to temporary directories.