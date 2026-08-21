# Uplink Access (Python)

Uplink Access is python library for Storj access management.

## Roadmap

- [ ] Creating access
- [X] Restricting access
- [X] Registering access with edge services

## Local Development

### Setting Up Virtual Environment

1. Create a new virtual environment

       $ python3 -m venv .venv

2. Activate the virtual environment

       $ . ./venv/bin/activate

3. Install the project into the virtual environment as an editable project

       (.venv) $ python3 -m pip install -e ".[dev,tests]"

### Style

This project has been formatted using `black`. New code should also be
formatted with `black`. `tox` will automatically run `black` on the code when
executing tests.

### Unit Testing

This repo uses `tox` for test execution. To run tests, do the following:

1. Activate the virtual environment (if not already activated)

       $ . ./venv/bin/activate

2. Install `tox` into the virtual environment (if not already installed)

       (.venv) $ python3 -m pip install tox

3. Run tox to execute tests

       (.venv) $ tox

### Access Grant Interoperability Fixtures

Regenerate the synthetic Go/Python fixtures (no satellite or credentials are
used) with Go 1.25 or newer:

       PYTHONPATH=src python tests/interop/test_access_grant_interop.py

### Protobuf (Re)generation

The proto files in this repo were copied from [storj/common](https://github.com/storj/common). The import statements were modified to be relative to the src directory, which is paramount to ensure the python import statements in the generated code will work.

To regenerate the proto files:

1. Activate the virtual environment (if not already activated)

       $ . ./venv/bin/activate

2. Run protoc (version >= v25) with protoc-gen-mypy (installed in virtualenv)

       (.venv) $ protoc -Isrc --python_out=src --mypy_out=src src/uplink/common/pb/*.proto src/uplink/common/macaroon/types.proto

## Examples

There are code examples [here](./tests/test_examples.py).

## CLI Tool

This project includes a rudimentary CLI tool `access`.
