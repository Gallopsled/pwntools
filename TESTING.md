# Testing

Pwntools makes extensive use of unit tests and integration tests to ensure everything is in working order, and no regressions occur.

## Test Suite

To run the test suite, it is best to use Ubuntu 22.04 or 24.04, and run the following commands.  **Be aware** that this will add a user to the machine, and create a public key for SSH login!

```sh
bash travis/install.sh
bash travis/ssh_setup.sh
pip install --upgrade --editable .
pip install --upgrade -r docs/requirements.txt
PWNLIB_NOTERM=1 make -C docs doctest
```

You can run doctests for a single file for faster iteration:

```sh
PWNLIB_NOTERM=1 python -m sphinx -b doctest docs/source docs/build/doctest docs/source/elf/elf.rst
```

## Testing in Docker

A `Dockerfile` has been provided which has a clean testing environment with Ubuntu Noble.  It is very similar to the online Github Actions CI testing environment.

See `travis/docker/README.md` for more information.

## New Tests

To add a new test to an existing module, just add an inline doctest.  If the test needs access to an external module, add the import statement to the `testsetup` block in the corresponding file in `docs/source/<module>.rst`.

To add an entirely new module, create a new `module.rst` and add it to the list in `index.rst`.  The best way to see if your tests are actually being run is to add an intentionally-failing test like:

```py
>>> assert False
```

## Example Test Module

The module `pwnlib.testexample` exists to demonstrate how everything is tied together.  The only files which were modified to add this example module and run its tests automatically are:

- `pwnlib/testexample.py`
- `docs/source/testexample.rst`
- `docs/source/index.rst`

## Shellcode and ROP

These are both less easy to test, as they require actually executing code, or loading real binaries.  In order to make the process simpler, the `runner` library was created to wrap common tasks.  For an example of testing shellcode with these helpers, see [exit.asm](pwnlib/shellcraft/templates/i386/linux/exit.asm).

Additionally, for loading ELF files on-the-fly, the helpers `ELF.from_bytes` and `ELF.from_assembly` are available.
