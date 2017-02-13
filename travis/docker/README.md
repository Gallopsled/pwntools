# Testing in a Can

This is a Dockerfile which has all of the requirements for testing pwntools.

It's pretty simple, just run `make`.  All of your changes will be copied into the docker container, and the doctest suite will be executed automatically.

```shell
$ make -C travis/docker ANDROID=yes
$ make -C travis/docker ANDROID=no TARGET=docs/source/tubes/ssh.rst
```

## Options

Currently, the options `TARGET` and `ANDROID` are available.

### `ANDROID`

Controls whether or not to run the Android test.  The valid options are ``yes`` (the default) and ``no``.

### `TARGET`

This is appended to the `sphinx` command line, but generally is useful to sepcify a specific `rst` file to parse (e.g. to only run those tests).

## Known Issues

Currently, some tests are broken when executed in Docker.

- `process.leak()` is broken, as it relies on `/proc/<pid>/mem`
- `srop` tests are broken, since there are issues with `SYS_sigreturn` when running in Docker.
