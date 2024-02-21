# Testing in a Can

This is a Dockerfile which has all of the requirements for testing pwntools.

It's pretty simple, just run `make`.  All of your changes will be copied into the docker container, and the doctest suite will be executed automatically.

```shell
$ make -C travis/docker ANDROID=yes
$ make -C travis/docker ANDROID=no TARGET=ssh.rst
```

By default the Python 3 tests are run. You can choose the Python version using the `doctest2` or `doctest3` target.

```shell
$ make -C travis/docker ANDROID=no doctest2
```

You can get drop into a tmux session in the container to debug tests using the `shell` or `bash` targets.

```shell
$ make -C travis/docker shell
```

## Options

Currently, the options `TARGET` and `ANDROID` are available.

### `ANDROID`

Controls whether or not to run the Android test.  The valid options are ``yes`` (the default) and ``no``.

### `TARGET`

This is appended to the `sphinx` command line, but generally is useful to select a specific `rst` file to parse (e.g. to only run those tests).

## Known Issues

Currently, some tests are broken when executed in Docker.

- `process.leak()` is broken, as it relies on `/proc/<pid>/mem`
- `srop` tests are broken, since there are issues with `SYS_sigreturn` when running in Docker.
