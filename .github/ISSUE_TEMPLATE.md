# Pwntools Issue Template

Thanks for contributing to Pwntools!

When reporting an issue, be sure that you are running the latest released version of pwntools (`pip install --upgrade pwntools`).

Please verify that your issue occurs on 64-bit Ubuntu 14.04.  You can use the Dockerfile on `docker.io` for quick testing.

```
$ docker pull pwntools/pwntools:stable
$ docker run -it pwntools/pwntools:stable
```

If possible, provide a proof-of-concept which demonstrates the problem.  Include any binaries or scripts necessary to reproduce the issue, and please include the full debug output via setting the environment variable `PWNLIB_DEBUG=1`.
