# Contributing

We love pull requests!

Github has a great guide for contributing to open source projects:

- [Contributing to a project](https://guides.github.com/activities/forking/)
- [Fork the repository](https://guides.github.com/activities/forking/#fork)
- [Clone your fork](https://guides.github.com/activities/forking/#clone)
- [Making and pushing changes](https://guides.github.com/activities/forking/#making-changes)
- [Making a Pull Request](https://guides.github.com/activities/forking/#making-a-pull-request)
- [Huzzah!](https://guides.github.com/activities/forking/#huzzah)

## Pwntools Specifics

In general, we like to keep things documented.  You should add documentation to any new functionality, and update it for any changed functionality.  Our docstrings use the [Google Style Python Docstrings](https://sphinxcontrib-napoleon.readthedocs.org/en/latest/example_google.html#example-google).

After you have documentation, you should add a [doctest](https://docs.python.org/2/library/doctest.html).

Finally, it is probably a good idea to run the test suite locally before doing
the pull-request to make sure everything works, however this is not a
requirement.

Once you do the pull-request Travis CI will run the test-suite on it. Once it
passes one of the core developers will look at your pull request, possibly
comment on it and then hopefully merge it into master.

## Test Suite

To run the test suite, you should be running Ubuntu 12.04 or 14.04, and run the following commands.  **Be aware** that this will add a user to your machine, and create a public key for SSH login!

```sh
bash .travis_install.sh
bash .travis_ssh_setup.sh
cd docs
pip install -r requirements.txt
make doctest
```
