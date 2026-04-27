# Contributing

Github has a great guide for contributing to open source projects:

- [Contributing to a project](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project)
- [Fork the repository](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project#creating-your-own-copy-of-a-project)
- [Clone your fork](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project#cloning-a-fork-to-your-computer)
- [Creating a branch to work on](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project#creating-a-branch-to-work-on)
- [Making and pushing changes](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project#making-and-pushing-changes)
- [Making a Pull Request](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project#making-a-pull-request)

## pwntools Specifics

In general, we like to keep things documented.  You should add documentation to any new functionality, and update it for any changed functionality.  Our docstrings use the [Google Style Python Docstrings](https://sphinxcontrib-napoleon.readthedocs.org/en/latest/example_google.html#example-google).

After you have documentation, you should add a [doctest](https://docs.python.org/3/library/doctest.html).

Finally, it is probably a good idea to run the test suite locally before doing
the pull-request to make sure everything works, however this is not a
requirement. See the [TESTING](TESTING.md) documentation on how to do that.

Once you are ready to do a pull-request, you should figure out if your changes
constitutes a new feature or a bugfix in stable or beta. If it is a bugfix in
stable or beta, you should do the pull-request against the branch in question,
and otherwise your pull-request should be against the dev branch.

Once you do the pull-request Github Actions will run the test-suite on it. Once it
passes one of the core developers will look at your pull request, possibly
comment on it and then hopefully merge it into the branch in question.

## Python Type Hints

Since Pwntools 5 dropped support for Python 2, type hints are added gradually to the existing code base.
[Type hints in Python](https://typing.python.org/en/latest/spec/index.html) allow static analysis tools and IDEs to help catch errors and provide a better developer
experience without running the code.

New code should include type hints where applicable and shouldn't add new type warnings.
You can use [this cheat sheet](https://mypy.readthedocs.io/en/stable/cheat_sheet_py3.html) as a reference for the type hint syntax.

Pwntools uses [mypy](https://mypy.readthedocs.io/en/stable/index.html) as a static type checker. Instead of trying to
introduce type hints everywhere at once, Pwntools uses [mypy-baseline](https://mypy-baseline.orsinium.dev/usage) to gradually reduce the number of problems over time.

To run the type checker locally, you can install Pwntools with the `dev` extra and check for new errors (`--group dev` requires pip 25.1+):

```shell
$ pip install -U . --group dev
$ mypy | mypy-baseline filter
```

If you fixed some problems, you can update the list of known errors in `mypy-baseline.txt` using

```shell
$ mypy | mypy-baseline sync --sort-baseline
```

## Automated Testing

Pull requests against Pwntools require at a minimum that no tests have been broken, and ideally each pull request will include new tests to ensure that all of the functionality works as intended.

You can find more information on testing in [TESTING.md](TESTING.md).
