# Contributing

Github has a great guide for contributing to open source projects:

- [Contributing to a project](https://guides.github.com/activities/forking/)
- [Fork the repository](https://guides.github.com/activities/forking/#fork)
- [Clone your fork](https://guides.github.com/activities/forking/#clone)
- [Making and pushing changes](https://guides.github.com/activities/forking/#making-changes)
- [Making a Pull Request](https://guides.github.com/activities/forking/#making-a-pull-request)
- [Huzzah!](https://guides.github.com/activities/forking/#huzzah)

## pwntools Specifics

In general, we like to keep things documented.  You should add documentation to any new functionality, and update it for any changed functionality.  Our docstrings use the [Google Style Python Docstrings](https://sphinxcontrib-napoleon.readthedocs.org/en/latest/example_google.html#example-google).

After you have documentation, you should add a [doctest](https://docs.python.org/2/library/doctest.html).

Finally, it is probably a good idea to run the test suite locally before doing
the pull-request to make sure everything works, however this is not a
requirement.

Once you are ready to do a pull-request, you should figure out if your changes
constitutes a new feature or a bugfix in stable or beta. If it is a bugfix in
stable or beta, you should do the pull-request against the branch in question,
and otherwise your pull-request should be against the dev branch.

Once you do the pull-request Travis CI will run the test-suite on it. Once it
passes one of the core developers will look at your pull request, possibly
comment on it and then hopefully merge it into the branch in question.

## Automated Testing

Pull requests against Pwntools require at a minimum that no tests have been broken, and ideally each pull request will include new tests to ensure that all of the functionality works as intended.

You can find more information on testing in [TESTING.md](TESTING.md).
