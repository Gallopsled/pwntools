# Pwntools Pull Request

Thanks for contributing to Pwntools!  Take a moment to look at [`CONTRIBUTING.md`][contributing] to make sure you're familiar with Pwntools development.

Please provide a high-level explanation of what this pull request is for.

## Testing

Pull Requests that introduce new code should try to add doctests for that code.  See [`TESTING.md`][testing] for more information.

## Target Branch

Depending on what the PR is for, it needs to target a different branch.

You can always [change the branch][change] after you create the PR if it's against the wrong branch.

| Branch   | Type of PR                                                       |
| -------- | ---------------------------------------------------------------- |
| `dev`    | New features, and enhancements
| `dev`    | Documentation fixes and new tests
| `stable` | Bug fixes that affect the current `stable` branch
| `beta`   | Bug fixes that affect the current `beta` branch, but not `stable`
| `dev`    | Bug fixes for code that has never been released

[contributing]: https://github.com/Gallopsled/pwntools/blob/dev/CONTRIBUTING.md
[testing]: https://github.com/Gallopsled/pwntools/blob/dev/TESTING.md
[change]: https://github.com/blog/2224-change-the-base-branch-of-a-pull-request
