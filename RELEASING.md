# Releasing and publishing vodozemac

While the release process can be handled manually, cargo-release has been
configured to make it more convenient.

By default, [`cargo-release`](https://github.com/crate-ci/cargo-release) assumes
that no pull request is required to cut a release. However, since the vodozemac
repo is set up so that each push requires a pull request, we need to slightly
deviate from the default workflow.

The procedure is as follows:

1. Switch to a release branch:

```bash
git switch -c release-x.y.z
```

2. Prepare the release. This will update the README.md, prepend the CHANGELOG.md
   file using `git cliff`, and bump the version in the `Cargo.toml` file.

```bash
cargo release --no-publish --no-tag --no-push --execute major|minor|patch|rc
```

3. Double-check and edit the changelog and README if necessary. Once you are
   satisfied, push the branch and open a PR.

```bash
git push --set-upstream origin/release-x.y.z
```

4. Pass the review and merge the branch as you would with any other branch.

5. Create a tag for your new release:

```bash
# Switch to main first.
git switch main
# Pull in the now-merged release commit(s).
git pull
# Run cargo-release to tag the commit, push the tag, and publish vodozemac on crates.io.
cargo release tag --execute
```

6. Publish the release to crates.io:

```bash
cargo release publish --execute
```

7. Push the tag to the repository:

```bash
cargo release push --execute
```

8. Create a GitHub release from the pushed tag and copy the updates from the
   changelog to the GitHub release.

For more information on cargo-release: https://github.com/crate-ci/cargo-release
