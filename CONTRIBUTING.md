# Contributing

Thanks for your interest in improving `android-page-align`. The bar for a
change is whether it keeps the check failing closed: a library it cannot read
is reported, never passed. An artifact layout it misreads, a sharper message,
and clearer docs are all welcome.

## Reporting an artifact it gets wrong

Include what the check printed, and what a 16 KB-page device or emulator did
with the artifact. If you can, include the program headers of the library in
question (`llvm-readelf -lW lib.so`) and, for an APK, the output of
`zipalign -c -P 16 -v 4 app.apk`. Please do not attach an artifact you are not
free to share.

## Running the checks

These are the checks CI runs on every push and pull request:

```sh
python3 -m unittest discover -s tests -t .
python3 -m pip install -r requirements-dev.txt
mypy
```

## Conventions

- **Tests ship with the change.** A bug fix or a feature includes a test in
  the same pull request. A test that guards a failure mode says which one.
- **Fail closed.** A library or archive the check cannot read is a finding,
  with the reason.
- **Fixtures are built in the tests.** ELF headers are packed with `struct`
  and archives written with `zipfile`; no binary is checked in.
- **Standard library only.** `check.py` must keep running as a single file.
- **Pin dependencies exactly.** An action reference is its release's commit
  SHA with the version beside it, since a tag can be moved. The tools in
  `requirements-dev.txt` are exact versions. Renovate proposes their updates.
  A pin written inline needs a `# renovate:` comment above it saying what the
  literal is.
- **Comments explain why, not what.**
- **Keep tracked text ASCII.** Use plain hyphens and words instead of Unicode
  punctuation or decorative symbols.

## Submitting

Keep each pull request focused on one change, make sure the checks pass, and
describe the why in the pull request body. CI must be green before merge.

## Releasing

A patch or minor release needs no approval: whoever cuts it follows the steps
below in order, on a `main` commit whose required checks have passed. A major
version, a 1.0, or a minor before 1.0 that changes an interface consumers use
needs the maintainer's explicit approval before its tag is pushed.

Every release gets a fixed `vMAJOR.MINOR.PATCH` tag. The repository blocks
updates and deletions of those tags, and publishing the GitHub Release makes the
tag immutable.

1. Bump `version` in `pyproject.toml` and merge that to `main`.
2. Tag the merge commit `vMAJOR.MINOR.PATCH` and push the tag.
3. Publish it: `gh release create vMAJOR.MINOR.PATCH --verify-tag`.

## License

By submitting a contribution for inclusion in this project, you agree that it
is licensed under the MIT and Apache-2.0 licenses, as the README's License
section describes, without any additional terms or conditions.
