# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it
privately via
[GitHub's security advisory feature](https://github.com/curlewlabs-com/android-page-align/security/advisories/new).

Do not open a public issue for security vulnerabilities.

## Scope

The check reads the archives it is given and runs nothing: no subprocess, no
network, nothing written. The security surface is:

- **The archives it reads.** These are the paths named on the command line,
  opened with Python's `zipfile`. Every entry whose name ends `.so` is
  decompressed into memory whole to read its headers, so an archive built to
  inflate without bound can exhaust memory. The check is meant for artifacts
  your own build produced.
- **A false pass.** A library the check passes that a 16 KB-page loader
  refuses, for one of the conditions the README says it checks, is a defect in
  what it promises. Report it as a bug, or privately if you think it matters
  more than that.
