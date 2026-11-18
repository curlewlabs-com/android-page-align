"""Check that an Android APK or app bundle's native libraries load on 16 KB
memory pages. See the README.

The command and the check are one module, check.py, which imports only the
standard library so it can also be run as a single file.
"""

import sys

# Checked here, before any other module of the package is imported, so an older
# interpreter gets this message rather than a syntax error from a newer form.
if sys.version_info < (3, 12):  # noqa: UP036 - the point is to run on older ones
    sys.exit("android-page-align needs Python 3.12 or newer")
