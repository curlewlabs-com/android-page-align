# android-page-align

## What it is

A check that every native library in an Android APK or app bundle (`.aab`)
can be loaded on a device that uses 16 KB memory pages. It reads the artifact
itself, using only the Python standard library, and exits 1 naming each
library that fails and the reason. It needs no Android SDK, NDK, emulator or
device, so it runs as a CI step anywhere Python runs.

## Why it exists

Android 15 and newer can run with 16 KB memory pages, and Google Play requires
apps that target Android 15 and higher to support them on 64-bit devices
([Google's guide](https://developer.android.com/guide/practices/page-sizes)).
On such a device a native library loads only if two things hold:

- **Its ELF segments are aligned for 16 KB pages.** Every `PT_LOAD` segment of
  a 64-bit `.so` must declare `p_align` of at least `0x4000`.
- **In an APK, its bytes sit where the loader can map them.** An app that
  stores its native libraries uncompressed (`extractNativeLibs="false"`) has
  them mapped in place out of the APK, so each one must be stored, not
  compressed, and start on a 16 KB boundary in the archive.

Your own code is usually fine: current NDK and Android Gradle Plugin versions
produce both by default. The failures come from prebuilt `.so` files that
arrive with dependencies, linked with flags nobody on your project chose. A
16 KB emulator finds those only for the one ABI it runs, only in the build you
install, and as an install failure or an `UnsatisfiedLinkError`. Reading the
artifact covers every packaged ABI of the build that ships, and names the
library.

## How to use it

It needs Python 3.12 or newer. It has no dependencies.

```sh
pip install git+https://github.com/curlewlabs-com/android-page-align@v0.1.1

android-page-align app/build/outputs/apk/release/app-release.apk
android-page-align app/build/outputs/bundle/release/app-release.aab
```

`python3 -m android_page_align` works the same way.
`src/android_page_align/check.py` imports only the standard library, so you can
also copy that one file and run it with `python3 check.py`.

Give it one or more artifacts. Its only inputs are the artifact paths; there
are no options. For each artifact that passes it prints one line to stdout:

```
OK app-release.aab: every packaged native library maps on 16 KB pages
```

For each one that fails, it prints the artifact and one line per finding to
stderr, then exits 1:

```
FAIL app-release.apk
  lib/arm64-v8a/libfoo.so: LOAD segment alignment 0x1000, needs 0x4000
  lib/x86_64/libbar.so: compressed in the APK, must be stored
```

It also exits 1, with the reason, when it cannot read an artifact, when an
artifact holds no `.so` at all (usually the wrong file), and when it is given
no artifact. A check that judged nothing never reads as a pass.

## What it checks

- **Every `.so` entry in the archive** is read as ELF, wherever it sits. A
  64-bit library fails if any `PT_LOAD` segment's `p_align` is below
  `0x4000`, or if it has no `PT_LOAD` segment. ELF32 and ELF64 are read in
  either byte order.
- **32-bit libraries are exempt from the alignment rule**, decided by the ELF
  class in each file's header, not by the directory it sits in. 16 KB pages are
  a 64-bit feature: the NDK applies its page-size handling to `arm64-v8a` and
  `x86_64` only, and NDK r28, whose default is 16 KB alignment, ships its own
  `armeabi-v7a` `libc++_shared.so` aligned to `0x1000`.
- **A `.so` it cannot read fails.** Something named `.so` that is not an ELF
  file, or whose program header table is truncated or has an entry size too
  small to hold the fields, is a finding rather than a skip.
- **In an APK** (a file whose name ends `.apk`), every `lib/<abi>/<name>.so`
  entry must be stored uncompressed and start on a 16 KB boundary. The offset
  is read from the entry's local header, where `zipalign` writes its padding.

## What a pass does not cover

- **An app that packs its libraries compressed fails by design.** With
  `useLegacyPackaging = true` the libraries are extracted at install, and a 16
  KB device can load them. This check is for apps that store libraries
  uncompressed and map them in place, and it does not read the manifest to
  decide which kind an APK is.
- **For an app bundle, only the ELF side is read.** Play builds the installed
  APKs from the bundle, and where it places the libraries in them is set by the
  bundle's own configuration, which this does not read.
  `bundletool dump config --bundle=app.aab` shows it (look for
  `PAGE_ALIGNMENT_16K`).
- **The `PT_GNU_RELRO` condition is not checked.** Google's guide also asks
  that, where `GNU_RELRO` shares a writable `LOAD` segment with data after it,
  the RELRO segment end at a 16 KB boundary. This check does not read
  `GNU_RELRO`.
- **Code that assumes a 4096-byte page** at run time (`PAGE_SIZE`, `mmap`
  arguments) can still fail. Only running on a 16 KB device or emulator finds
  that.

## Other tools

Google's guide describes checks you can run with the Android SDK and NDK
installed:

- `check_elf_alignment.sh`, from AOSP, takes an APK, a directory or an APEX
  file; an app bundle is not one of its inputs. For each ELF file it reads the
  alignment of the first `LOAD` segment. It checks an APK's zip placement only
  when a `zipalign` from build-tools 35.0.0-rc3 or newer is on `PATH`.
- `zipalign -c -P 16 4 app.apk`, from build-tools 35.0.0 or newer, checks where
  an APK's stored entries start. It checks the archive, not the libraries' ELF
  headers.
- Android Studio's APK Analyzer and lint flag unaligned libraries in the IDE.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

By submitting a contribution for inclusion in this project, you agree that it
is dual licensed as above, without any additional terms or conditions.
