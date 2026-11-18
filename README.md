# android-page-align

## What it is

A check that every native library in an Android APK or app bundle (`.aab`),
or a shared library on its own, meets the conditions Google documents for a
device that uses 16 KB memory pages. It reads the files themselves, using only
the Python standard library, and exits 1 naming each library that fails and
the reason. It needs no Android SDK, NDK, emulator or device, so it runs as a
CI step anywhere Python runs.

## Why it exists

Android 15 and newer can run with 16 KB memory pages, and Google Play requires
apps that target Android 15 and higher to support them on 64-bit devices
([Google's guide](https://developer.android.com/guide/practices/page-sizes)).
The guide documents three conditions a native library must meet there:

- **Its ELF segments are aligned for 16 KB pages.** Every `PT_LOAD` segment of
  a 64-bit `.so` must declare `p_align` of at least `0x4000`.
- **Its RELRO range does not end on a page shared with writable data.** After
  relocation the loader makes `PT_GNU_RELRO` read-only a whole 16 KB page at a
  time, so writable data (`.data`, `.bss`) on the rest of the page holding the
  RELRO end faults on its first write.
- **In an APK, its bytes sit where the loader can map them.** An app that
  stores its native libraries uncompressed (`extractNativeLibs="false"`) has
  them mapped in place out of the APK, so each one must be stored, not
  compressed, and start on a 16 KB boundary in the archive.

Your own code is usually fine: current NDK and Android Gradle Plugin versions
produce all three by default. The failures come from prebuilt `.so` files that
arrive with dependencies, linked with flags nobody on your project chose. A
16 KB emulator finds those only for the one ABI it runs, only in the build you
install, and as an install failure or an `UnsatisfiedLinkError`. Reading the
artifact covers every packaged ABI of the build that ships, and names the
library.

## How to use it

It needs Python 3.12 or newer. It has no dependencies.

```sh
pip install git+https://github.com/curlewlabs-com/android-page-align@v0.3.0

android-page-align app/build/outputs/apk/release/app-release.apk
android-page-align app/build/outputs/bundle/release/app-release.aab
android-page-align build/arm64-v8a/libfoo.so
```

`python3 -m android_page_align` works the same way.
`src/android_page_align/check.py` imports only the standard library, so you can
also copy that one file and run it with `python3 check.py`.

Give it one or more paths. Its only inputs are those paths; there are no
options. A path ending `.so` is read as one shared library, which checks it
before it is packaged; anything else is read as an APK or app bundle. For each
input that passes it prints one line to stdout:

```
OK app-release.aab: every packaged native library maps on 16 KB pages
OK build/arm64-v8a/libfoo.so: maps on 16 KB pages
```

For each one that fails, it prints the artifact and one line per finding to
stderr, then exits 1:

```
FAIL app-release.apk
  lib/arm64-v8a/libfoo.so: LOAD segment alignment 0x1000, needs 0x4000
  lib/arm64-v8a/libbaz.so: GNU_RELRO ends at 0xe1000, not a 0x4000 boundary, and its LOAD segment ends at 0xe4000
  lib/x86_64/libbar.so: compressed in the APK, must be stored
```

It also exits 1, with the reason, when it cannot read an input, when an
artifact holds no `.so` at all (usually the wrong file), and when it is given
no input. A check that judged nothing never reads as a pass.

## What it checks

- **Every `.so` entry in the archive** is read as ELF, wherever it sits. A
  64-bit library fails if any `PT_LOAD` segment's `p_align` is below
  `0x4000`, or if it has no `PT_LOAD` segment. ELF32 and ELF64 are read in
  either byte order.
- **A 64-bit library fails the RELRO condition** unless one of the three ways
  the guide's "Check the RELRO security flag" section states holds, read
  exactly as stated:
  1. there is no `PT_GNU_RELRO` segment;
  2. the RELRO end, `p_vaddr + p_memsz`, is a multiple of `0x4000`; or
  3. the RELRO ends exactly where its containing `PT_LOAD` segment ends, the
     one that holds the RELRO's start.

  A finding means none of the three holds, and its text shows each: it names
  the RELRO end, which is off a 16 KB boundary, and where its containing `LOAD`
  ends, which is somewhere else (or that no `LOAD` contains it). Each
  `GNU_RELRO` header is read on its own.

- **32-bit libraries are exempt from both ELF rules**, decided by the ELF
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
- **A shared library given on its own** (a path ending `.so`) takes the two
  ELF rules. Where it will sit in an APK is not known yet, so placement is not
  checked.

### Reading the RELRO condition by its end alone is wrong

The second way, an aligned RELRO end, is easy to take for the whole condition,
and read on its own it fails most current libraries that comply. LLD pads the
RELRO end only to 4 KB and gives writable data a `LOAD` segment of its own, so
the RELRO usually ends off a 16 KB boundary but exactly where its `LOAD` ends:
the third way. NDK r28c's own arm64-v8a `libc++_shared.so` is an example:

```
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x127898 0x000000000012f898 0x000000000012f898 0x009b98 0x00a768 RW  0x4000
  LOAD           0x131430 0x000000000013d430 0x000000000013d430 0x000238 0x007d20 RW  0x4000
  GNU_RELRO      0x127898 0x000000000012f898 0x000000000012f898 0x009b98 0x00a768 R   0x1
```

Its RELRO ends at `0x13a000`, `0x2000` past a 16 KB boundary, which is exactly
where its containing `LOAD` ends. It complies. In one release app bundle we
measured, holding 28 64-bit libraries from six toolchains, 19 ended their RELRO
off a 16 KB boundary and every one of those complied by the third way; none
failed the condition as Google states it.

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
- **The RELRO verdict is the condition Google documents, read from the program
  headers.** It is not a model of the Android loader, and the documented
  condition does not speak to every layout the loader handles. These are judged
  by the three ways as stated, not by what the loader would do with them:
  - another writable or executable `LOAD` sharing the 16 KB page the RELRO is
    protected in;
  - several `GNU_RELRO` headers, each read on its own rather than together;
  - page-rounded bounds: the loader protects and maps whole pages, so a RELRO
    padded past its `LOAD`'s declared end, or starting on its `LOAD`'s first
    page before the `LOAD`'s first byte, is judged by the stated condition.
- **It reads headers; it does not run anything.** Neither a pass nor a finding
  is a test on a device.
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
