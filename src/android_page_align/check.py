"""Refuse an Android artifact whose native libraries cannot load on 16 KB pages.

Owns the whole check: reading each native library's ELF program headers out of
an APK or app bundle, or from a shared library given on its own, reading where
each library's bytes start inside an APK, and the verdict. It imports only the standard library, so this file also runs
on its own.

WHY READ THE ARTIFACT. Most of the native code an app packages is not built by
the app: it arrives prebuilt with dependencies, linked with flags nobody on the
project chose. A device or emulator running 16 KB pages finds an unloadable
library eventually, but only for the one ABI it runs, only in the build it
installs, and as an install failure or an `UnsatisfiedLinkError` far from the
cause. Reading the artifact covers every packaged ABI of the build that ships,
needs no device, and names the library and the reason.

WHAT A PASS MEANS, because it is narrower than "the app works on 16 KB pages":
every packaged library meets the 16 KB conditions Google documents, read from
its headers. It says nothing about code that assumes a page is 4096 bytes once
it is running, it is not a model of the Android loader, and it does not read
an app bundle's own page-alignment setting. The README lists what a pass does
not cover.

LOAD ALIGNMENT, RELRO END AND ZIP PLACEMENT, the three conditions Google's
16 KB guide documents (developer.android.com/guide/practices/page-sizes).

  ELF LOAD ALIGNMENT - every `PT_LOAD` segment of every 64-bit `.so` declares
    `p_align` of at least 16 KB. 32-bit ABIs are exempt, and the reason is
    checkable rather than asserted: the NDK scopes the entire flexible-page-size
    treatment to the 64-bit ABIs. Its own build files gate the opt-out on
    the ABI - `-Wl,-z,max-page-size=4096` is added only for `arm64-v8a` and
    `x86_64` (`build/cmake/flags.cmake` and `build/core/build-binary.mk`) -
    because a 32-bit ABI has no page size to choose. Which is why the NDK, at
    the revision whose DEFAULT is 16 KB alignment, emits `0x1000` for
    `armeabi-v7a`: applying the bar there would fail an artifact on libraries
    Google's own toolchain produced, and the only ways to pass it would be
    patching a third-party prebuilt or dropping 32-bit devices.

  RELRO END - every 64-bit `.so` meets the condition the guide's "Check the
    RELRO security flag" section states, read exactly as stated: it has no
    `PT_GNU_RELRO`; or the RELRO end (`p_vaddr + p_memsz`) is a multiple of
    16 KB; or the RELRO ends exactly where its containing `PT_LOAD` segment
    ends. Each `GNU_RELRO` header is read on its own. All three ways are read,
    because the second alone is the misreading: LLD pads the RELRO end only to
    4 KB and gives writable data a `LOAD` of its own, so most current libraries
    fail the second and comply by the third. This is the documented condition,
    not the loader's behavior; the README names the layouts it does not speak
    to. 32-bit ABIs are exempt, as for LOAD alignment.

  ZIP PLACEMENT, for an APK only. An app that stores its native libraries
    uncompressed (`extractNativeLibs="false"` in its merged manifest) is
    installed without unpacking them: the loader maps each library in place
    out of the APK, which puts a requirement on the ENTRY's own layout. It has
    to start on a 16 KB boundary and be stored uncompressed. An app bundle is
    not an install artifact (Play builds the APKs from it), so how its entries
    sit is not checked.

The zip condition is unconditional rather than read from the manifest, and that
is deliberate: deciding it would mean parsing binary AndroidManifest.xml, and
the only artifact the answer changes is one built with legacy packaging
(`useLegacyPackaging`), whose compressed libraries are extracted at install.
Such an APK fails here by design. Compressing the libraries is a packaging
decision with a 16 KB consequence for an app that maps them in place, and this
check is for apps that do.

A shared library given on its own (a `.so` path) takes the two ELF conditions,
for a library checked before it is packaged; placement is a property of an APK
entry, so it does not apply.

Usage:
  android-page-align <artifact.apk|artifact.aab|library.so> [...]

Exit codes:
  0 - every native library clears its load, RELRO and placement conditions
  1 - one or more do not, or an input could not be read
"""

from __future__ import annotations

import re
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, override

# Android's 16 KB page size. ELF requires `p_align` be a power of two, so
# "at least this" is also "a multiple of this" and needs no second test.
PAGE_16K: Final = 16 * 1024

ELFCLASS32: Final = 1
ELFCLASS64: Final = 2
ELFDATA2LSB: Final = 1
ELFDATA2MSB: Final = 2
PT_LOAD: Final = 1
PT_GNU_RELRO: Final = 0x6474E552

# `lib/<abi>/<name>.so` - the layout the loader maps out of an APK, as opposed to
# a `.so` riding in assets, which it does not. Not anchored at the start of the
# path: an unanchored match can only ADD entries to the placement check, which is
# the safe direction to be wrong in.
_PACKAGED_LIB: Final = re.compile(r"(?:^|/)lib/[^/]+/[^/]+\.so$")


class NotAnElf(Exception):
    """The bytes at a `.so` entry are not an ELF this module can read."""


class UnreadableMember(Exception):
    """A `.so` entry's bytes could not be read out of the archive."""


@dataclass(frozen=True, slots=True)
class Finding:
    entry: str
    reason: str

    @override
    def __str__(self) -> str:
        return f"  {self.entry}: {self.reason}"


@dataclass(frozen=True, slots=True)
class Segment:
    """The fields of one program header that the conditions read."""

    p_type: int
    vaddr: int
    memsz: int
    align: int

    @property
    def end(self) -> int:
        return self.vaddr + self.memsz


def program_headers(elf: bytes) -> tuple[int, list[Segment]]:
    """`(ELF class in bits, every program header)`.

    ELF32, ELF64, little-endian, and big-endian encodings are read rather than
    assumed, because the packaged set spans them: arm64-v8a and x86_64 are
    ELFCLASS64 while armeabi-v7a is ELFCLASS32, and the caller needs the class
    to decide whether the 16 KB bar applies at all.
    """
    # 64 is the ELF64 header size, which covers the header fields read for
    # ELF32 and ELF64 classes; no real shared library is anywhere near this small.
    if len(elf) < 64:
        raise NotAnElf("too short to hold an ELF header")
    if elf[:4] != b"\x7fELF":
        raise NotAnElf("not an ELF file")

    ei_class, ei_data = elf[4], elf[5]
    # Refused rather than defaulted: a byte order guessed for a header that
    # names neither would have the alignments read in an order the file never
    # claimed, and the result judged as if it were real.
    if ei_data == ELFDATA2LSB:
        endian = "<"
    elif ei_data == ELFDATA2MSB:
        endian = ">"
    else:
        raise NotAnElf(f"unknown ELF data encoding {ei_data}")

    # Offsets of e_phoff, of e_phentsize (e_phnum follows it), and of p_vaddr,
    # p_memsz and p_align within one program header, per ELF class.
    if ei_class == ELFCLASS64:
        bits, ph_at, count_at, word = 64, 0x20, 0x36, "Q"
        vaddr_at, memsz_at, align_at = 0x10, 0x28, 0x30
    elif ei_class == ELFCLASS32:
        bits, ph_at, count_at, word = 32, 0x1C, 0x2A, "I"
        vaddr_at, memsz_at, align_at = 0x08, 0x14, 0x1C
    else:
        raise NotAnElf(f"unknown ELF class {ei_class}")

    (phoff,) = struct.unpack_from(endian + word, elf, ph_at)
    phentsize, phnum = struct.unpack_from(endian + "HH", elf, count_at)
    # A stride shorter than the fields read below would still land inside the
    # file, so `unpack_from` would return neighboring bytes rather than raise -
    # and a garbage `p_align` reads as large, which is the fail-OPEN direction.
    # p_align is the last field read in both classes.
    min_entry = align_at + struct.calcsize(word)
    if phentsize < min_entry:
        raise NotAnElf(f"program header entry size {phentsize} is below {min_entry}")

    segments: list[Segment] = []
    for i in range(phnum):
        at = phoff + i * phentsize
        if at + phentsize > len(elf):
            raise NotAnElf("program header table runs past the end of the file")
        (p_type,) = struct.unpack_from(endian + "I", elf, at)
        (vaddr,) = struct.unpack_from(endian + word, elf, at + vaddr_at)
        (memsz,) = struct.unpack_from(endian + word, elf, at + memsz_at)
        (p_align,) = struct.unpack_from(endian + word, elf, at + align_at)
        segments.append(Segment(p_type, vaddr, memsz, p_align))
    return bits, segments


def relro_reason(relro: Segment, loads: list[Segment]) -> str | None:
    """Why `relro` meets none of the guide's three ways, if it meets none.

    The caller found a `GNU_RELRO`, so the first way is gone; this reads the
    other two as the guide states them. The containing `LOAD` is the one that
    holds the RELRO's start.
    """
    if relro.end % PAGE_16K == 0:
        return None
    containing = [s for s in loads if s.vaddr <= relro.vaddr < s.end]
    if not containing:
        return (
            f"GNU_RELRO ends at 0x{relro.end:x}, not a 0x{PAGE_16K:x} boundary, "
            "and no LOAD segment contains it"
        )
    if containing[0].end == relro.end:
        return None
    return (
        f"GNU_RELRO ends at 0x{relro.end:x}, not a 0x{PAGE_16K:x} boundary, "
        f"and its LOAD segment ends at 0x{containing[0].end:x}"
    )


def elf_findings(entry: str, elf: bytes) -> list[Finding]:
    """Each reason `entry` fails a 16 KB condition, empty if it meets them."""
    try:
        bits, segments = program_headers(elf)
    except (NotAnElf, struct.error) as e:
        # Fail closed: an entry named `.so` that this cannot read is not a pass.
        return [Finding(entry, f"unreadable as ELF ({e})")]

    if bits != 64:
        return []
    loads = [s for s in segments if s.p_type == PT_LOAD]
    if not loads:
        return [Finding(entry, "no PT_LOAD segment")]

    findings: list[Finding] = []
    under = sorted({s.align for s in loads if s.align < PAGE_16K})
    if under:
        shown = ", ".join(f"0x{a:x}" for a in under)
        findings.append(
            Finding(entry, f"LOAD segment alignment {shown}, needs 0x{PAGE_16K:x}")
        )
    for relro in (s for s in segments if s.p_type == PT_GNU_RELRO):
        reason = relro_reason(relro, loads)
        if reason:
            findings.append(Finding(entry, reason))
    return findings


def zip_data_offset(fp: BinaryIO, header_offset: int) -> int:
    """Where an entry's bytes start, read from its LOCAL header.

    The local header is what decides this and it is not interchangeable with the
    central directory's copy: zipalign pads in the local extra field alone, so
    the central directory's `extra` for an aligned entry is typically empty.
    """
    fp.seek(header_offset)
    local = fp.read(30)
    if len(local) < 30 or local[:4] != b"PK\x03\x04":
        raise ValueError(f"no local file header at offset {header_offset}")
    name_len, extra_len = struct.unpack_from("<HH", local, 26)
    return int(header_offset + 30 + name_len + extra_len)


def read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    """The uncompressed bytes of `info`, or `UnreadableMember` naming it."""
    try:
        return archive.read(info)
    except Exception as e:
        # Every exception rather than a list, because the set is not fixed: it
        # depends on the entry's compression method and on the Python version.
        # zlib.error and EOFError for deflate, OSError for bzip2,
        # lzma.LZMAError, a Zstandard error from 3.14, RuntimeError for an
        # encrypted entry, NotImplementedError for a method zipfile lacks,
        # BadZipFile for a CRC mismatch. Each means the artifact cannot be
        # read, and a list would leave the next one to end the run with a
        # traceback before the remaining artifacts are checked.
        raise UnreadableMember(f"{info.filename}: {e}") from e


def library_findings(path: Path) -> list[Finding]:
    """Each reason the shared library at `path` fails a 16 KB condition."""
    return elf_findings(path.name, path.read_bytes())


def artifact_findings(path: Path) -> list[Finding]:
    """Every reason `path` would not load on a 16 KB-page device."""
    findings: list[Finding] = []
    # Only an APK is installed as-is; see the module docstring on why an AAB
    # takes the ELF conditions and not the placement one.
    check_placement = path.suffix == ".apk"

    # A second handle for the local-header reads rather than seeking the one
    # ZipFile is holding: interleaving a raw seek with `archive.read` happens to
    # survive today only because ZipFile restores its own position per read, and
    # a gate should not rest on that.
    with (
        open(path, "rb") as fp,
        open(path, "rb") as headers,
        zipfile.ZipFile(fp) as archive,
    ):
        libs = [i for i in archive.infolist() if i.filename.endswith(".so")]
        if not libs:
            return [Finding(path.name, "no native libraries found - wrong artifact?")]

        for info in libs:
            findings += elf_findings(info.filename, read_member(archive, info))

            if not (check_placement and _PACKAGED_LIB.search(info.filename)):
                continue
            if info.compress_type != zipfile.ZIP_STORED:
                findings.append(
                    Finding(info.filename, "compressed in the APK, must be stored")
                )
                continue
            offset = zip_data_offset(headers, info.header_offset)
            if offset % PAGE_16K:
                findings.append(
                    Finding(
                        info.filename,
                        f"starts at APK offset 0x{offset:x}, not a 0x{PAGE_16K:x} boundary",
                    )
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    if len(argv) < 2:
        print(
            "usage: android-page-align <artifact.apk|artifact.aab|library.so> [...]",
            file=sys.stderr,
        )
        return 1

    failed = False
    for arg in argv[1:]:
        path = Path(arg)
        library = path.suffix == ".so"
        try:
            findings = library_findings(path) if library else artifact_findings(path)
        except (OSError, zipfile.BadZipFile, ValueError, UnreadableMember) as e:
            what = "library" if library else "artifact"
            print(f"FAIL {path}: could not read the {what}: {e}", file=sys.stderr)
            failed = True
            continue

        if findings:
            failed = True
            print(f"FAIL {path}", file=sys.stderr)
            for finding in findings:
                print(str(finding), file=sys.stderr)
        elif library:
            print(f"OK {path}: maps on 16 KB pages")
        else:
            print(f"OK {path}: every packaged native library maps on 16 KB pages")

    if failed:
        print(
            "\nThe libraries above fail a 16 KB condition Google documents. If one\n"
            "arrived with a dependency, the fix is upstream or a pinned version\n"
            "built with NDK r28 or newer, or linked with\n"
            "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384; see\n"
            "https://github.com/curlewlabs-com/android-page-align.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
