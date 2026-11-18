"""Tests for check.py: the ELF read, where an APK entry's bytes start, and the
verdict the command prints and exits with.

THE ELF FIXTURES ARE PACKED HERE, from the ELF specification's structure
layouts written whole (`Elf64_Ehdr`, `Elf64_Phdr` and their 32-bit forms), while
the checker reads single fields at fixed offsets. The two are separate
statements of the format, so a wrong offset in either makes them disagree
rather than agree while both are wrong. The headers and program headers are
everything the checker reads, so no linker is needed.

THE ZIP FIXTURES ARE WRITTEN BY `zipfile`, and where a test depends on where an
entry's bytes start, the expected offset is found by searching the archive's
raw bytes for the payload rather than computed by the arithmetic under test.
"""

from __future__ import annotations

import contextlib
import io
import os
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import override

from android_page_align.check import (
    PAGE_16K,
    PT_LOAD,
    Finding,
    artifact_findings,
    elf_finding,
    load_segment_alignments,
    main,
    zip_data_offset,
)

ET_DYN = 3
EM_ARM = 40
EM_AARCH64 = 183
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551

# Each structure as the ELF specification lays it out, field by field.
_EHDR64 = "16sHHIQQQIHHHHHH"
_PHDR64 = "IIQQQQQQ"
_EHDR32 = "16sHHIIIIIHHHHHH"
_PHDR32 = "IIIIIIII"


def elf(
    bits: int = 64,
    endian: str = "<",
    segments: tuple[tuple[int, int], ...] = ((PT_LOAD, 0x4000), (PT_LOAD, 0x4000)),
    phentsize: int | None = None,
) -> bytes:
    """A shared object's ELF header and program header table.

    `segments` is `(p_type, p_align)` per program header. The table follows the
    header directly, as a linker places it.
    """
    ehdr, phdr = (_EHDR64, _PHDR64) if bits == 64 else (_EHDR32, _PHDR32)
    ehsize = struct.calcsize(ehdr)
    entsize = struct.calcsize(phdr) if phentsize is None else phentsize
    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1 if endian == "<" else 2, 1])
    machine = EM_AARCH64 if bits == 64 else EM_ARM
    header = struct.pack(
        endian + ehdr,
        ident.ljust(16, b"\0"),
        ET_DYN,
        machine,
        1,
        0,
        ehsize,
        0,
        0,
        ehsize,
        entsize,
        len(segments),
        0,
        0,
        0,
    )
    table = b""
    for p_type, p_align in segments:
        if bits == 64:
            entry = struct.pack(
                endian + phdr, p_type, 5, 0, 0, 0, 0x1000, 0x1000, p_align
            )
        else:
            entry = struct.pack(
                endian + phdr, p_type, 0, 0, 0, 0x1000, 0x1000, 5, p_align
            )
        # Written at the declared stride, so a short one truncates each entry
        # the way a corrupt table would present it.
        table += (entry + b"\0" * entsize)[:entsize]
    return header + table


def write_archive(path: Path, entries: list[tuple[str, bytes, int]]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data, method in entries:
            archive.writestr(zipfile.ZipInfo(name), data, method)
    return path


def write_aligned_apk(path: Path, name: str, data: bytes) -> Path:
    """An APK holding `name` stored with its bytes on a 16 KB boundary, padded
    as zipalign pads: in the local header's extra field."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(zipfile.ZipInfo("AndroidManifest.xml"), b"manifest")
        info = zipfile.ZipInfo(name)
        info.compress_type = zipfile.ZIP_STORED
        start = archive.fp.tell() if archive.fp else 0
        # The extra field zipalign writes (0xD935: alignment, then padding).
        unpadded = start + 30 + len(name.encode()) + 6
        padding = -unpadded % PAGE_16K
        info.extra = struct.pack("<HHH", 0xD935, 2 + padding, PAGE_16K // 1024)
        info.extra += b"\0" * padding
        archive.writestr(info, data)
    return path


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(argv)
    return status, out.getvalue(), err.getvalue()


class TempDirTest(unittest.TestCase):
    @override
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)


class TestLoadSegmentAlignments(unittest.TestCase):
    def test_a_64_bit_library_reads_its_class_and_each_load_alignment(self) -> None:
        segments = ((PT_LOAD, 0x4000), (PT_DYNAMIC, 8), (PT_LOAD, 0x10000))
        self.assertEqual(
            load_segment_alignments(elf(segments=segments)), (64, [0x4000, 0x10000])
        )

    def test_a_32_bit_library_reads_as_32_bit(self) -> None:
        # The discrimination the exemption rests on: the ELF32 header puts
        # e_phoff and the program header fields at other offsets, so a parser
        # that ignored EI_CLASS would read garbage here.
        self.assertEqual(
            load_segment_alignments(elf(bits=32, segments=((PT_LOAD, 0x1000),))),
            (32, [0x1000]),
        )

    def test_a_big_endian_library_is_read_in_its_own_byte_order(self) -> None:
        # Read little-endian, 0x4000 in a big-endian Q field is 0x40 << 48 - a
        # huge alignment, which would pass. The byte order has to be honored.
        segments = ((PT_LOAD, 0x1000),)
        self.assertEqual(
            load_segment_alignments(elf(endian=">", segments=segments)),
            (64, [0x1000]),
        )


class TestElfFinding(unittest.TestCase):
    def test_a_16k_aligned_64_bit_library_passes(self) -> None:
        self.assertIsNone(elf_finding("lib.so", elf()))

    def test_a_64k_aligned_library_passes(self) -> None:
        # Larger than a 16 KB page is still a multiple of one; prebuilt engines
        # ship at 0x10000 and must not be reported.
        self.assertIsNone(elf_finding("lib.so", elf(segments=((PT_LOAD, 0x10000),))))

    def test_a_4k_aligned_64_bit_library_is_reported(self) -> None:
        found = elf_finding("lib.so", elf(segments=((PT_LOAD, 0x1000),)))
        self.assertIsNotNone(found)
        assert found is not None
        self.assertEqual(found.reason, "LOAD segment alignment 0x1000, needs 0x4000")

    def test_each_short_alignment_is_named_once(self) -> None:
        segments = (
            (PT_LOAD, 0x4000),
            (PT_LOAD, 0x1000),
            (PT_LOAD, 0x2000),
            (PT_LOAD, 0x1000),
        )
        found = elf_finding("lib.so", elf(segments=segments))
        assert found is not None
        self.assertEqual(
            found.reason, "LOAD segment alignment 0x1000, 0x2000, needs 0x4000"
        )

    def test_a_segment_other_than_load_does_not_count(self) -> None:
        # PT_GNU_STACK and PT_DYNAMIC carry small alignments in every real
        # library; reading them as LOAD would fail everything.
        segments = ((PT_LOAD, 0x4000), (PT_GNU_STACK, 0x10), (PT_DYNAMIC, 8))
        self.assertIsNone(elf_finding("lib.so", elf(segments=segments)))

    def test_a_32_bit_library_at_4k_is_exempt_rather_than_a_failure(self) -> None:
        # Not a skip: the NDK scopes flexible page sizes to the 64-bit ABIs, so
        # its own 32-bit output is 0x1000. The module docstring says where.
        found = elf_finding("lib.so", elf(bits=32, segments=((PT_LOAD, 0x1000),)))
        self.assertIsNone(found)

    def test_a_64_bit_library_with_no_load_segment_is_reported(self) -> None:
        found = elf_finding("lib.so", elf(segments=((PT_DYNAMIC, 8),)))
        assert found is not None
        self.assertEqual(found.reason, "no PT_LOAD segment")

    def test_something_that_is_not_an_elf_fails_closed(self) -> None:
        found = elf_finding("lib.so", b"not an ELF at all" * 8)
        assert found is not None
        self.assertIn("not an ELF file", found.reason)

    def test_an_unknown_elf_class_fails_closed(self) -> None:
        raw = bytearray(elf())
        raw[4] = 3
        found = elf_finding("lib.so", bytes(raw))
        assert found is not None
        self.assertIn("unknown ELF class 3", found.reason)

    def test_an_unknown_elf_data_encoding_fails_closed(self) -> None:
        # The case a fallback byte order gets wrong: a big-endian header with
        # good alignments but an invalid EI_DATA would read cleanly as
        # big-endian and pass. 0 is ELFDATANONE; 3 is past the defined values.
        for ei_data in (0, 3):
            with self.subTest(ei_data=ei_data):
                raw = bytearray(elf(endian=">"))
                raw[5] = ei_data
                found = elf_finding("lib.so", bytes(raw))
                assert found is not None
                self.assertEqual(
                    found.reason,
                    f"unreadable as ELF (unknown ELF data encoding {ei_data})",
                )

    def test_a_short_program_header_stride_fails_closed(self) -> None:
        # The fail-OPEN direction, which is why this is a test and not a guard
        # taken on faith: a stride below the fields the parser reads still lands
        # inside the file, so the read returns neighboring bytes rather than
        # raising, and garbage reads as a large alignment - a pass.
        found = elf_finding("lib.so", elf(segments=((PT_LOAD, 0x1000),), phentsize=8))
        assert found is not None
        self.assertIn("program header entry size 8", found.reason)

    def test_a_program_header_table_past_the_end_fails_closed(self) -> None:
        # A truncated library must not pass on the segments that happened to
        # survive.
        found = elf_finding("lib.so", elf()[:-1])
        assert found is not None
        self.assertIn("runs past the end", found.reason)

    def test_a_file_too_short_for_a_header_fails_closed(self) -> None:
        found = elf_finding("lib.so", elf()[:40])
        assert found is not None
        self.assertIn("too short", found.reason)


class TestZipDataOffset(TempDirTest):
    def test_the_offset_points_at_the_entrys_own_bytes(self) -> None:
        # The independent oracle: the arithmetic is right only if the bytes are
        # where it says they are. An off-by-one in the local-header layout
        # fails here without the fixture having to know the answer in advance.
        payload = b"a stored payload with recognisable bytes" * 7
        path = write_archive(
            self.tmp / "probe.apk",
            [
                (
                    "first/entry.txt",
                    b"padding of an awkward length",
                    zipfile.ZIP_STORED,
                ),
                ("lib/arm64-v8a/x.so", payload, zipfile.ZIP_STORED),
            ],
        )
        raw = path.read_bytes()
        with open(path, "rb") as fp, zipfile.ZipFile(fp) as archive:
            info = archive.getinfo("lib/arm64-v8a/x.so")
            offset = zip_data_offset(fp, info.header_offset)
        self.assertEqual(raw[offset : offset + len(payload)], payload)

    def test_an_offset_with_no_local_header_is_an_error(self) -> None:
        path = self.tmp / "junk.bin"
        path.write_bytes(b"\0" * 64)
        with open(path, "rb") as fp, self.assertRaises(ValueError):
            zip_data_offset(fp, 0)


class TestArtifactFindings(TempDirTest):
    def test_a_stored_16k_placed_library_in_an_apk_passes(self) -> None:
        # The production shape of a good APK. The fixture's placement is
        # confirmed from the raw bytes, not taken from the padding arithmetic.
        library = elf()
        path = write_aligned_apk(self.tmp / "a.apk", "lib/arm64-v8a/x.so", library)
        self.assertEqual(path.read_bytes().index(library) % PAGE_16K, 0)
        self.assertEqual(artifact_findings(path), [])

    def test_a_stored_library_off_a_16k_boundary_is_reported(self) -> None:
        path = write_archive(
            self.tmp / "a.apk", [("lib/arm64-v8a/x.so", elf(), zipfile.ZIP_STORED)]
        )
        start = path.read_bytes().index(elf())
        self.assertNotEqual(start % PAGE_16K, 0)
        reasons = [f.reason for f in artifact_findings(path)]
        self.assertEqual(
            reasons, [f"starts at APK offset 0x{start:x}, not a 0x4000 boundary"]
        )

    def test_a_compressed_library_in_an_apk_is_reported(self) -> None:
        # `useLegacyPackaging` is the switch that produces this, and it is the
        # half of 16 KB support an ELF check alone would miss.
        path = write_archive(
            self.tmp / "a.apk", [("lib/arm64-v8a/x.so", elf(), zipfile.ZIP_DEFLATED)]
        )
        reasons = [f.reason for f in artifact_findings(path)]
        self.assertEqual(reasons, ["compressed in the APK, must be stored"])

    def test_an_aab_does_not_take_the_placement_condition(self) -> None:
        # Play builds the APKs from a bundle, so how its entries sit is not the
        # install artifact's layout. Applying it here would fail every bundle.
        path = write_archive(
            self.tmp / "a.aab",
            [("base/lib/arm64-v8a/x.so", elf(), zipfile.ZIP_DEFLATED)],
        )
        self.assertEqual(artifact_findings(path), [])

    def test_an_aab_still_takes_the_elf_condition(self) -> None:
        path = write_archive(
            self.tmp / "a.aab",
            [
                (
                    "base/lib/arm64-v8a/x.so",
                    elf(segments=((PT_LOAD, 0x1000),)),
                    zipfile.ZIP_DEFLATED,
                )
            ],
        )
        self.assertEqual(
            [f.entry for f in artifact_findings(path)], ["base/lib/arm64-v8a/x.so"]
        )

    def test_a_library_outside_lib_abi_takes_only_the_elf_condition(self) -> None:
        # A `.so` in assets is not mapped out of the APK by the loader, so its
        # placement is not in question - but its alignment still is.
        good = write_archive(
            self.tmp / "good.apk", [("assets/x.so", elf(), zipfile.ZIP_DEFLATED)]
        )
        self.assertEqual(artifact_findings(good), [])
        bad = write_archive(
            self.tmp / "bad.apk",
            [("assets/x.so", elf(segments=((PT_LOAD, 0x1000),)), zipfile.ZIP_DEFLATED)],
        )
        self.assertEqual([f.entry for f in artifact_findings(bad)], ["assets/x.so"])

    def test_a_32_bit_abi_is_still_placement_checked(self) -> None:
        # The ELF exemption is for the 32-bit alignment the NDK emits; a
        # compressed entry is a packaging decision and fails on any ABI.
        path = write_archive(
            self.tmp / "a.apk",
            [
                (
                    "lib/armeabi-v7a/x.so",
                    elf(bits=32, segments=((PT_LOAD, 0x1000),)),
                    zipfile.ZIP_DEFLATED,
                )
            ],
        )
        reasons = [f.reason for f in artifact_findings(path)]
        self.assertEqual(reasons, ["compressed in the APK, must be stored"])

    def test_several_libraries_are_each_judged_on_their_own_entry(self) -> None:
        # Reading an entry's bytes and reading the next entry's local header
        # interleave, and a per-entry verdict has to stay attached to the entry
        # it came from.
        path = write_archive(
            self.tmp / "a.apk",
            [
                ("lib/arm64-v8a/ok.so", elf(), zipfile.ZIP_STORED),
                ("lib/arm64-v8a/bad.so", elf(), zipfile.ZIP_DEFLATED),
                ("lib/x86_64/ok.so", elf(), zipfile.ZIP_STORED),
            ],
        )
        compressed = [f.entry for f in artifact_findings(path) if "stored" in f.reason]
        self.assertEqual(compressed, ["lib/arm64-v8a/bad.so"])

    def test_an_artifact_with_no_native_libraries_is_reported(self) -> None:
        # A pass over an empty set is the failure a gate is most likely to
        # have: a moved build output path would otherwise pass silently.
        path = write_archive(
            self.tmp / "a.apk", [("classes.dex", b"dex", zipfile.ZIP_STORED)]
        )
        self.assertEqual(
            artifact_findings(path),
            [Finding("a.apk", "no native libraries found - wrong artifact?")],
        )


class TestCommand(TempDirTest):
    def test_a_passing_artifact_prints_ok_and_exits_zero(self) -> None:
        path = write_aligned_apk(self.tmp / "a.apk", "lib/arm64-v8a/x.so", elf())
        self.assertEqual(
            run(["android-page-align", str(path)]),
            (0, f"OK {path}: every packaged native library maps on 16 KB pages\n", ""),
        )

    def test_a_failing_artifact_names_each_finding_and_exits_one(self) -> None:
        path = write_archive(
            self.tmp / "a.aab",
            [
                (
                    "base/lib/arm64-v8a/x.so",
                    elf(segments=((PT_LOAD, 0x1000),)),
                    zipfile.ZIP_STORED,
                )
            ],
        )
        status, out, err = run(["android-page-align", str(path)])
        self.assertEqual((status, out), (1, ""))
        self.assertTrue(
            err.startswith(
                f"FAIL {path}\n"
                "  base/lib/arm64-v8a/x.so: LOAD segment alignment 0x1000, needs 0x4000\n"
                "\nA 16 KB-page device would refuse to load the libraries above."
            ),
            err,
        )

    def test_every_artifact_is_judged_even_after_a_failure(self) -> None:
        bad = self.tmp / "bad.apk"
        bad.write_bytes(b"not a zip")
        good = write_aligned_apk(self.tmp / "good.apk", "lib/x86_64/x.so", elf())
        status, out, err = run(["android-page-align", str(bad), str(good)])
        self.assertEqual(status, 1)
        self.assertEqual(
            out, f"OK {good}: every packaged native library maps on 16 KB pages\n"
        )
        self.assertIn(f"FAIL {bad}: could not read the artifact:", err)

    def test_a_missing_artifact_is_a_failure_not_a_pass(self) -> None:
        status, out, err = run(["android-page-align", str(self.tmp / "absent.apk")])
        self.assertEqual((status, out), (1, ""))
        self.assertIn("could not read the artifact", err)

    def test_no_artifact_is_a_usage_error(self) -> None:
        # A gate handed an empty list must not exit 0 having judged nothing.
        status, out, err = run(["android-page-align"])
        self.assertEqual((status, out), (1, ""))
        self.assertIn("usage: android-page-align", err)

    def test_the_module_runs_as_a_command(self) -> None:
        # `python3 -m android_page_align` is how a consumer without the console
        # script runs it; its exit status has to reach the shell.
        bad = self.tmp / "bad.apk"
        bad.write_bytes(b"not a zip")
        src = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [sys.executable, "-m", "android_page_align", str(bad)],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": src},
            check=False,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("could not read the artifact", result.stderr)


if __name__ == "__main__":
    unittest.main()
