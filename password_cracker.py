#!/usr/bin/env python3
"""
Password dictionary/brute-force helper for PDFs and encrypted archives.

Features:
* Takes relative/absolute paths with optional target-type override.
* Optional pattern-driven brute force (e.g. AAAA1111 for 4 letters + 4 digits).
* Optional fixed length brute force with custom charset.
* Optional seed password prioritization with close variations.
* Falls back to dictionary attack via user-supplied wordlist.
* Writes cracked password to "Cracked password.txt" when found.
"""
from __future__ import annotations

import argparse
import itertools
import platform
import plistlib
import string
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Sequence, Set

try:
    from PyPDF2 import PdfReader
except ImportError as exc:  # pragma: no cover - interactive error path
    raise SystemExit(
        "PyPDF2 is required. Install it with `pip install PyPDF2`."
    ) from exc

try:
    import rarfile
except ImportError:  # pragma: no cover - optional dependency
    rarfile = None

try:
    import py7zr
except ImportError:  # pragma: no cover - optional dependency
    py7zr = None


DEFAULT_CHARSET = string.ascii_letters + string.digits
PATTERN_CHARSETS = {
    "A": string.ascii_uppercase,
    "a": string.ascii_lowercase,
    "1": string.digits,
    "0": string.digits,
    "#": string.digits,
    "?": string.ascii_letters,
    "*": DEFAULT_CHARSET,
}

TARGET_TYPE_MAP = {
    ".pdf": "pdf",
    ".zip": "zip",
    ".rar": "rar",
    ".7z": "7z",
    ".iso": "iso",
}
SUPPORTED_TYPES = tuple(sorted(set(TARGET_TYPE_MAP.values())))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Attempt to crack password-protected PDFs, ZIP/RAR/7Z archives, or ISO/DMG images."
    )
    parser.add_argument(
        "target",
        help="Relative or absolute path to the encrypted file (PDF/ZIP/RAR/7Z/ISO).",
    )
    parser.add_argument(
        "--pattern",
        help=(
            "Pattern describing the password layout. "
            "Use A=uppercase, a=lowercase, 1 (or 0/#)=digit, "
            "?=any letter, *=letter/digit. Example: AAAA1111."
        ),
    )
    parser.add_argument(
        "--pattern-prefix",
        default="",
        help="Fixed literal prefix to prepend to --pattern (e.g., SARS + 1111).",
    )
    parser.add_argument(
        "--pattern-suffix",
        default="",
        help="Fixed literal suffix to append to --pattern.",
    )
    parser.add_argument(
        "--pattern-order",
        choices=("asc", "desc"),
        default="asc",
        help="Order for pattern expansion (asc=AAAA1111 first, desc=ZZZZ9999 first).",
    )
    parser.add_argument(
        "--length",
        type=int,
        help=(
            "When pattern is omitted, brute force all combinations for the length "
            "using --charset (default letters+digits)."
        ),
    )
    parser.add_argument(
        "--charset",
        default=DEFAULT_CHARSET,
        help="Characters used for --length brute force attempts.",
    )
    parser.add_argument(
        "--seed",
        help="Initial password guess. Nearby variations will be tried first.",
    )
    parser.add_argument(
        "--wordlist",
        type=Path,
        help="Dictionary file for fallback attack (one password per line).",
    )
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=250000,
        help="Safety limit for generated candidates per strategy.",
    )
    parser.add_argument(
        "--seed-variants",
        type=int,
        default=1000,
        help="Maximum number of variations derived from --seed.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("Cracked password.txt"),
        help="Where to store the cracked password (default: ./Cracked password.txt).",
    )
    parser.add_argument(
        "--type",
        choices=SUPPORTED_TYPES,
        help="Force the target type (pdf/zip/rar/7z/iso). Defaults to extension inference.",
    )
    return parser.parse_args(argv)


def resolve_target(path_str: str) -> Path:
    pdf_path = Path(path_str).expanduser()
    if not pdf_path.is_absolute():
        pdf_path = (Path.cwd() / pdf_path).resolve()
    if not pdf_path.exists():
        raise FileNotFoundError(f"Target file not found: {pdf_path}")
    return pdf_path


def determine_target_type(path: Path, forced: Optional[str]) -> str:
    if forced:
        return forced
    return TARGET_TYPE_MAP.get(path.suffix.lower(), "pdf")


def try_password(pdf_path: Path, password: str, target_type: str) -> bool:
    if target_type == "pdf":
        return try_pdf_password(pdf_path, password)
    if target_type == "zip":
        return try_zip_password(pdf_path, password)
    if target_type == "rar":
        return try_rar_password(pdf_path, password)
    if target_type == "7z":
        return try_7z_password(pdf_path, password)
    if target_type == "iso":
        return try_iso_password(pdf_path, password)
    raise ValueError(f"Unsupported target type: {target_type}")


def try_pdf_password(pdf_path: Path, password: str) -> bool:
    try:
        with pdf_path.open("rb") as handle:
            reader = PdfReader(handle)
            if not reader.is_encrypted:
                return True
            result = reader.decrypt(password)
            return bool(result)
    except Exception:
        return False


def try_zip_password(zip_path: Path, password: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            member = next((info for info in zf.infolist() if not info.is_dir()), None)
            if member is None:
                # Archive is empty; treat as success with password
                zf.namelist()
                return True
            with zf.open(member, pwd=password.encode("utf-8")) as handle:
                handle.read(1)
        return True
    except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False
    except Exception:
        return False


def try_rar_password(rar_path: Path, password: str) -> bool:
    if rarfile is None:
        raise RuntimeError("rarfile dependency missing. Install via pip.")
    try:
        with rarfile.RarFile(rar_path) as rf:
            member = next((info for info in rf.infolist() if not info.isdir()), None)
            if member is None:
                rf.testrar()
                return True
            with rf.open(member, pwd=password) as handle:
                handle.read(1)
        return True
    except (rarfile.BadRarFile, rarfile.RarWrongPassword, rarfile.RarCRCError):
        return False
    except rarfile.RarCannotExec as exc:
        raise RuntimeError(
            "rarfile requires 'unrar' or 'rar' command to be installed."
        ) from exc
    except Exception:
        return False


def try_7z_password(archive_path: Path, password: str) -> bool:
    if py7zr is None:
        raise RuntimeError("py7zr dependency missing. Install via pip.")
    try:
        with py7zr.SevenZipFile(archive_path, mode="r", password=password) as archive:
            names = archive.getnames()
            if not names:
                archive.list()
            else:
                target = names[0]
                archive.read([target])
        return True
    except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.Bad7zFile):
        return False
    except py7zr.exceptions.UnsupportedCompressionMethodError:
        return False
    except RuntimeError as exc:
        if "password" in str(exc).lower():
            return False
        return False


def try_iso_password(iso_path: Path, password: str) -> bool:
    system = platform.system()
    if system == "Darwin":
        return try_iso_hdiutil(iso_path, password)
    return try_iso_with_7z_cli(iso_path, password)


def try_iso_hdiutil(iso_path: Path, password: str) -> bool:
    # macOS disk images can be tested by attempting to attach them via hdiutil.
    cmd_base = [
        "hdiutil",
        "attach",
        "-plist",
        "-nobrowse",
        "-readonly",
    ]
    try:
        with tempfile.TemporaryDirectory() as mount_dir:
            cmd = cmd_base + ["-mountpoint", mount_dir, "-stdinpass", str(iso_path)]
            proc = subprocess.run(
                cmd,
                input=(password + "\n").encode("utf-8"),
                capture_output=True,
                check=False,
            )
            if proc.returncode != 0:
                return False
            plist_data = plistlib.loads(proc.stdout)
            devices = [
                entity.get("dev-entry")
                for entity in plist_data.get("system-entities", [])
                if entity.get("dev-entry")
            ]
            for device in devices:
                subprocess.run(
                    ["hdiutil", "detach", device],
                    capture_output=True,
                    check=False,
                )
            return True
    except FileNotFoundError as exc:
        raise RuntimeError("hdiutil not found. ISO/DMG testing requires macOS.") from exc
    except Exception:
        return False


def try_iso_with_7z_cli(iso_path: Path, password: str) -> bool:
    """
    For Linux/Windows we rely on the external `7z` command (from p7zip).
    We invoke `7z t` to test extraction with the supplied password.
    """
    try:
        proc = subprocess.run(
            ["7z", "t", f"-p{password}", "-y", str(iso_path)],
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "7z executable not found. Install p7zip-full / 7-Zip to test ISO passwords."
        ) from exc
    return proc.returncode == 0


def candidate_variants(seed: str) -> Iterator[str]:
    substitutions = {
        "0": "oO",
        "1": "lLI!",
        "3": "eE",
        "5": "sS",
        "7": "tT",
        "8": "B",
    }
    pools: List[List[str]] = []
    for char in seed:
        options: Set[str] = {char}
        if char.isalpha():
            options.add(char.swapcase())
        if char.isdigit():
            prev_digit = str((int(char) - 1) % 10)
            next_digit = str((int(char) + 1) % 10)
            options.update({prev_digit, next_digit})
        for repl in substitutions.get(char, ""):
            options.add(repl)
        pools.append(sorted(options))
    for combo in itertools.product(*pools):
        yield "".join(combo)


def generate_from_pattern(pattern: str, *, order: str = "asc") -> Iterator[str]:
    char_sets: List[str] = []
    for char in pattern:
        charset = PATTERN_CHARSETS.get(char)
        if charset is None:
            char_sets.append(char)
        else:
            char_sets.append(charset if order == "asc" else charset[::-1])
    for combo in itertools.product(*char_sets):
        yield "".join(combo)


def generate_by_length(length: int, charset: str) -> Iterator[str]:
    for combo in itertools.product(charset, repeat=length):
        yield "".join(combo)


def limited(generator: Iterable[str], limit: Optional[int]) -> Iterator[str]:
    if limit is None:
        yield from generator
        return
    for index, candidate in enumerate(generator):
        if index >= limit:
            break
        yield candidate


def read_wordlist(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip()
            if word:
                yield word


def crack_target(
    target_path: Path,
    target_type: str,
    args: argparse.Namespace,
) -> Optional[str]:
    attempted = 0

    def log_attempt(password: str) -> None:
        nonlocal attempted
        attempted += 1
        if attempted % 500 == 0:
            print(f"[+] Tried {attempted} candidates... last: {password}", flush=True)

    candidate_streams: List[Iterable[str]] = []

    if args.seed:
        candidate_streams.append(
            limited(candidate_variants(args.seed), args.seed_variants)
        )

    pattern_spec: Optional[str] = None
    if args.pattern or args.pattern_prefix or args.pattern_suffix:
        pattern_spec = f"{args.pattern_prefix}{args.pattern or ''}{args.pattern_suffix}"

    if pattern_spec:
        candidate_streams.append(
            limited(
                generate_from_pattern(pattern_spec, order=args.pattern_order),
                args.max_candidates,
            )
        )
    elif args.length:
        candidate_streams.append(
            limited(generate_by_length(args.length, args.charset), args.max_candidates)
        )

    if args.wordlist and args.wordlist.exists():
        candidate_streams.append(read_wordlist(args.wordlist))

    seen: Set[str] = set()
    for stream in candidate_streams:
        for password in stream:
            if password in seen:
                continue
            seen.add(password)
            log_attempt(password)
            if try_password(target_path, password, target_type):
                return password

    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        target_path = resolve_target(args.target)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 2

    target_type = determine_target_type(target_path, args.type)

    if not args.pattern and not args.length and not args.wordlist and not args.seed:
        print(
            "Warning: no generation strategy requested. Provide --pattern, --length, "
            "--seed, or --wordlist.",
            file=sys.stderr,
        )

    start = time.perf_counter()
    password = crack_target(target_path, target_type, args)
    elapsed = time.perf_counter() - start

    if password:
        args.output.write_text(password, encoding="utf-8")
        print(
            f"[+] Success! Password '{password}' unlocked the {target_type.upper()} file "
            f"and was saved to {args.output}."
        )
        print(f"[+] Time elapsed: {elapsed:.2f}s over tried candidates.")
        return 0

    print(
        f"[-] Failed to crack the {target_type.upper()} file with the provided strategies.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
