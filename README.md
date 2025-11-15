# PDF & Archive Password Helper

`password_cracker.py` is a lightweight command-line tool for brute-forcing or dictionary-attacking password protected files. It supports PDFs, ZIP/RAR/7Z archives, and ISO/DMG images (using `hdiutil` on macOS or the `7z` CLI elsewhere). You can mix and match seed guesses, pattern-based brute force, fixed-length brute force, and dictionary fallbacks. Successful passwords are written to `Cracked password.txt`.

## Features

- Targets PDFs, ZIPs, RARs, 7Z archives, and ISO/DMG images (ISO handled via `hdiutil` on macOS, or the `7z` CLI elsewhere).
- Pattern generator using tokens like `AAAA1111`, `a1*?`, etc., plus literal prefixes/suffixes.
- Fixed-length brute force with custom charsets (letters+digits by default).
- Seed password mode mutates the guess (case flips, digit ±1, common leetspeak swaps) before other strategies.
- Dictionary fallback (`--wordlist`) runs after custom generators.
- Progress log every 500 attempts; writes cracked passwords to `Cracked password.txt`.
- Target-type auto-detection by extension, overridable with `--type`.

## Requirements

Create a virtual environment (optional but recommended) and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

RAR cracking requires `unrar` or `rar` in `PATH`. ISO/DMG attempts need `hdiutil` on macOS or the `7z` CLI (p7zip / 7-Zip) on Linux/Windows; 7-Zip can open ISO/DMG images just like other archives, so the tool simply invokes `7z t -pPASSWORD file.iso`.

## Setup

1. **Python environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. **External tools**
   - **RAR**: install `unrar`/`rar` (e.g., `brew install unrar`, `sudo apt install unrar`).
   - **ISO/DMG**:
     - macOS: `hdiutil` comes preinstalled.
     - Linux/Windows: install the `7z` CLI (e.g., `sudo apt install p7zip-full`, `brew install p7zip`, or install 7-Zip on Windows and add it to PATH). The script calls `7z t -pPASSWORD` so ISO/DMG archives are treated like regular 7z extractions.
3. **Verify tools**
   ```bash
   source .venv/bin/activate
   python password_cracker.py --help
   unrar --help   # optional, ensures PATH visibility
   7z --help      # optional, ensures PATH visibility
   ```

## Usage

Basic syntax (target type inferred from the file extension unless `--type` is supplied):

```bash
python3 password_cracker.py /path/to/encrypted.file [OPTIONS]
```

### Common Options

- `--pattern PATTERN` – Pattern describing the password layout. Tokens: `A` uppercase, `a` lowercase, `1`/`0`/`#` digit, `?` any letter, `*` alphanumeric.
- `--pattern-prefix TEXT` / `--pattern-suffix TEXT` – Literal prefix/suffix to wrap around the pattern (e.g., `--pattern-prefix SARS --pattern 1111`).
- `--pattern-order {asc,desc}` – Control iteration order (ASC = start at `AAAA1111`, DESC = start at `ZZZZ9999`).
- `--length N` – Brute force all combinations of length `N` using `--charset` (default letters+digits).
- `--charset CHARS` – Character set for `--length`.
- `--seed PASSWORD` – Initial guess to mutate (tries closish passwords first).
- `--seed-variants N` – Cap for mutated guesses (default `1000`).
- `--wordlist FILE` – Dictionary file with one candidate per line (used as fallback stage).
- `--max-candidates N` – Limit for generated candidates per strategy to avoid runaway workloads.
- `--output FILE` – Destination for the cracked password (default `Cracked password.txt`).
- `--type {pdf,zip,rar,7z,iso}` – Force the target type instead of relying on the extension.

### Examples

Pattern + seed first, then dictionary fallback:

```bash
python3 password_cracker.py secure.pdf \
  --pattern AAAA1111 \
  --seed AbCd1234 \
  --wordlist passwords.txt
```

Fixed-length brute force using hex characters:

```bash
python3 password_cracker.py report.pdf --length 6 --charset 0123456789abcdef
```

7Z archive, counting downward from `SARS9999`:

```bash
python3 password_cracker.py secrets.7z \
  --pattern 1111 \
  --pattern-prefix SARS \
  --pattern-order desc
```

RAR with seed mutations first:

```bash
python3 password_cracker.py backup.rar \
  --seed SARS2006 \
  --pattern AAAA1111
```

ISO/DMG attempt (uses `hdiutil` on macOS, or the `7z` CLI if available on Linux/Windows):

```bash
python3 password_cracker.py disk.iso --length 4 --charset 0123456789 --type iso
```

### Seed mode

`--seed` treats the supplied password as a base guess. For each character it mixes in:

- Opposite casing for letters (`s` ↔ `S`).
- Neighboring digits (`5` ↔ `4`/`6`).
- Common substitutions (`0↔O`, `1↔l/!`, `3↔E`, etc.).

The cartesian product of these pools (capped by `--seed-variants`) is attempted before any other strategy.

### Target Types

- **PDF** – Uses `PyPDF2`’s `decrypt()` to test each password.
- **ZIP** – Uses `zipfile.ZipFile` to read 1 byte from a member with the supplied password.
- **RAR** – Uses `rarfile` (and the `unrar`/`rar` system binary) to read a file entry.
- **7Z** – Uses `py7zr` to open the archive and read a member (supports AES-256/SHA-256).
- **ISO/DMG** – On macOS executes `hdiutil attach -stdinpass`; on Linux/Windows shells out to the `7z` CLI (`7z t`) to test the archive.

### How it works

1. **Candidate generation pipeline**
   - Seed variants (if `--seed` provided) attempt “close” passwords first.
   - Pattern-driven (`--pattern` with optional prefix/suffix/order) or fixed-length brute force follows, limited by `--max-candidates`.
   - Dictionary (`--wordlist`) attempts act as a final fallback.
   - Duplicates across stages are skipped.
2. **Target-specific probes**
   - Every candidate is tested using the appropriate backend (PyPDF2, zipfile, rarfile, py7zr, or `hdiutil`/`7z` for ISO/DMG).
   - Only tiny reads/mounts are performed to keep attempts fast.
3. **Feedback and output**
   - A log entry appears every 500 attempts.
   - Once a password works, it is printed and stored in `Cracked password.txt` (or your custom path), then the tool exits.

## Output

When the password is found, it is printed to stdout and saved to `Cracked password.txt` (or the file specified via `--output`). If the password cannot be found with the chosen strategies, the script exits with a non-zero status code.
