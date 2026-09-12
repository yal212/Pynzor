# Standalone binaries

Tagged GitHub releases build PyInstaller binaries for Windows, macOS, and Linux.

| Platform | File | Run |
|----------|------|-----|
| Windows | `Pynzor.exe` | `Pynzor.exe --help` |
| macOS | `Pynzor-macos` | `chmod +x Pynzor-macos && ./Pynzor-macos --help` |
| Linux | `Pynzor-linux` | `chmod +x Pynzor-linux && ./Pynzor-linux --help` |

Download them from the
[releases page](https://github.com/yal212/Pynzor/releases).

The binaries are self-contained: the default config, wordlists, and HTML report
template are bundled inside and resolved at runtime, so reports can be written
to any output directory you pass with `-o`. Each release build is smoke-tested
(`--version`, `--help`, `headers --help`) on its native runner in CI.

## Platform notes

**macOS** — binaries are unsigned. If Gatekeeper blocks the binary, allow it
from System Settings or clear the quarantine attribute:

```bash
xattr -d com.apple.quarantine ./Pynzor-macos
```

They are built on Apple Silicon runners (`arm64`); run under Rosetta on Intel
Macs if needed.

**Linux** — built on `ubuntu-latest` against that image's glibc, so very old
distributions may not be compatible. Prefer `pipx install Pynzor` there.

**Windows** — TLS uses the bundled `certifi` CA store, so HTTPS targets work
without a system Python.

**UPX** — the spec enables UPX compression. If a corporate AV flags the binary,
rebuild with `upx=False` in `Pynzor.spec`.
