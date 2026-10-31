# bh3scan

## Installation

### Windows x64 (PowerShell)

```powershell
irm https://github.com/sunfkny/bh3scan/releases/latest/download/bh3scan-installer.ps1 | iex
```

### macOS Apple Silicon

```shell
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/sunfkny/bh3scan/releases/latest/download/bh3scan-installer.sh | sh
```

### From source

```shell
cargo install --locked --git https://github.com/sunfkny/bh3scan.git bh3scan
```

## Usage

```shell
# Get QR code image from clipboard or screen
bh3scan
# Pass QR code ticket direct
bh3scan [ticket]
```
