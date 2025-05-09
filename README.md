# FUfs - Virtual Filesystem with Process Enforcement

`FUfs` is a custom FUSE-based virtual filesystem written in Python. It dynamically creates a virtual directory and file structure, supports read operations with configurable size limits, and enforces strict unlink/rmdir behavior by terminating the calling process tree when unauthorized operations are attempted.

## Features

- Creates a virtual directory and file at every level in the mounted filesystem.
- Configurable file size for `stat` and data stream size for `read`.
- Prevents deletion of the virtual file or directory by killing the calling process tree.
- Identifies root process (e.g., `sshd`, `systemd`) before terminating.
- Optionally overlays real directory contents under the virtual structure.
- Logs all filesystem operations and process information for traceability.

## Installation

### Prerequisites

- Python 3.6+
- FUSE (Filesystem in Userspace)
- `psutil` Python module

On Ubuntu:

```bash
sudo apt install fuse
pip install psutil
```

### Clone the Repository

```bash
git clone https://github.com/ponquersohn/fufs.git
cd fufs
```

## Usage

### Basic Mount

```bash
mkdir /tmp/mountpoint
sudo python3 fufs.py --mount /tmp/mountpoint
```

### Options

```bash
--mount         Path to mount point (required)
--dir-name      Virtual directory name (default: "vdir")
--file-name     Virtual file name (default: "vfile")
--file-size     Apparent size of the file (default: 1024)
--read-size     How many bytes to return in read (-1 for infinite) (default: 1024)
--source-dir    (Optional) Path to real directory to overlay
```

### Example

```bash
sudo python3 fufs.py --mount /mnt/fufs --dir-name trapdir --file-name trigger.txt --file-size 2048 --read-size -1 --source-dir /home/user/data
```

## Behavior

* **Reading** `trigger.txt` returns infinite or limited data based on `--read-size`.
* **Deleting** `trapdir` or `trigger.txt` forcibly kills the calling process and its parents (unless from a root process like `sshd` or `systemd`).
* **Listing** a directory always shows both virtual items and optionally real files.

## Logging

Logs are printed to stdout and include process information, kill decisions, and filesystem operation traces.

## Warning

This tool is intended for **educational, testing, or controlled environments only**. It forcefully kills processes and can disrupt system operations if misused.

## License

MIT License



