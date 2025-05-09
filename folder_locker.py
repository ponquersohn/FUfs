#!/usr/bin/env python3
import json
import os
import time
import argparse
import threading
from collections import defaultdict
import logging
from functools import wraps

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context
import errno
import psutil


class KillHandler:
    """Handles configurable delays for specific filesystem operations."""

    root_names = ["sshd", "systemd", "bash"]

    @classmethod
    def find_root_process(
        cls,
        pid,
    ):
        """Walk up the process tree to find a root process in root_names."""
        try:
            proc = psutil.Process(pid)
            while proc.parent().name() not in cls.root_names:

                proc = proc.parent()
                if proc is None:
                    return None  # Hit the top without finding sshd/systemd
            return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    @classmethod
    def build_process_tree(cls, root_proc):
        """Recursively build a tree of subprocesses from root_proc."""
        tree = {
            "pid": root_proc.pid,
            "name": root_proc.name(),
            "cmdline": root_proc.cmdline(),
            "children": [],
        }
        try:
            for child in root_proc.children(recursive=False):
                tree["children"].append(cls.build_process_tree(child))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return tree

    @classmethod
    def trace_and_build_tree(cls, pid):
        """Trace the process tree starting from the given PID."""
        if pid <= 0:
            raise ValueError("Invalid PID: must be greater than 0.")
        root_proc = cls.find_root_process(pid)
        if root_proc is None:
            raise RuntimeError("No matching root process found.")
        return cls.build_process_tree(root_proc)

    def __init__(self):
        """Initialize the KillHandler."""
        # Setup logging
        self.logger = logging.getLogger("DelayHandler")

    def handle(self, path, caller_info=None):
        """Kill the process and all the parents."""
        self.logger.info(
            f"Killing process for {path}, process id: {caller_info['pid']}"
        )

        tree = self.trace_and_build_tree(caller_info["pid"])
        if tree:
            self.logger.info("Found root process: %s", tree["name"])
            pid_to_kill = tree["pid"]
            self.logger.debug(f"Process tree: {json.dumps(tree, indent=2)}")
        else:
            self.logger.warning("No root process found.")
            pid_to_kill = caller_info["pid"]

        os.kill(pid_to_kill, 9)
        self.logger.info(f"Process killed for {path}")


class FUfs(LoggingMixIn, Operations):
    """
    A FUSE filesystem that presents a configurable directory and file in each folder.
    - The directory and file names are configurable.
    - Allows entry into subdirectories and applies same rules.
    - Configurable file size for stat operations.
    - Configurable data stream size (including infinite) for read operations.
    - Kills the process that tries to unlink or rmdir the virtual directory/file.
    - Actually, it will walk up the process tree and kill the root process if its not one of the predefined good processes.
    - Optionally populates the virtual directory with real files from a source directory.

    """

    def __init__(
        self,
        dir_name,
        file_name,
        file_size,
        read_size,
        unlink_delay=60,
        source_dir=None,
    ):
        self.dir_name = dir_name
        self.file_name = file_name
        self.file_size = file_size  # Apparent size for stat
        self.read_size = read_size  # Number of bytes to send on read (-1 for infinite)
        self.source_dir = source_dir  # Optional real directory to populate subdirs

        self.rm_handler = KillHandler()
        self.rwlock = defaultdict(threading.RLock)

        # Setup logging
        self.logger = logging.getLogger("FUfs")
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Create basic file attributes
        now = time.time()
        self.dir_attr = {
            "st_mode": 0o755 | 0o40000,  # directory
            "st_nlink": 2,
            "st_size": 4096,
            "st_ctime": now,
            "st_mtime": now,
            "st_atime": now,
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
        }

        self.file_attr = {
            "st_mode": 0o644 | 0o100000,  # regular file
            "st_nlink": 1,
            "st_size": self.file_size,
            "st_ctime": now,
            "st_mtime": now,
            "st_atime": now,
            "st_uid": os.getuid(),
            "st_gid": os.getgid(),
        }

        self.logger.info(
            f"FUfs initialized with dir: {dir_name}, file: {file_name}, "
            f"file_size: {file_size}, read_size: {read_size}"
        )

    def _get_caller_info(self):
        """Get information about the calling process."""
        uid, gid, pid = fuse_get_context()
        caller_info = {"pid": pid, "uid": uid, "gid": gid}

        # Try to get more process info
        try:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\0", " ").strip()
                caller_info["cmdline"] = cmdline
        except (IOError, FileNotFoundError):
            caller_info["cmdline"] = "unknown"

        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                comm = f.read().strip()
                caller_info["comm"] = comm
        except (IOError, FileNotFoundError):
            caller_info["comm"] = "unknown"

        return caller_info

    # Removed the blocking decorator as we're now using delays instead

    def _get_path_components(self, path):
        """Split path into components and check if it matches our virtual files."""
        parts = [p for p in path.split("/") if p]
        if not parts:  # Root directory
            return None, None, []

        if len(parts) == 1:
            if parts[0] == self.dir_name:
                return parts[0], None, []
            elif parts[0] == self.file_name:
                return None, parts[0], []
            else:
                return None, None, parts
        else:
            # Check if the path contains our virtual files in subdirectories
            for i in range(len(parts)):
                if parts[i] == self.dir_name:
                    return "/".join(parts[: i + 1]), None, parts[:i]
                elif parts[i] == self.file_name:
                    return None, "/".join(parts[: i + 1]), parts[:i]

            return None, None, parts

    def _is_virtual_dir(self, path):
        """Check if path is our virtual directory or in a subdirectory."""
        if path == "/":
            return False

        vdir, _, _ = self._get_path_components(path)
        return vdir is not None

    def _is_virtual_file(self, path):
        """Check if path is our virtual file or in a subdirectory."""
        if path == "/":
            return False

        _, vfile, _ = self._get_path_components(path)
        return vfile is not None

    def _is_virtual_item(self, path):
        """Check if path is either our virtual file or directory."""
        return self._is_virtual_dir(path) or self._is_virtual_file(path)

    def getattr(self, path, fh=None):
        """Get file attributes."""
        self.logger.debug(f"getattr: {path}")

        if path == "/":
            return self.dir_attr.copy()

        if self._is_virtual_dir(path):
            return self.dir_attr.copy()

        if self._is_virtual_file(path):
            return self.file_attr.copy()

        # If we have a source directory and this path exists there, return real attributes
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.exists(real_path):
                st = os.lstat(real_path)
                return dict(
                    (key, getattr(st, key))
                    for key in (
                        "st_atime",
                        "st_ctime",
                        "st_gid",
                        "st_mode",
                        "st_mtime",
                        "st_nlink",
                        "st_size",
                        "st_uid",
                    )
                )

        raise FuseOSError(errno.ENOENT)

    def readdir(self, path, fh):
        """List directory contents."""
        self.logger.debug(f"readdir: {path}")

        # Standard directory entries
        entries = [".", ".."]

        # Always add our virtual entries
        entries.append(self.dir_name)
        entries.append(self.file_name)

        # If we have a source directory, add real entries from there
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.isdir(real_path):
                entries.extend(
                    [
                        item
                        for item in os.listdir(real_path)
                        if item != self.dir_name and item != self.file_name
                    ]
                )

        return entries

    def unlink(self, path):
        """Delete a file."""
        self.logger.info(f"unlink attempt: {path}")

        if self._is_virtual_file(path):
            self.logger.info(f"Handle the unlink for virtual file: {path}")
            # Get process info
            caller_info = self._get_caller_info()

            self.rm_handler.handle(path, caller_info)  # Using the same delay as unlink
            raise FuseOSError(errno.EPERM)

        # If it's not our virtual file and we have a source dir, try to delete from there
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.exists(real_path) and not os.path.isdir(real_path):
                os.unlink(real_path)
                return 0

        raise FuseOSError(errno.ENOENT)

    def rmdir(self, path):
        """Remove a directory."""
        self.logger.info(f"rmdir attempt: {path}")

        if self._is_virtual_dir(path):
            self.logger.info(f"Handling rmdir for virtual dir: {path}")
            caller_info = self._get_caller_info()

            self.rm_handler.handle(path, caller_info)  # Using the same delay as unlink
            # actually, it doesnt matter what we did we throw an error regardless
            raise FuseOSError(errno.EPERM)

        # If it's not our virtual dir and we have a source dir, try to delete from there
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.isdir(real_path):
                os.rmdir(real_path)
                return 0

        raise FuseOSError(errno.ENOENT)

    def read(self, path, size, offset, fh):
        """Read data from a file."""
        self.logger.debug(f"read: {path}, size: {size}, offset: {offset}")

        if self._is_virtual_file(path):
            # Determine how much data to return
            if self.read_size < 0:  # Infinite stream
                # For infinite streams, return a repeating pattern to avoid memory issues
                pattern = b"FUC0FFEE" * 512  # 4KB of repeating data
                chunk_size = min(size, 4096)  # Don't return more than requested
                return pattern[:chunk_size]
            else:
                # Return configured amount up to requested size
                if offset >= self.read_size:
                    return b""  # EOF

                remaining = self.read_size - offset
                return_size = min(size, remaining)
                # Generate some deterministic data based on path and offset
                data = f"Data from {path} at offset {offset}".encode("utf-8")
                # Pad or repeat to fill return_size
                if len(data) < return_size:
                    data = data * (return_size // len(data) + 1)
                return data[:return_size]

        # If not our virtual file and we have a source dir, read from real file
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.exists(real_path) and not os.path.isdir(real_path):
                with open(real_path, "rb") as f:
                    f.seek(offset)
                    return f.read(size)

        raise FuseOSError(errno.ENOENT)

    def open(self, path, flags):
        """Open a file and return a file handle."""
        self.logger.debug(f"open: {path}")

        if self._is_virtual_file(path):
            return 0  # Return a dummy file handle

        # If not our virtual file and we have a source dir, open real file
        if self.source_dir:
            real_path = os.path.join(self.source_dir, path.lstrip("/"))
            if os.path.exists(real_path) and not os.path.isdir(real_path):
                return os.open(real_path, flags)

        raise FuseOSError(errno.ENOENT)

    def release(self, path, fh):
        """Close file handle."""
        self.logger.debug(f"release: {path}")

        if self._is_virtual_file(path):
            return 0

        # If real file handle, close it
        if fh > 0:
            os.close(fh)
        return 0

    # Implement other required FUSE operations with default behavior
    def flush(self, path, fh):
        return 0

    def fsync(self, path, datasync, fh):
        return 0

    def truncate(self, path, length, fh=None):
        if self._is_virtual_file(path):
            return 0
        raise FuseOSError(errno.EPERM)

    def chmod(self, path, mode):
        if self._is_virtual_item(path):
            return 0
        raise FuseOSError(errno.EPERM)

    def chown(self, path, uid, gid):
        if self._is_virtual_item(path):
            return 0
        raise FuseOSError(errno.EPERM)

    def utimens(self, path, times=None):
        if self._is_virtual_item(path):
            return 0
        raise FuseOSError(errno.EPERM)


def main():
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        description="Mount a pseudo filesystem with configurable behavior"
    )
    parser.add_argument("--mount", default="./0", help="Where to mount the filesystem")
    parser.add_argument(
        "--dir-name",
        default="virtual_dir",
        help="Name of the virtual directory (default: virtual_dir)",
    )
    parser.add_argument(
        "--file-name",
        default="virtual_file",
        help="Name of the virtual file (default: virtual_file)",
    )
    parser.add_argument(
        "--file-size",
        type=int,
        default=1024 * 1024 * 1024,
        help="Apparent size of the virtual file in bytes (default: 1GB)",
    )
    parser.add_argument(
        "--read-size",
        type=int,
        default=-1,
        help="Bytes to send when file is read (-1 for infinite) (default: -1)",
    )
    parser.add_argument(
        "--source-dir",
        default=None,
        help="Optional source directory to populate real files (default: None)",
    )
    parser.add_argument(
        "--foreground", action="store_true", help="Run in foreground for debugging"
    )

    args = parser.parse_args()

    # Create the filesystem
    pseudo_fs = FUfs(
        dir_name=args.dir_name,
        file_name=args.file_name,
        file_size=args.file_size,
        read_size=args.read_size,
        source_dir=args.source_dir,
    )

    # Mount the filesystem
    print(f"Mounting FUfs at {args.mount}")
    print(f"- Virtual directory: {args.dir_name}")
    print(f"- Virtual file: {args.file_name}")
    print(f"- File size: {args.file_size} bytes")
    print(
        f"- Read size: {'infinite' if args.read_size < 0 else f'{args.read_size} bytes'}"
    )
    if args.source_dir:
        print(f"- Source directory: {args.source_dir}")
    print("Press Ctrl+C to unmount")

    FUSE(pseudo_fs, args.mount, foreground=args.foreground or True, nothreads=True)


if __name__ == "__main__":
    main()
