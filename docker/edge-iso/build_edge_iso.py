#!/usr/bin/env python3
"""Build Ludus's secret-free stateless Alpine `ludus-edge.iso` live appliance.

Follows Sophon's deterministic `localhost.apkovl.tar.gz` + `xorriso` pattern:
- Zero secrets, private keys, or environment-specific IPs are baked into the ISO.
- Bundles signed offline Alpine `.apk` packages (`/opt/ludus-edge-pkgs/*.apk`),
  the static `ludus-edge-proxy` Go binary, and `ludus-edge-init.sh` so `ludus-edge`
  boots 100% air-gapped in RAM and reads network + Ed25519 enrollment pubkey from
  Proxmox standard Cloud-Init `cidata`.
"""

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
DEFAULT_INIT_SCRIPT = HERE / "ludus-edge-init.sh"

WORLD = "alpine-base\n"

ISSUE = (
    "Ludus Stateless Edge Appliance (ludus-edge) — Managed via mTLS 1.3 (:8444)\n"
    "Zero local SSH or baked secrets. Logs: /var/log/ludus-edge-proxy.log\n\n"
)

AUTOSTART = (
    "#!/bin/sh\n"
    "exec >/dev/console 2>&1 </dev/console\n"
    "/usr/local/libexec/ludus-edge-init\n"
)


def _add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    tar.addfile(info, io.BytesIO(data))


def _add_dir(tar: tarfile.TarFile, name: str, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    tar.addfile(info)


def _add_symlink(tar: tarfile.TarFile, name: str, target: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.mode = 0o777
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = 0
    tar.addfile(info)


def build_apkovl(
    edge_binary: Path,
    pkgs_dir: Path,
    apk_keys_dir: Path | None = None,
    init_script: Path = DEFAULT_INIT_SCRIPT,
) -> bytes:
    """Return deterministic gzip-compressed `localhost.apkovl.tar.gz` bytes."""
    binary_bytes = edge_binary.read_bytes()
    init_bytes = init_script.read_bytes()
    apk_files = sorted(pkgs_dir.glob("*.apk"), key=lambda p: p.name)
    if not apk_files:
        raise ValueError(f"No offline .apk packages found in {pkgs_dir}")

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for directory in (
            "etc",
            "etc/apk",
            "etc/apk/keys",
            "etc/local.d",
            "etc/runlevels",
            "etc/runlevels/default",
            "opt",
            "opt/ludus-edge-pkgs",
            "usr",
            "usr/local",
            "usr/local/bin",
            "usr/local/libexec",
        ):
            _add_dir(tar, directory)

        _add_bytes(tar, "etc/.default_boot_services", b"", 0o644)
        _add_bytes(tar, "etc/hostname", b"ludus-edge\n", 0o644)
        _add_bytes(tar, "etc/apk/world", WORLD.encode(), 0o644)
        _add_bytes(tar, "etc/issue", ISSUE.encode(), 0o644)
        _add_symlink(tar, "etc/runlevels/default/local", "/etc/init.d/local")
        _add_bytes(tar, "etc/local.d/10-ludus-edge.start", AUTOSTART.encode(), 0o755)
        _add_bytes(tar, "usr/local/libexec/ludus-edge-init", init_bytes, 0o755)
        _add_bytes(tar, "usr/local/bin/ludus-edge-proxy", binary_bytes, 0o755)

        if apk_keys_dir and apk_keys_dir.is_dir():
            for key_file in sorted(apk_keys_dir.iterdir(), key=lambda p: p.name):
                if key_file.is_file():
                    _add_bytes(tar, f"etc/apk/keys/{key_file.name}", key_file.read_bytes(), 0o644)

        for apk_file in apk_files:
            _add_bytes(tar, f"opt/ludus-edge-pkgs/{apk_file.name}", apk_file.read_bytes(), 0o644)

    return gzip.compress(raw.getvalue(), mtime=0)


def build_iso(
    stock_iso: Path,
    edge_binary: Path,
    pkgs_dir: Path,
    output_iso: Path,
    apk_keys_dir: Path | None = None,
    init_script: Path = DEFAULT_INIT_SCRIPT,
) -> None:
    if not shutil.which("xorriso"):
        raise ValueError("xorriso is required to build ludus-edge.iso")
    for label, path in (
        ("stock Alpine virt ISO", stock_iso),
        ("ludus-edge-proxy binary", edge_binary),
        ("ludus-edge-init.sh", init_script),
    ):
        if not path.is_file():
            raise ValueError(f"Missing {label}: {path}")

    apkovl_bytes = build_apkovl(edge_binary, pkgs_dir, apk_keys_dir=apk_keys_dir, init_script=init_script)
    output_iso = Path(os.path.abspath(output_iso))
    output_iso.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="ludus-edge-iso-") as work:
        ovl_path = Path(work) / "localhost.apkovl.tar.gz"
        ovl_path.write_bytes(apkovl_bytes)
        staged_iso = Path(work) / "ludus-edge.iso"
        subprocess.run(
            [
                "xorriso",
                "-indev",
                str(stock_iso),
                "-outdev",
                str(staged_iso),
                "-boot_image",
                "any",
                "replay",
                "-volid",
                "LUDUS_EDGE",
                "-map",
                str(ovl_path),
                "/localhost.apkovl.tar.gz",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not staged_iso.is_file() or staged_iso.stat().st_size == 0:
            raise ValueError("xorriso did not produce a non-empty ludus-edge.iso")
        shutil.copyfile(staged_iso, output_iso)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-iso", type=Path, required=True, help="Verified alpine-virt x86_64 ISO")
    parser.add_argument("--edge-binary", type=Path, required=True, help="Static linux/amd64 ludus-edge-proxy binary")
    parser.add_argument("--pkgs-dir", type=Path, required=True, help="Directory of signed offline .apk files")
    parser.add_argument("--apk-keys-dir", type=Path, default=Path("/etc/apk/keys"), help="Alpine APK signing keys dir")
    parser.add_argument("--init-script", type=Path, default=DEFAULT_INIT_SCRIPT, help="OpenRC boot script")
    parser.add_argument("--output", type=Path, required=True, help="Destination path for ludus-edge.iso")
    args = parser.parse_args(argv)

    try:
        build_iso(
            stock_iso=args.stock_iso,
            edge_binary=args.edge_binary,
            pkgs_dir=args.pkgs_dir,
            output_iso=args.output,
            apk_keys_dir=args.apk_keys_dir,
            init_script=args.init_script,
        )
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "output", "") or str(exc)
        print(f"ludus-edge ISO build failed: {detail}", file=sys.stderr)
        return 1

    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    size_mb = args.output.stat().st_size / (1024 * 1024)
    print(f"Built {args.output} ({size_mb:.1f} MiB, sha256={digest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
