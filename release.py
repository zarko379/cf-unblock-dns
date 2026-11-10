#!/usr/bin/env python3
"""Publica una versión de cf-unblock-dns en GitHub (la que descarga `cfu update`).

  python release.py            comprueba, compila, empaqueta, firma, crea la etiqueta vX.Y.Z y la publica
  python release.py --dry-run  solo compila, empaqueta y firma en dist/release

La versión es la de `var version` en main.go: súbela allí antes de publicar.
Requiere Go, gh (con sesión iniciada), el árbol de git limpio en main, las
pruebas de GitHub Actions en verde para ese commit y la clave de firma
(CFU_SIGNING_KEY o %LOCALAPPDATA%/cf-unblock-dns/release-signing.key).

Una versión publicada no se modifica nunca: cualquier corrección es una
versión nueva (las cachés de GitHub siguen sirviendo los ficheros antiguos).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "dist" / "release"
# GOARCH -> GOARM ("" si no aplica). armv6 también funciona en armv7.
TARGETS = {"amd64": "", "arm64": "", "arm": "6"}
# Mismo conjunto que packageFiles en selfupdate.go.
SCRIPTS = ("install.sh", "check.sh", "uninstall.sh")
DATA = ("cf-unblock-dns.service", "cf-unblock-dns-update.service", "README.md", "LICENSE")


def tool(name: str, local: Path) -> str:
    found = shutil.which(name)
    if found:
        return found
    if local.exists():
        return str(local)
    sys.exit(f"No se encuentra {name}.")


LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", ""))
GO = tool("go", LOCALAPPDATA / "Programs" / "Go" / "go" / "bin" / "go.exe")
GH = tool("gh", LOCALAPPDATA / "Programs" / "gh" / "bin" / "gh.exe")
SIGNING_KEY = Path(os.environ.get("CFU_SIGNING_KEY") or LOCALAPPDATA / "cf-unblock-dns" / "release-signing.key")


def run(*args: str, capture: bool = False, **kwargs) -> str:
    result = subprocess.run(args, cwd=ROOT, check=True, text=True, capture_output=capture, **kwargs)
    return result.stdout.strip() if capture else ""


def program_version() -> str:
    match = re.search(r'^var version = "(\d+\.\d+\.\d+)"$', (ROOT / "main.go").read_text(encoding="utf-8"), re.M)
    if not match:
        sys.exit("No se encuentra 'var version = \"X.Y.Z\"' en main.go.")
    return match.group(1)


def add(archive: tarfile.TarFile, name: str, data: bytes, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), mode, 0
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    archive.addfile(info, io.BytesIO(data))


def build(version: str) -> list[Path]:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    packages = []
    for arch, arm in TARGETS.items():
        binary = OUT / f"cfu-{arch}"
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOTOOLCHAIN="local")
        if arm:
            env["GOARM"] = arm
        run(GO, "build", "-trimpath", "-buildvcs=false", f"-ldflags=-s -w -X main.version={version}", "-o", str(binary), ".", env=env)
        package = OUT / f"cf-unblock-dns-linux-{arch}.tar.gz"
        with tarfile.open(package, "w:gz", format=tarfile.GNU_FORMAT) as archive:
            add(archive, "cfu", binary.read_bytes(), 0o755)
            for name in SCRIPTS + DATA:
                data = (ROOT / name).read_bytes()
                if name.endswith((".sh", ".service")):
                    data = data.replace(b"\r\n", b"\n")
                add(archive, name, data, 0o755 if name in SCRIPTS else 0o644)
        binary.unlink()
        packages.append(package)
        print(f"  {package.name} ({package.stat().st_size // 1024} KiB)")
    sums = OUT / "SHA256SUMS"
    sums.write_text(
        "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in packages),
        encoding="ascii",
        newline="\n",  # en Windows write_text pondría CRLF, que sha256sum -c no acepta
    )
    # Firma Ed25519 de los bytes exactos de SHA256SUMS (cfu update la exige).
    run(GO, "run", "./tools/signrelease", "sign", str(SIGNING_KEY), str(sums))
    signature = sums.with_name(sums.name + ".sig")
    if signature.stat().st_size != 64:
        sys.exit("La firma no tiene 64 bytes.")
    print(f"  {signature.name} (firma Ed25519)")
    return packages + [sums, signature]


def ci_passed(commit: str) -> bool:
    out = run(GH, "run", "list", "--workflow", "ci.yml", "--commit", commit, "--json", "conclusion",
              "--jq", ".[].conclusion", capture=True)
    return "success" in out.split()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    version = program_version()
    tag = f"v{version}"

    if not args.dry_run:
        if run("git", "status", "--porcelain", capture=True):
            sys.exit("Hay cambios sin confirmar en git.")
        if run("git", "branch", "--show-current", capture=True) != "main":
            sys.exit("Publica desde la rama main.")
        if run("git", "tag", "--list", tag, capture=True):
            sys.exit(f"La etiqueta {tag} ya existe: sube la versión en main.go.")
        run("git", "fetch", "origin", "main")
        head = run("git", "rev-parse", "HEAD", capture=True)
        if head != run("git", "rev-parse", "origin/main", capture=True):
            sys.exit("main no coincide con origin/main: haz push (o pull) antes.")
        if not ci_passed(head):
            sys.exit("Las pruebas de GitHub Actions (ci.yml) no están en verde para este commit.")
    if not SIGNING_KEY.is_file():
        sys.exit(f"No se encuentra la clave de firma {SIGNING_KEY}.")

    print(f"Pruebas ({version})...")
    run(GO, "test", "./...", env=dict(os.environ, GOTOOLCHAIN="local"))
    print("Paquetes:")
    files = build(version)
    if args.dry_run:
        print(f"Listo en {OUT} (sin publicar).")
        return 0

    run("git", "tag", "-a", tag, "-m", f"cf-unblock-dns {version}")
    run("git", "push", "origin", tag)
    notes = (
        f"cf-unblock-dns {version}.\n\n"
        "Actualizar una instalación existente (conserva la configuración):\n\n"
        "```\nsudo cfu update\n```\n\n"
        "Instalación nueva: ver README."
    )
    run(GH, "release", "create", tag, *map(str, files), "--title", f"cf-unblock-dns {version}", "--notes", notes)
    print(f"Publicada {tag}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
