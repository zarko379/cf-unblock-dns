#!/usr/bin/env python3
"""Despliega y diagnostica cf-unblock-dns en el LXC por SSH (desarrollo).

Las credenciales se leen de .env (junto a este script) y nunca se imprimen;
cualquier aparición de una contraseña en la salida remota se enmascara.
Requiere paramiko (pip install -r requirements-dev.txt).

  python deploy.py info              estado del LXC, sin cambios
  python deploy.py install           compila, sube los ficheros y ejecuta install.sh -y
  python deploy.py install --as-version 3.99.0   igual, pero el binario dice ser esa versión
                                     (para probar cfu update contra GitHub)
  python deploy.py check [DOMINIO]   diagnóstico; con DOMINIO simula un bloqueo
  python deploy.py simulate DOMINIO  bloqueo simulado de extremo a extremo (Pi-hole + HTTPS)
  python deploy.py logs [N]          últimas N líneas del journal
  python deploy.py run "COMANDO"     ejecuta un comando como root
  python deploy.py uninstall         devuelve Pi-hole a Unbound y desinstala
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import posixpath
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import paramiko
except ImportError:  # pragma: no cover - mensaje para el usuario
    sys.exit("Falta paramiko: python -m pip install -r requirements-dev.txt")

ROOT = Path(__file__).resolve().parent
# CFU_ENV_FILE lets another checkout (e.g. a git worktree) reuse the same credentials.
ENV_FILE = Path(os.environ.get("CFU_ENV_FILE") or ROOT / ".env")
KNOWN_HOSTS = ENV_FILE.with_name(".ssh_known_hosts")
REMOTE_DIR = "cf-unblock-dns-src"
INSTALL_DIR = "/opt/cf-unblock-dns"
UPLOAD_FILES = (
    "install.sh",
    "uninstall.sh",
    "check.sh",
    "cf-unblock-dns.service",
    "cf-unblock-dns-update.service",
)
# Sources too, so install.sh can build on the LXC if no binary is uploaded.
GO_SOURCES = tuple(sorted(p.name for p in ROOT.glob("*.go") if not p.name.endswith("_test.go"))) + ("go.mod",)
# uname -m -> (GOARCH, GOARM)
GO_ARCHES: Dict[str, Tuple[str, str]] = {
    "x86_64": ("amd64", ""),
    "aarch64": ("arm64", ""),
    "armv7l": ("arm", "7"),
    "armv6l": ("arm", "6"),
}


def find_go() -> Optional[str]:
    found = shutil.which("go")
    if found:
        return found
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Go" / "go" / "bin" / "go.exe"
    return str(local) if local.exists() else None


def build_binary(machine: str, as_version: Optional[str] = None) -> Optional[Path]:
    """Cross-compile the static Linux binary for the LXC's architecture."""
    go = find_go()
    if go is None:
        print("[deploy] Go no está instalado aquí: se suben las fuentes y el LXC deberá compilarlas")
        return None
    if machine not in GO_ARCHES:
        sys.exit(f"Arquitectura del LXC no soportada: {machine}")
    arch, arm = GO_ARCHES[machine]
    output = ROOT / "dist" / f"cfu-linux-{arch}"
    env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOTOOLCHAIN="local")
    if arm:
        env["GOARM"] = arm
    ldflags = "-s -w" + (f" -X main.version={as_version}" if as_version else "")
    subprocess.run([go, "build", "-trimpath", f"-ldflags={ldflags}", "-o", str(output), "."], cwd=ROOT, env=env, check=True)
    print(f"[deploy] Compilado {output.relative_to(ROOT)} para linux/{arch} ({output.stat().st_size // 1024} KiB)")
    return output

INFO_SCRIPT = r"""
echo "== Sistema"
(. /etc/os-release && echo "$PRETTY_NAME"); uname -r
echo "virtualización: $(systemd-detect-virt 2>/dev/null || echo desconocida)"
echo "python: $(python3 -V 2>&1)"
echo "== Pi-hole"
pihole -v 2>/dev/null || echo "pihole no encontrado"
echo "dns.upstreams: $(pihole-FTL --config dns.upstreams 2>/dev/null)"
echo "dns.dnssec: $(pihole-FTL --config dns.dnssec 2>/dev/null)"
echo "dns.cache.optimizer: $(pihole-FTL --config dns.cache.optimizer 2>/dev/null)"
echo "== Unbound"
unbound -V 2>/dev/null | head -1
echo "== Servicios"
for unit in pihole-FTL unbound cf-unblock-dns cf-unblock-dns-update bpasserr-dns bpasserr-dns-update redsocks warp-svc; do
    printf '%-22s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null)"
done
echo "== Puertos"
ss -Hlnup 2>/dev/null | grep -E ':(53|5335|5336)\s'
ss -Hlntp 2>/dev/null | grep -E ':(53|5335|5336)\s'
echo "== Red"
ip -br addr 2>/dev/null
ip route show default 2>/dev/null
ip -6 route show default 2>/dev/null
echo "== Pruebas"
echo "Unbound example.com: $(dig +time=2 +tries=1 @127.0.0.1 -p 5335 example.com A +short 2>/dev/null | tr '\n' ' ')"
echo "Reglas iptables antiguas (SOCKS_PROXY): $(iptables -t nat -S 2>/dev/null | grep -c SOCKS_PROXY)"
"""


def load_env(path: Path) -> Dict[str, str]:
    if not path.exists():
        sys.exit(f"No existe {path}. Copia .env.example a .env y rellénalo.")
    values: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def fingerprint(key: "paramiko.PKey") -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")


class TrustOnFirstUse(paramiko.MissingHostKeyPolicy):
    def __init__(self, pinned: Optional[str]) -> None:
        self.pinned = pinned

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        print_fp = fingerprint(key)
        if self.pinned and print_fp != self.pinned:
            raise paramiko.SSHException(
                f"La huella del host (SHA256:{print_fp}) no coincide con SSH_HOST_KEY_SHA256"
            )
        client.get_host_keys().add(hostname, key.get_name(), key)
        client.save_host_keys(str(KNOWN_HOSTS))
        print(f"[deploy] Clave del host {hostname} guardada en {KNOWN_HOSTS.name} (SHA256:{print_fp})")


class MaskedPrinter:
    def __init__(self, secrets: List[str]) -> None:
        self.secrets = [secret for secret in secrets if len(secret) >= 3]
        self.buffer = ""

    def feed(self, data: bytes) -> None:
        self.buffer += data.decode("utf-8", "replace")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            self._emit(line + "\n")

    def flush(self) -> None:
        if self.buffer:
            self._emit(self.buffer)
            self.buffer = ""

    def _emit(self, text: str) -> None:
        for secret in self.secrets:
            text = text.replace(secret, "******")
        sys.stdout.write(text)
        sys.stdout.flush()


class Remote:
    def __init__(self, env: Dict[str, str]) -> None:
        self.host = env.get("SSH_HOST", "").strip()
        if not self.host:
            sys.exit(f"Falta SSH_HOST en {ENV_FILE}")
        self.port = int(env.get("SSH_PORT") or 22)
        self.user = env.get("SSH_USER") or "root"
        self.password = env.get("SSH_PASSWORD") or None
        key_file = env.get("SSH_KEY_FILE") or None
        self.key_file = str(Path(key_file).expanduser()) if key_file else None
        self.passphrase = env.get("SSH_KEY_PASSPHRASE") or None
        self.sudo_password = env.get("SUDO_PASSWORD") or self.password
        pinned = (env.get("SSH_HOST_KEY_SHA256") or "").strip()
        self.pinned = pinned[len("SHA256:"):] if pinned.startswith("SHA256:") else (pinned or None)
        self.secrets = [value for value in (self.password, self.passphrase, self.sudo_password) if value]
        self.client: Optional[paramiko.SSHClient] = None

    def __enter__(self) -> "Remote":
        client = paramiko.SSHClient()
        if KNOWN_HOSTS.exists():
            client.load_host_keys(str(KNOWN_HOSTS))
        client.set_missing_host_key_policy(TrustOnFirstUse(self.pinned))
        try:
            client.connect(
                self.host,
                port=self.port,
                username=self.user,
                password=self.password,
                key_filename=self.key_file,
                passphrase=self.passphrase,
                look_for_keys=self.key_file is None and self.password is None,
                allow_agent=self.password is None,
                timeout=15,
                auth_timeout=20,
                banner_timeout=20,
            )
        except paramiko.BadHostKeyException:
            sys.exit(
                f"La clave del host {self.host} ha cambiado respecto a {KNOWN_HOSTS.name}. "
                "Si has reinstalado el LXC, borra ese fichero; si no, no continúes."
            )
        except paramiko.AuthenticationException:
            sys.exit("Autenticación SSH rechazada: revisa SSH_USER y la contraseña o clave en .env")
        except (OSError, paramiko.SSHException) as exc:
            sys.exit(f"No se pudo conectar a {self.host}:{self.port}: {exc}")
        transport = client.get_transport()
        assert transport is not None
        actual = fingerprint(transport.get_remote_server_key())
        if self.pinned and actual != self.pinned:
            client.close()
            sys.exit(f"La huella del host (SHA256:{actual}) no coincide con SSH_HOST_KEY_SHA256")
        self.client = client
        print(f"[deploy] Conectado a {self.user}@{self.host}:{self.port}")
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.client is not None:
            self.client.close()

    def run(self, command: str) -> int:
        """Run command as root (through sudo when SSH_USER is not root), streaming its output."""
        assert self.client is not None
        sudo_password = None
        if self.user == "root":
            wrapped = f"bash -c {shlex.quote(command)}"
        elif self.sudo_password:
            wrapped = f"sudo -S -p '' -- bash -c {shlex.quote(command)}"
            sudo_password = self.sudo_password
        else:
            wrapped = f"sudo -n -- bash -c {shlex.quote(command)}"
        transport = self.client.get_transport()
        assert transport is not None
        channel = transport.open_session()
        channel.set_combine_stderr(True)
        channel.exec_command(wrapped)
        if sudo_password is not None:
            channel.sendall((sudo_password + "\n").encode("utf-8"))
        channel.shutdown_write()
        printer = MaskedPrinter(self.secrets)
        while True:
            data = channel.recv(65536)
            if not data:
                break
            printer.feed(data)
        printer.flush()
        status = channel.recv_exit_status()
        channel.close()
        return status

    def capture(self, command: str) -> str:
        """Run a harmless command as the SSH user and return its output."""
        assert self.client is not None
        _stdin, stdout, _stderr = self.client.exec_command(command, timeout=30)
        return stdout.read().decode("utf-8", "replace").strip()

    def upload(self, binary: Optional[Path] = None) -> str:
        assert self.client is not None
        sftp = self.client.open_sftp()
        try:
            remote_dir = posixpath.join(sftp.normalize("."), REMOTE_DIR)
            try:
                sftp.mkdir(remote_dir, 0o700)
            except OSError:
                pass
            for name in UPLOAD_FILES + GO_SOURCES:
                data = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
                target = posixpath.join(remote_dir, name)
                with sftp.open(target, "wb") as handle:
                    handle.write(data)
                sftp.chmod(target, 0o755 if name.endswith(".sh") else 0o644)
            target = posixpath.join(remote_dir, "cfu")
            if binary is not None:
                sftp.put(str(binary), target)
                sftp.chmod(target, 0o755)
            else:
                try:
                    sftp.remove(target)  # never install a stale binary
                except OSError:
                    pass
        finally:
            sftp.close()
        count = len(UPLOAD_FILES) + len(GO_SOURCES) + (binary is not None)
        print(f"[deploy] {count} ficheros subidos a {remote_dir}")
        return remote_dir


def main(argv: Optional[List[str]] = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("info")
    commands.add_parser("upload")
    install = commands.add_parser("install")
    install.add_argument("--as-version", help="versión X.Y.Z que dirá el binario")
    check = commands.add_parser("check")
    check.add_argument("domain", nargs="?")
    selftest = commands.add_parser("selftest")
    selftest.add_argument("domain")
    simulate = commands.add_parser("simulate")
    simulate.add_argument("domain")
    logs = commands.add_parser("logs")
    logs.add_argument("lines", nargs="?", type=int, default=50)
    run = commands.add_parser("run")
    run.add_argument("remote_command")
    commands.add_parser("uninstall")
    args = parser.parse_args(argv)

    with Remote(load_env(ENV_FILE)) as remote:
        if args.command == "info":
            return remote.run(INFO_SCRIPT)
        if args.command in ("upload", "install"):
            as_version = getattr(args, "as_version", None)
            remote_dir = remote.upload(build_binary(remote.capture("uname -m"), as_version))
            if args.command == "upload":
                return 0
            status = remote.run(f"bash {shlex.quote(remote_dir + '/install.sh')} -y")
            if status == 0:
                status = remote.run(f"{INSTALL_DIR}/check.sh")
            return status
        if args.command == "check":
            domain = f" {shlex.quote(args.domain)}" if args.domain else ""
            return remote.run(f"{INSTALL_DIR}/check.sh{domain}")
        if args.command == "simulate":
            return remote.run(f"{INSTALL_DIR}/check.sh --simular {shlex.quote(args.domain)}")
        if args.command == "selftest":
            return remote.run(
                f"cd / && runuser -u cf-unblock-dns -- {INSTALL_DIR}/cfu serve --self-test {shlex.quote(args.domain)}"
            )
        if args.command == "logs":
            return remote.run(
                f"journalctl -u cf-unblock-dns -u cf-unblock-dns-update -n {args.lines} --no-pager -o short-iso"
            )
        if args.command == "run":
            return remote.run(args.remote_command)
        if args.command == "uninstall":
            return remote.run(f"{INSTALL_DIR}/uninstall.sh")
    return 2


if __name__ == "__main__":
    sys.exit(main())
