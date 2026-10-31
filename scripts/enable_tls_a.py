"""Enable HTTPS on server A via Caddy + DuckDNS (DNS-01), serving the panel on
:8443. Non-invasive: separate Caddy container, fictorium's 80/443 untouched.

Env: A_HOST, A_PW, PANEL_DOMAIN, DUCKDNS_TOKEN [, A_USER=root, TARGET=/opt/vpn-panel]
"""

import os
import posixpath
import sys
import time
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = os.environ.get("TARGET", "/opt/vpn-panel")
A_HOST = os.environ["A_HOST"]
A_PW = os.environ["A_PW"]
PANEL_DOMAIN = os.environ["PANEL_DOMAIN"]
DUCKDNS_TOKEN = os.environ["DUCKDNS_TOKEN"]

UPLOAD = [
    "deploy/duckdns/Dockerfile",
    "deploy/duckdns/Caddyfile",
    "deploy/docker-compose.duckdns.yml",
]


def _mkdirs(sftp, path):
    cur = ""
    for p in path.strip("/").split("/"):
        cur += "/" + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def upsert_env(text: str, updates: dict) -> str:
    lines = text.splitlines()
    keys = {k: False for k in updates}
    out = []
    for line in lines:
        if "=" in line and not line.strip().startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in updates:
                out.append(f"{k}={updates[k]}")
                keys[k] = True
                continue
        out.append(line)
    for k, done in keys.items():
        if not done:
            out.append(f"{k}={updates[k]}")
    return "\n".join(out) + "\n"


def main() -> int:
    with SSHNode(NodeCredentials(host=A_HOST, password=A_PW)) as node:
        print(f"[ssh] connected to {A_HOST}")
        sftp = node.client.open_sftp()
        for rel in UPLOAD:
            remote = posixpath.join(TARGET, rel)
            _mkdirs(sftp, posixpath.dirname(remote))
            sftp.put(str(ROOT / rel), remote)
            print(f"[upload] {rel}")

        env_path = posixpath.join(TARGET, ".env")
        with sftp.open(env_path, "r") as fh:
            env_text = fh.read().decode("utf-8")
        env_text = upsert_env(env_text, {
            "PANEL_DOMAIN": PANEL_DOMAIN,
            "DUCKDNS_TOKEN": DUCKDNS_TOKEN,
            "SESSION_HTTPS_ONLY": "true",
        })
        with sftp.open(env_path, "w") as fh:
            fh.write(env_text)
        sftp.chmod(env_path, 0o600)
        sftp.close()
        print("[env] PANEL_DOMAIN / DUCKDNS_TOKEN / SESSION_HTTPS_ONLY set")

        print("[compose] building Caddy + bringing up (xcaddy build can take a minute)…")
        rc, out, _ = node.run(
            f"cd {TARGET} && docker compose -f docker-compose.yml "
            f"-f deploy/docker-compose.duckdns.yml up -d --build 2>&1",
            timeout=600,
        )
        print(out[-2500:])
        if rc != 0:
            print(f"[compose] FAILED rc={rc}")
            return 1

        print("\n[tls] waiting for certificate issuance (DNS-01)…")
        ok = False
        for i in range(8):
            time.sleep(10)
            rc, out, _ = node.run(
                f"curl -sS -m 10 --resolve {PANEL_DOMAIN}:8443:127.0.0.1 "
                f"https://{PANEL_DOMAIN}:8443/healthz -w ' [%{{http_code}}]'",
                timeout=30,
            )
            print(f"  try {i+1}: {out.strip()[:120]}")
            if "[200]" in out:
                ok = True
                break

        print("\n[caddy logs]")
        _, logs, _ = node.run("docker logs vpn-panel-caddy --tail 20 2>&1", timeout=30)
        print(logs[-1800:])

        print("\n[containers]")
        _, ps, _ = node.run(
            "docker ps --format 'table {{.Names}}\\t{{.Status}}' | grep -E 'vpn-panel|caddy|fictorium'",
            timeout=30,
        )
        print(ps)
    print("\n" + ("HTTPS OK" if ok else "HTTPS not confirmed yet — check caddy logs above"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
