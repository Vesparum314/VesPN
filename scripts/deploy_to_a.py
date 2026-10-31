"""Deploy the panel to server A over SSH (non-invasive: own compose project in
/opt/vpn-panel, localhost-bound port). Uploads the repo, writes .env with fresh
secrets, then `docker compose up -d --build`.

Env: A_HOST, A_PW [, A_USER=root, TARGET=/opt/vpn-panel, PANEL_BIND]
Prints the generated admin password.
"""

import os
import posixpath
import secrets
import stat
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = os.environ.get("TARGET", "/opt/vpn-panel")
PANEL_BIND = os.environ.get("PANEL_BIND", "127.0.0.1:8080")

# what to upload (relative to repo root)
UPLOAD_DIRS = ["app", "deploy"]
UPLOAD_FILES = ["Dockerfile", "docker-compose.yml", "requirements.txt", "README.md", ".env.example"]
SKIP_SUFFIX = (".pyc",)
# NB: do NOT skip "data" — app/data/ holds the VLESS inbound template the
# provisioner reads. (The runtime sqlite dir lives at repo-root ./data, which
# isn't under UPLOAD_DIRS, so it's never uploaded anyway.)
SKIP_PARTS = {"__pycache__"}


def _sftp_mkdirs(sftp, path):
    parts = path.strip("/").split("/")
    cur = ""
    for p in parts:
        cur += "/" + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def upload_tree(sftp, local_dir: pathlib.Path, remote_dir: str):
    for item in sorted(local_dir.rglob("*")):
        if any(part in SKIP_PARTS for part in item.relative_to(local_dir).parts):
            continue
        if item.is_dir():
            continue
        if item.suffix in SKIP_SUFFIX:
            continue
        rel = item.relative_to(local_dir).as_posix()
        remote = posixpath.join(remote_dir, rel)
        _sftp_mkdirs(sftp, posixpath.dirname(remote))
        sftp.put(str(item), remote)


def main() -> int:
    creds = NodeCredentials(host=os.environ["A_HOST"],
                            username=os.environ.get("A_USER", "root"),
                            password=os.environ["A_PW"])
    admin_pw = secrets.token_urlsafe(10)
    secret_key = secrets.token_urlsafe(48)

    with SSHNode(creds) as node:
        print(f"[ssh] connected to {creds.host}")
        sftp = node.client.open_sftp()
        _sftp_mkdirs(sftp, TARGET)
        print(f"[upload] -> {TARGET}")
        for d in UPLOAD_DIRS:
            upload_tree(sftp, ROOT / d, posixpath.join(TARGET, d))
        for f in UPLOAD_FILES:
            _sftp_mkdirs(sftp, TARGET)
            sftp.put(str(ROOT / f), posixpath.join(TARGET, f))

        env_path = posixpath.join(TARGET, ".env")
        try:
            sftp.stat(env_path)
            env_exists = True
        except FileNotFoundError:
            env_exists = False
        if env_exists:
            admin_pw = "(unchanged — existing .env kept)"
            print("[env] existing .env kept (secrets not rotated)")
        else:
            env = (
                f"PANEL_SECRET_KEY={secret_key}\n"
                f"ADMIN_USERNAME=admin\n"
                f"ADMIN_PASSWORD={admin_pw}\n"
                f"SESSION_HTTPS_ONLY=false\n"
                f"PANEL_BIND={PANEL_BIND}\n"
            )
            with sftp.open(env_path, "w") as fh:
                fh.write(env)
            sftp.chmod(env_path, 0o600)
            print("[env] wrote .env (0600)")
        sftp.close()

        overlay = os.environ.get("COMPOSE_OVERLAY", "")  # e.g. deploy/docker-compose.duckdns.yml
        files = "-f docker-compose.yml" + (f" -f {overlay}" if overlay else "")
        print(f"[build] docker compose {files} up -d --build (may take a few minutes) ...")
        rc, out, err = node.run(f"cd {TARGET} && docker compose {files} up -d --build 2>&1", timeout=600)
        print(out[-3000:])
        if rc != 0:
            print(f"[build] FAILED rc={rc}")
            return 1

        rc, out, _ = node.run(f"cd {TARGET} && docker compose ps", timeout=60)
        print(out)
        rc, out, _ = node.run(
            "sleep 3; curl -sS -o /dev/null -w '%{http_code}' http://" + PANEL_BIND + "/healthz", timeout=30
        )
        print(f"[health] /healthz -> {out}")

    print("\n==== DEPLOYED ====")
    print(f"dir:   {TARGET}")
    print(f"bind:  {PANEL_BIND}")
    print(f"admin: admin / {admin_pw}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
