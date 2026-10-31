"""End-to-end smoke test of the whole panel against a live node (B).

Boots the FastAPI app in-process and drives it over HTTP like a browser would:
admin logs in, adds node B, activates it, creates a client user; the client
logs in, creates a VLESS and an AmneziaWG device and fetches each config; then
both devices are deleted (which removes them from node B again).

Env:
  NODE_HOST, NODE_PW, XUI_PATH, XUI_TOKEN  [, XUI_PORT, AWG_PORT]
"""

import os
import re
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("PANEL_SECRET_KEY", "smoke-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "adminpass")
_dbfd, _dbpath = tempfile.mkstemp(suffix=".db")
os.close(_dbfd)
os.environ["DATABASE_URL"] = "sqlite:///" + _dbpath.replace("\\", "/")

import requests  # noqa: E402
import uvicorn  # noqa: E402

PORT = 8111
BASE = f"http://127.0.0.1:{PORT}"

NODE_HOST = os.environ["NODE_HOST"]
NODE_PW = os.environ["NODE_PW"]
XUI_PATH = os.environ["XUI_PATH"]
XUI_TOKEN = os.environ["XUI_TOKEN"]
XUI_PORT = os.environ.get("XUI_PORT", "29568")
AWG_PORT = os.environ.get("AWG_PORT", "44625")

_failures = []


def check(name, cond, extra=""):
    status = "ok " if cond else "FAIL"
    print(f"  [{status}] {name}" + (f"  {extra}" if extra else ""))
    if not cond:
        _failures.append(name)


def device_ids(html):
    return sorted(int(x) for x in set(re.findall(r"/devices/(\d+)", html)))


def main() -> int:
    config = uvicorn.Config("app.main:app", host="127.0.0.1", port=PORT, log_level="warning")
    server = uvicorn.Server(config)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # wait for startup
    for _ in range(100):
        try:
            if requests.get(BASE + "/healthz", timeout=1).status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.1)
    else:
        print("server did not start")
        return 1

    try:
        # --- admin ---
        a = requests.Session()
        r = a.post(BASE + "/login", data={"username": "admin", "password": "adminpass"})
        check("admin login", r.ok and r.url.rstrip("/") == BASE)

        r = a.post(BASE + "/admin/nodes", data={
            "name": "node-B", "public_host": NODE_HOST,
            "ssh_host": NODE_HOST, "ssh_port": "22", "ssh_username": "root", "ssh_password": NODE_PW,
            "xui_path": XUI_PATH, "xui_port": XUI_PORT, "xui_token": XUI_TOKEN,
            "awg_endpoint_host": "", "awg_port": AWG_PORT,
        })
        check("add node B", r.ok)
        r = a.post(BASE + "/admin/nodes/1/activate")
        check("activate node B", r.ok)
        # requests follows the 303, so the POST response already holds the
        # rendered page with the one-shot test result.
        test_html = a.post(BASE + "/admin/nodes/1/test").text
        check("node test shows SSH+xui green", ("SSH ✓" in test_html and "3x-ui ✓" in test_html),
              test_html.split("Проверка")[-1][:120] if "Проверка" in test_html else "(no result block)")

        r = a.post(BASE + "/admin/users", data={"username": "friend"})
        check("create client user (temp pw)", r.ok)

        # --- client: forced password change on first login ---
        c = requests.Session()
        c.post(BASE + "/login", data={"username": "friend", "password": "change-me-123"})
        landing = c.get(BASE + "/")
        check("first login pinned to change-password", landing.url.endswith("/change-password"))
        r = c.post(BASE + "/change-password", data={"new_password": "friendpass", "confirm": "friendpass"})
        check("password changed -> dashboard", r.ok and r.url.rstrip("/") == BASE)

        # VLESS device
        c.post(BASE + "/devices", data={"name": "phone", "protocol": "vless"})
        ids = device_ids(c.get(BASE + "/").text)
        vless_id = ids[-1]
        page = c.get(BASE + f"/devices/{vless_id}").text
        check("vless config issued", "vless://" in page, "vless://" + page.split("vless://")[-1][:60] if "vless://" in page else page[-200:])

        # AmneziaWG device
        c.post(BASE + "/devices", data={"name": "laptop", "protocol": "awg"})
        ids = device_ids(c.get(BASE + "/").text)
        awg_id = [i for i in ids if i != vless_id][-1]
        page = c.get(BASE + f"/devices/{awg_id}").text
        check("awg config issued (vpn://)", "vpn://" in page)

        # downloads
        r = c.get(BASE + f"/devices/{awg_id}/download")
        check("awg download (.vpn)", r.ok and r.text.startswith("vpn://")
              and ".vpn" in r.headers.get("Content-Disposition", ""))

        # --- cleanup: delete devices (removes client/peer from node B) ---
        r = c.post(BASE + f"/devices/{vless_id}/delete")
        check("delete vless device", r.ok)
        r = c.post(BASE + f"/devices/{awg_id}/delete")
        check("delete awg device", r.ok)
    finally:
        server.should_exit = True
        t.join(timeout=5)
        try:
            os.remove(_dbpath)
        except OSError:
            pass

    print()
    if _failures:
        print("FAILURES:", _failures)
        return 1
    print("ALL GREEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
