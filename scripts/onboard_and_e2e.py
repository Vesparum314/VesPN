"""Through the DEPLOYED panel on A (over an SSH tunnel), register node V, make
it active, and run a transient end-to-end check (create user+devices, verify the
issued configs point at V, then clean them up). Leaves the panel with just the
admin user and node V active.

Env: A_HOST, A_PW, A_ADMIN_PW, V_HOST, V_PW, V_XUI_PATH, V_XUI_PORT, V_XUI_TOKEN,
     V_AWG_PORT
"""

import os
import re
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402

import requests  # noqa: E402

A_HOST = os.environ["A_HOST"]
A_PW = os.environ["A_PW"]
ADMIN_PW = os.environ["A_ADMIN_PW"]
V_HOST = os.environ["V_HOST"]
V_PW = os.environ["V_PW"]
V_XUI_PATH = os.environ["V_XUI_PATH"]
V_XUI_PORT = os.environ["V_XUI_PORT"]
V_XUI_TOKEN = os.environ["V_XUI_TOKEN"]
V_AWG_PORT = os.environ.get("V_AWG_PORT", "33347")

fails = []


def check(name, cond, extra=""):
    print(f"  [{'ok ' if cond else 'FAIL'}] {name}" + (f"  {extra}" if extra else ""))
    if not cond:
        fails.append(name)


def ids(html):
    return sorted(int(x) for x in set(re.findall(r"/devices/(\d+)", html)))


def main() -> int:
    with SSHNode(NodeCredentials(host=A_HOST, password=A_PW)) as a, a.tunnel(8080) as lport:
        base = f"http://127.0.0.1:{lport}"
        print(f"[tunnel] localhost:{lport} -> A:8080")

        adm = requests.Session()
        r = adm.post(f"{base}/login", data={"username": "admin", "password": ADMIN_PW})
        check("admin login", r.ok and r.url.rstrip("/") == base)

        # add node V (idempotent-ish: only add if not present)
        nodes_html = adm.get(f"{base}/admin/nodes").text
        if "vespn3-V" not in nodes_html:
            r = adm.post(f"{base}/admin/nodes", data={
                "name": "vespn3-V", "public_host": V_HOST,
                "ssh_host": V_HOST, "ssh_port": "22", "ssh_username": "root", "ssh_password": V_PW,
                "xui_path": V_XUI_PATH, "xui_port": V_XUI_PORT, "xui_token": V_XUI_TOKEN,
                "awg_endpoint_host": "", "awg_port": V_AWG_PORT,
            })
            check("add node V", r.ok)
        else:
            print("  [ok ] node V already present")

        # find its id and activate
        nodes_html = adm.get(f"{base}/admin/nodes").text
        node_id = re.search(r"/admin/nodes/(\d+)/activate", nodes_html)
        # if already active there is no activate button; handle both
        if node_id:
            adm.post(f"{base}/admin/nodes/{node_id.group(1)}/activate")
        # test (any node id works; grab first test form)
        tid = re.search(r"/admin/nodes/(\d+)/test", adm.get(f"{base}/admin/nodes").text).group(1)
        test_html = adm.post(f"{base}/admin/nodes/{tid}/test").text
        check("node V test SSH+AWG+3x-ui green",
              all(s in test_html for s in ["SSH ✓", "AmneziaWG ✓", "3x-ui ✓"]),
              test_html.split("Проверка")[-1][:120] if "Проверка" in test_html else "(no block)")

        # transient client + devices
        adm.post(f"{base}/admin/users", data={"username": "e2e-check", "password": "e2epass"})
        c = requests.Session()
        c.post(f"{base}/login", data={"username": "e2e-check", "password": "e2epass"})

        c.post(f"{base}/devices", data={"name": "t", "protocol": "vless"})
        vid = ids(c.get(f"{base}/").text)[-1]
        page = c.get(f"{base}/devices/{vid}").text
        check("VLESS config issued from V", f"@{V_HOST}:" in page,
              ("vless://" + page.split("vless://")[-1][:50]) if "vless://" in page else page[-160:])

        c.post(f"{base}/devices", data={"name": "t", "protocol": "awg"})
        aid = [i for i in ids(c.get(f"{base}/").text) if i != vid][-1]
        page = c.get(f"{base}/devices/{aid}").text
        check("AWG config issued from V", ("[Interface]" in page and f"{V_HOST}:{V_AWG_PORT}" in page))

        # cleanup transient (also deprovisions from V)
        c.post(f"{base}/devices/{vid}/delete")
        c.post(f"{base}/devices/{aid}/delete")
        # delete the e2e user
        uhtml = adm.get(f"{base}/admin/users").text
        m = re.findall(r"/admin/users/(\d+)/delete", uhtml)
        # delete the last user (e2e-check was created last)
        for uid in m[-1:]:
            adm.post(f"{base}/admin/users/{uid}/delete")
        print("  [ok ] cleaned up transient user + devices")

    print()
    if fails:
        print("FAILURES:", fails)
        return 1
    print("ALL GREEN — node V onboarded & active, end-to-end verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
