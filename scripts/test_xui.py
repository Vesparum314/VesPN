"""Exercise the VLESS primitive end-to-end against a live node (test node B).

Env (no secrets in file):
  NODE_HOST, NODE_PW   - SSH root access to the node
  XUI_PATH             - 3x-ui webBasePath (no slashes)
  XUI_PORT             - 3x-ui panel port on 127.0.0.1 (default 29568)
  XUI_TOKEN            - XUI_API_TOKEN

Creates a test client, fetches its server-built vless:// link, then DELETES it.
"""

import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402
from app.xui import XUIClient  # noqa: E402

NODE_HOST = os.environ["NODE_HOST"]
NODE_PW = os.environ["NODE_PW"]
XUI_PATH = os.environ["XUI_PATH"]
XUI_PORT = int(os.environ.get("XUI_PORT", "29568"))
XUI_TOKEN = os.environ["XUI_TOKEN"]

TEST_EMAIL = "paneltest-delete-me"


def main() -> int:
    creds = NodeCredentials(host=NODE_HOST, password=NODE_PW)
    with SSHNode(creds) as node:
        print(f"[ssh] connected to {NODE_HOST}")
        with node.tunnel(XUI_PORT) as lport:
            base = f"http://127.0.0.1:{lport}/{XUI_PATH}"
            print(f"[tunnel] 127.0.0.1:{lport} -> node 127.0.0.1:{XUI_PORT}")
            xui = XUIClient(base, XUI_TOKEN)

            inbound = xui.find_vless_inbound()
            print(f"[inbound] id={inbound.inbound_id} port={inbound.port} remark={inbound.remark!r}")

            if xui.client_exists(TEST_EMAIL):
                print("[cleanup] removing leftover test client")
                xui.del_client(TEST_EMAIL)

            print(f"[create] adding {TEST_EMAIL!r} ...")
            client = xui.add_client(TEST_EMAIL, [inbound.inbound_id], flow="xtls-rprx-vision")
            print(f"  uuid={client['uuid']}  subId={client['subId']}")

            links = xui.get_client_links(TEST_EMAIL)
            print(f"[links] {len(links)} link(s):")
            for l in links:
                print("  " + l)

            print(f"[verify] exists after add: {xui.client_exists(TEST_EMAIL)}")
            print(f"[delete] removing {TEST_EMAIL!r} ...")
            xui.del_client(TEST_EMAIL)
            print(f"[verify] exists after delete: {xui.client_exists(TEST_EMAIL)}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
