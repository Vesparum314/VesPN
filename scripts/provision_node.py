"""Provision 3x-ui on a fresh node (install + create VLESS inbound). Validates
the provisioning path on a real node. Env: NODE_HOST, NODE_PW."""

import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

os.environ.setdefault("PANEL_SECRET_KEY", "provision-test")  # crypto import needs it

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402
from app import provisioning  # noqa: E402

NODE_HOST = os.environ["NODE_HOST"]
NODE_PW = os.environ["NODE_PW"]


def main() -> int:
    with SSHNode(NodeCredentials(host=NODE_HOST, password=NODE_PW)) as node:
        print(f"[ssh] connected to {NODE_HOST}")
        print("[install] running 3x-ui installer (non-interactive)…")
        info = provisioning.install_3xui(node)
        print(f"[install] done: path={info['xui_path']} port={info['xui_port']} "
              f"user={info['username']} token=…{info['xui_token'][-6:]}")
        print("[inbound] creating VLESS+Reality inbound…")
        iid = provisioning.create_vless_inbound(
            node, info["xui_path"], info["xui_port"], info["xui_token"], name="vespn3"
        )
        print(f"[inbound] vless inbound id={iid}")
        print("\nXUI_PATH=" + info["xui_path"])
        print("XUI_PORT=" + str(info["xui_port"]))
        print("XUI_TOKEN=" + info["xui_token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
