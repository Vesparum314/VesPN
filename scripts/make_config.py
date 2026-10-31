"""Create a client config on a node (and leave it there). Reusable CLI.

Usage:
  NODE_HOST=.. NODE_PW=.. XUI_PATH=.. XUI_TOKEN=.. [PUBLIC_HOST=..] \
      python scripts/make_config.py --name test --proto vless|awg|both

Idempotent per name: if the client already exists it is reused, not duplicated.
"""

import argparse
import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402
from app.xui import XUIClient  # noqa: E402
from app.awg import AWGManager  # noqa: E402


def make_vless(node: SSHNode, name: str) -> None:
    path = os.environ["XUI_PATH"]
    port = int(os.environ.get("XUI_PORT", "29568"))
    token = os.environ["XUI_TOKEN"]
    with node.tunnel(port) as lport:
        xui = XUIClient(f"http://127.0.0.1:{lport}/{path}", token)
        inbound = xui.find_vless_inbound()
        if xui.client_exists(name):
            print(f"[vless] client {name!r} already exists on inbound {inbound.inbound_id} — reusing")
        else:
            c = xui.add_client(name, [inbound.inbound_id])
            print(f"[vless] created {name!r}  uuid={c['uuid']} subId={c['subId']}")
        print("[vless] link(s):")
        for l in xui.get_client_links(name):
            print("  " + l)


def make_awg(node: SSHNode, name: str) -> None:
    public_host = os.environ.get("PUBLIC_HOST") or os.environ["NODE_HOST"]
    mgr = AWGManager(node)
    mgr.discover_container()
    peer = mgr.add_peer(name, public_host)
    print(f"[awg] created peer {name!r}  address={peer['address']} pub={peer['public_key']}")
    print("[awg] client .conf:\n" + peer["conf"])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--proto", choices=["vless", "awg", "both"], default="vless")
    args = ap.parse_args()

    creds = NodeCredentials(host=os.environ["NODE_HOST"], password=os.environ.get("NODE_PW"))
    with SSHNode(creds) as node:
        print(f"[ssh] connected to {creds.host}")
        if args.proto in ("vless", "both"):
            make_vless(node, args.name)
        if args.proto in ("awg", "both"):
            make_awg(node, args.name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
