"""Exercise the AmneziaWG primitive end-to-end against a live node (test node B).

Env:
  NODE_HOST, NODE_PW   - SSH root access to the node
  PUBLIC_HOST          - endpoint host clients dial (default NODE_HOST)

Adds a client peer (live + persisted), prints the client .conf, verifies it in
`awg show`, the server config and clientsTable, then removes it and confirms the
node is back to its original state. Uses try/finally so a test peer is never
left behind.
"""

import os
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.node_ssh import NodeCredentials, SSHNode  # noqa: E402
from app.awg import AWGManager  # noqa: E402

NODE_HOST = os.environ["NODE_HOST"]
NODE_PW = os.environ["NODE_PW"]
PUBLIC_HOST = os.environ.get("PUBLIC_HOST", NODE_HOST)
TEST_NAME = "paneltest-delete-me"


def live_peer_count(mgr: AWGManager) -> int:
    out = mgr._dexec("awg show awg0 peers")
    return len([x for x in out.splitlines() if x.strip()])


def conf_peer_count(mgr: AWGManager) -> int:
    out = mgr._read_container_file(mgr.conf_path)
    return out.count("[Peer]")


def main() -> int:
    creds = NodeCredentials(host=NODE_HOST, password=NODE_PW)
    with SSHNode(creds) as node:
        print(f"[ssh] connected to {NODE_HOST}")
        mgr = AWGManager(node)
        mgr.discover_container()
        print(f"[container] {mgr.container}")

        server = mgr.read_server()
        print(f"[server] iface={server.interface} port={server.listen_port} "
              f"subnet={server.subnet_prefix}.0/{server.cidr}")
        print(f"[server] pubkey={server.server_pubkey}")
        print(f"[server] obfuscation lines: {len(server.obfuscation)}")
        for l in server.obfuscation:
            print(f"    {l}")
        print(f"[server] next free host -> {server.subnet_prefix}.{AWGManager.next_free_host(server)}")

        live0, conf0 = live_peer_count(mgr), conf_peer_count(mgr)
        print(f"[before] live peers={live0} conf peers={conf0}")

        peer = None
        try:
            print(f"[create] adding peer {TEST_NAME!r} ...")
            peer = mgr.add_peer(TEST_NAME, PUBLIC_HOST)
            print(f"  pub={peer['public_key']}  address={peer['address']}")
            live1, conf1 = live_peer_count(mgr), conf_peer_count(mgr)
            print(f"[after-add] live peers={live1} conf peers={conf1}")
            print("\n[client .conf]\n" + peer["conf"])
        finally:
            if peer:
                print(f"[delete] removing peer {peer['public_key']} ...")
                mgr.del_peer(peer["public_key"])

        live2, conf2 = live_peer_count(mgr), conf_peer_count(mgr)
        print(f"[after-del] live peers={live2} conf peers={conf2}")
        ok = (live2 == live0 and conf2 == conf0)
        print(f"[verify] restored to original state: {ok}")
        return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
