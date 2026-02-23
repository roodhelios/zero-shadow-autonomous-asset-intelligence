import json
import socket
import subprocess
from typing import Dict, List

def _run(cmd: List[str]) -> str:
    return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL).strip()

def discover_local_host() -> Dict:
    hostname = socket.gethostname()
    return {
        "provider": "local",
        "asset_type": "host",
        "asset_id": hostname,
        "name": hostname,
        "region": "local",
        "public_exposure": False,
        "tags": {"owner": "unknown"},
        "metadata": {
            "os": _run(["cmd", "/c", "ver"]),
        },
    }

def discover_docker_containers() -> List[Dict]:
    try:
        out = _run(["docker", "ps", "--format", "{{.ID}} {{.Image}} {{.Names}} {{.Status}}"])
    except Exception:
        return []

    assets = []
    if not out:
        return assets

    for line in out.splitlines():
        cid, image, name, *status = line.split()
        assets.append({
            "provider": "docker",
            "asset_type": "container",
            "asset_id": cid,
            "name": name,
            "region": "local",
            "public_exposure": False,
            "tags": {"owner": "unknown"},
            "metadata": {"image": image, "status": " ".join(status)},
        })
    return assets