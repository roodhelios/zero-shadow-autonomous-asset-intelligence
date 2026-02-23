from engine.discovery.local_discovery import discover_local_host, discover_docker_containers
from engine.utils.db import upsert_assets

def main():
    assets = []
    assets.append(discover_local_host())
    assets.extend(discover_docker_containers())

    count = upsert_assets(assets)
    print(f"Stored {count} local assets")

if __name__ == "__main__":
    main()