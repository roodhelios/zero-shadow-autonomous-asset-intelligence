import json
import psycopg2
from typing import Dict, Iterable
from engine.utils.config import DB

UPSERT = """
INSERT INTO assets (provider, asset_type, asset_id, name, region, public_exposure, tags, metadata, last_seen)
VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb,NOW())
ON CONFLICT (provider, asset_type, asset_id)
DO UPDATE SET
name=EXCLUDED.name,
region=EXCLUDED.region,
public_exposure=EXCLUDED.public_exposure,
tags=EXCLUDED.tags,
metadata=EXCLUDED.metadata,
last_seen=NOW();
"""

def upsert_assets(assets: Iterable[Dict]) -> int:
    conn = psycopg2.connect(
        host=DB["host"],
        port=DB["port"],
        dbname=DB["name"],
        user=DB["user"],
        password=DB["password"],
    )
    cur = conn.cursor()
    count = 0

    for a in assets:
        cur.execute(
            UPSERT,
            (
                a["provider"],
                a["asset_type"],
                a["asset_id"],
                a.get("name"),
                a.get("region"),
                bool(a.get("public_exposure", False)),
                json.dumps(a.get("tags", {})),
                json.dumps(a.get("metadata", {})),
            ),
        )
        count += 1

    conn.commit()
    cur.close()
    conn.close()
    return count