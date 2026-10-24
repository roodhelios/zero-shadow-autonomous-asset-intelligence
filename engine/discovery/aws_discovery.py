"""Import a supplied EC2 describe-instances JSON export without contacting AWS."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

from engine.correlation import correlate_assets
from engine.discovery.fixture_discovery import ALLOWED_SCOPES
from engine.discovery.osquery_collector import MAX_INPUT_BYTES, _publish, _read, _unique_fields
from engine.models import AssetObservation

SOURCE = "aws-ec2-export"
MAX_INSTANCES = 10000
REVIEW_TAGS = {"environment", "owner_group", "service"}


def convert_export(data, *, scope, account, region):
    if scope not in ALLOWED_SCOPES:
        raise ValueError("explicit authorized scope required")
    if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
        raise ValueError("expected an explicit 12-digit account")
    if not isinstance(region, str) or not re.fullmatch(r"(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[1-9][0-9]*", region):
        raise ValueError("only explicitly supplied commercial AWS region names are supported")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("EC2 input exceeds 4 MiB")
    document = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_fields)
    json.dumps(document, allow_nan=False)
    if not isinstance(document, dict) or "Reservations" not in document:
        raise ValueError("expected a describe-instances object")
    if document.get("NextToken") not in (None, ""):
        raise ValueError("export contains an unfinished pagination token")
    reservations = document["Reservations"]
    if not isinstance(reservations, list) or len(reservations) > MAX_INSTANCES:
        raise ValueError("invalid reservation collection")
    assets, references, seen = [], [], set()
    for reservation_index, reservation in enumerate(reservations, 1):
        if not isinstance(reservation, dict) or reservation.get("OwnerId") != account:
            raise ValueError("reservation owner differs from the explicitly supplied account")
        instances = reservation.get("Instances")
        if not isinstance(instances, list):
            raise ValueError("expected an instance collection")
        for instance_index, instance in enumerate(instances, 1):
            if len(assets) >= MAX_INSTANCES or not isinstance(instance, dict):
                raise ValueError("invalid or oversized instance collection")
            identifier = instance.get("InstanceId")
            if not isinstance(identifier, str) or not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", identifier):
                raise ValueError("expected a literal EC2 instance identifier")
            arn = "arn:aws:ec2:" + region + ":" + account + ":instance/" + identifier
            if arn in seen:
                raise ValueError("duplicate instance in supplied account and region")
            seen.add(arn)
            addresses = set()
            for field in ("PrivateIpAddress", "PublicIpAddress"):
                value = instance.get(field)
                if value is None:
                    continue
                if not isinstance(value, str) or "%" in value:
                    raise ValueError("expected a literal IPv4 address")
                addresses.add(str(ipaddress.IPv4Address(value)))
            raw_tags = instance.get("Tags", [])
            if not isinstance(raw_tags, list) or len(raw_tags) > 100:
                raise ValueError("expected at most 100 tag records")
            tags, tag_keys = {}, set()
            for tag in raw_tags:
                if not isinstance(tag, dict) or set(tag) != {"Key", "Value"}:
                    raise ValueError("expected tag key/value pairs")
                key, value = tag["Key"], tag["Value"]
                if not isinstance(key, str) or not isinstance(value, str) or key in tag_keys:
                    raise ValueError("duplicate or invalid tag")
                tag_keys.add(key)
                if key in REVIEW_TAGS:
                    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", value):
                        raise ValueError("review tag must use a bounded technical label")
                    tags[key] = value
            asset = {"source_record_id": arn, "kind": "server", "cloud_provider": "aws",
                     "cloud_account": account, "cloud_resource_id": arn,
                     "hostname": None, "ip_addresses": sorted(addresses), "tags": tags}
            AssetObservation.from_dict(SOURCE, asset)
            assets.append(asset)
            references.append({"source_record_id": arn, "reservation_record": reservation_index,
                               "instance_record": instance_index})
    return {"schema_version": 1, "source": SOURCE, "scope": scope,
            "assets": sorted(assets, key=lambda item: item["source_record_id"]),
            "import_metadata": {"input_sha256": hashlib.sha256(data).hexdigest(),
                "account": account, "region": region, "source_records": references,
                "interpretation": "Selected saved-export claims only. Account/scope/region are supplied; "
                "no authentication, full coverage, current state or effective exposure is established. "
                "DNS names and unselected tags are omitted. No AWS call occurs."}}


def inventory(document):
    observations = [AssetObservation.from_dict(SOURCE, item) for item in document["assets"]]
    assets = correlate_assets(observations)
    return {"schema_version": 1, "report_type": "saved-ec2-inventory", "scope": document["scope"],
            "observation_count": len(observations), "asset_count": len(assets),
            "assets": [item.to_dict() for item in assets], "import_metadata": document["import_metadata"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("export", type=Path)
    parser.add_argument("--scope", required=True, choices=sorted(ALLOWED_SCOPES))
    parser.add_argument("--account", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--format", choices=("fixture", "inventory"), default="fixture")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("bounded private file handling requires POSIX")
        result = convert_export(_read(args.export), scope=args.scope, account=args.account, region=args.region)
        if args.format == "inventory":
            result = inventory(result)
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            _publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: EC2 export was not imported; check saved input, scope, account, region and output",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
