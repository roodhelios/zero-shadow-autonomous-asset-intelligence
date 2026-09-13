"""Validated asset observations collected from authorized fixture sources."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping


class AssetValidationError(ValueError):
    """Raised when an observation cannot be represented without guessing."""


def _required_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AssetValidationError(f"{field_name} must be a non-empty string")
    return value.strip()


def _optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name)


def _hostname(value: Any) -> str | None:
    hostname = _optional_text(value, "hostname")
    if hostname is None:
        return None
    normalized = hostname.rstrip(".").lower()
    if not normalized or " " in normalized or normalized.startswith("."):
        raise AssetValidationError("hostname is not valid")
    return normalized


def _ip_addresses(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise AssetValidationError("ip_addresses must be a list")
    addresses: set[str] = set()
    for item in value:
        try:
            addresses.add(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise AssetValidationError(f"invalid IP address: {item}") from exc
    return tuple(sorted(addresses))


def _tags(value: Any) -> Mapping[str, str]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise AssetValidationError("tags must be an object")
    tags: dict[str, str] = {}
    for key, item in value.items():
        normalized_key = _required_text(key, "tag key").lower()
        tags[normalized_key] = _required_text(item, f"tag {key}")
    return MappingProxyType(dict(sorted(tags.items())))


@dataclass(frozen=True, slots=True)
class AssetObservation:
    """One source's claim about an asset, preserved for later correlation."""

    source: str
    source_record_id: str
    kind: str
    hostname: str | None = None
    ip_addresses: tuple[str, ...] = ()
    cloud_provider: str | None = None
    cloud_account: str | None = None
    cloud_resource_id: str | None = None
    tags: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_dict(cls, source: str, value: Mapping[str, Any]) -> "AssetObservation":
        if not isinstance(value, Mapping):
            raise AssetValidationError("asset must be an object")
        return cls(
            source=_required_text(source, "source").lower(),
            source_record_id=_required_text(
                value.get("source_record_id"), "source_record_id"
            ),
            kind=_required_text(value.get("kind"), "kind").lower(),
            hostname=_hostname(value.get("hostname")),
            ip_addresses=_ip_addresses(value.get("ip_addresses")),
            cloud_provider=(
                _optional_text(value.get("cloud_provider"), "cloud_provider") or None
            ),
            cloud_account=_optional_text(value.get("cloud_account"), "cloud_account"),
            cloud_resource_id=_optional_text(
                value.get("cloud_resource_id"), "cloud_resource_id"
            ),
            tags=_tags(value.get("tags")),
        )

    def identity_keys(self) -> tuple[str, ...]:
        """Return strong keys only. IP addresses are evidence, not identity."""

        keys = {f"source:{self.source}:{self.source_record_id}"}
        if self.hostname and "." in self.hostname:
            keys.add(f"fqdn:{self.hostname}")
        if self.cloud_provider and self.cloud_account and self.cloud_resource_id:
            keys.add(
                "cloud:"
                f"{self.cloud_provider.lower()}:{self.cloud_account}:"
                f"{self.cloud_resource_id}"
            )
        return tuple(sorted(keys))

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "source_record_id": self.source_record_id,
            "kind": self.kind,
            "hostname": self.hostname,
            "ip_addresses": list(self.ip_addresses),
            "cloud_provider": self.cloud_provider,
            "cloud_account": self.cloud_account,
            "cloud_resource_id": self.cloud_resource_id,
            "tags": dict(self.tags),
        }
