"""Deterministically correlate observations using strong identity keys."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable

from engine.models import AssetObservation


@dataclass(frozen=True, slots=True)
class ConsolidatedAsset:
    asset_id: str
    kinds: tuple[str, ...]
    hostnames: tuple[str, ...]
    ip_addresses: tuple[str, ...]
    sources: tuple[str, ...]
    correlation_keys: tuple[str, ...]
    observations: tuple[AssetObservation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "kinds": list(self.kinds),
            "hostnames": list(self.hostnames),
            "ip_addresses": list(self.ip_addresses),
            "sources": list(self.sources),
            "correlation_keys": list(self.correlation_keys),
            "observations": [item.to_dict() for item in self.observations],
        }


def _asset_id(keys: tuple[str, ...]) -> str:
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return f"asset-{digest[:16]}"


def _consolidate(observations: list[AssetObservation]) -> ConsolidatedAsset:
    ordered = tuple(sorted(observations, key=lambda item: (item.source, item.source_record_id)))
    keys = tuple(sorted({key for item in ordered for key in item.identity_keys()}))
    return ConsolidatedAsset(
        asset_id=_asset_id(keys),
        kinds=tuple(sorted({item.kind for item in ordered})),
        hostnames=tuple(sorted({item.hostname for item in ordered if item.hostname})),
        ip_addresses=tuple(
            sorted({address for item in ordered for address in item.ip_addresses})
        ),
        sources=tuple(sorted({item.source for item in ordered})),
        correlation_keys=keys,
        observations=ordered,
    )


def correlate_assets(
    observations: Iterable[AssetObservation],
) -> tuple[ConsolidatedAsset, ...]:
    """Merge observations that share an explicit strong identity key."""

    items = list(observations)
    parents = list(range(len(items)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parents[max(left_root, right_root)] = min(left_root, right_root)

    owner_by_key: dict[str, int] = {}
    for index, observation in enumerate(items):
        for key in observation.identity_keys():
            if key in owner_by_key:
                union(index, owner_by_key[key])
            else:
                owner_by_key[key] = index

    groups: dict[int, list[AssetObservation]] = {}
    for index, observation in enumerate(items):
        groups.setdefault(find(index), []).append(observation)

    assets = [_consolidate(group) for group in groups.values()]
    return tuple(sorted(assets, key=lambda item: item.asset_id))
