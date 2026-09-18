"""Deterministic remediation queues grouped by accountable fixture teams."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from .ownership import OwnershipDirectory, OwnershipResolution
from .remediation import RemediationPlan


@dataclass(frozen=True, slots=True)
class QueueItem:
    plan: RemediationPlan
    ownership: OwnershipResolution

    def to_dict(self) -> dict[str, Any]:
        output = self.plan.to_dict()
        output["ownership_resolution"] = self.ownership.to_dict()
        return output


def _sort_key(item: QueueItem) -> tuple[int, date, str]:
    return (int(item.plan.priority[1]), item.plan.due_date, item.plan.finding_id)


def build_work_queue_document(
    items: Iterable[QueueItem],
    *,
    directory: OwnershipDirectory,
    as_of: date,
) -> dict[str, Any]:
    """Group unique plans by resolved team and preserve unassigned evidence."""

    grouped: dict[str, list[QueueItem]] = {}
    unassigned: list[QueueItem] = []
    finding_ids: set[str] = set()
    for item in items:
        finding_id = item.plan.finding_id
        if finding_id in finding_ids:
            raise ValueError(f"duplicate finding_id: {finding_id}")
        finding_ids.add(finding_id)

        if item.ownership.status == "resolved":
            team_id = item.ownership.team_id
            if team_id is None or team_id not in directory.teams:
                raise ValueError(f"resolved ownership is invalid for {finding_id}")
            if item.plan.owner != team_id:
                raise ValueError(f"plan owner does not match resolution for {finding_id}")
            grouped.setdefault(team_id, []).append(item)
        else:
            if item.plan.owner is not None:
                raise ValueError(f"unresolved plan must not have an owner: {finding_id}")
            unassigned.append(item)

    queues = []
    for team_id in sorted(grouped):
        team = directory.teams[team_id]
        queue_items = sorted(grouped[team_id], key=_sort_key)
        queues.append(
            {
                "team_id": team_id,
                "display_name": team.display_name,
                "item_count": len(queue_items),
                "items": [item.to_dict() for item in queue_items],
            }
        )

    unassigned.sort(key=_sort_key)
    return {
        "schema_version": 1,
        "as_of": as_of.isoformat(),
        "queue_count": len(queues),
        "assigned_item_count": sum(len(items) for items in grouped.values()),
        "unassigned_item_count": len(unassigned),
        "queues": queues,
        "unassigned": [item.to_dict() for item in unassigned],
    }
