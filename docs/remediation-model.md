# Remediation Priority Model

The planner keeps technical risk, ownership, and schedule evidence separate so a
reviewer can see why an item received its priority.

## Base windows

| Risk band | Base priority | Target window |
| --- | --- | --- |
| Critical | P0 | 1 day |
| High | P1 | 7 days |
| Moderate | P2 | 30 days |
| Low | P3 | 90 days |

A missing owner raises urgency by one level. An overdue due date raises it by one more
level. Priority is capped at P0. A requested due date may shorten the target, but it
cannot extend the risk-based window.

These are lab policy values, not a claim about an employer's service-level agreement.
The caller supplies both `opened_on` and `as_of`, which keeps tests and historical
reviews deterministic.

## Evidence preserved

Every plan includes the original risk assessment, all four risk factors, and separate
priority factors for risk band, ownership, and due-date state. The planner never changes
the technical risk score. A reviewer can adjust the policy later without losing the
source explanation.

The generated action list begins with ownership or overdue escalation when applicable.
It always requires validation of finding evidence before an asset is changed.
