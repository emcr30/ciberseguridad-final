"""Alert record and de-duplication (RF12)."""
from __future__ import annotations

from dataclasses import dataclass

DEDUP_SECONDS = 60
SEVERITY_HIGH = "alta"
SEVERITY_CRITICAL = "crítica"


@dataclass
class Alert:
    ts: float          # packet timestamp
    type: str          # ARP_SPOOFING, MITM, ...
    severity: str
    subject: str       # what the alert is about (IP or MAC); used to de-duplicate
    detail: str


class Deduplicator:
    """Drops an alert if the same type+subject was raised less than 60 s before (packet time)."""

    def __init__(self, seconds: float = DEDUP_SECONDS):
        self.seconds = seconds
        self._last: dict[tuple[str, str], float] = {}

    def allow(self, alert: Alert) -> bool:
        key = (alert.type, alert.subject)
        last = self._last.get(key)
        if last is not None and alert.ts - last < self.seconds:
            return False
        self._last[key] = alert.ts
        return True
