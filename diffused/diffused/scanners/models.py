"""Data classes used by the scanners."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Package:
    name: str
    version: str
