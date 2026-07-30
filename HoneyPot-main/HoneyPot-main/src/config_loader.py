"""Loads and validates config/config.yaml into a typed, dot-accessible object."""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List

import yaml


class ConfigDict(dict):
    """A dict that also supports attribute access, recursively."""

    def __getattr__(self, item: str) -> Any:
        try:
            value = self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc
        if isinstance(value, dict) and not isinstance(value, ConfigDict):
            value = ConfigDict(value)
            self[item] = value
        return value


@dataclass
class HoneypotConfig:
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str = "config/config.yaml") -> "HoneypotConfig":
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        return cls(raw=data)

    def __getattr__(self, item: str) -> Any:
        try:
            value = self.raw[item]
        except KeyError as exc:
            raise AttributeError(item) from exc
        if isinstance(value, dict):
            return ConfigDict(value)
        return value

    def fake_users(self) -> List[Dict[str, Any]]:
        return copy.deepcopy(self.raw["identity"]["fake_users"])
