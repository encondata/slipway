"""Types shared by the hypervisor clients, the machine providers and the accounts service.

They live apart from ``machines.py`` and the providers so the Proxmox and ESXi clients (and the
accounts service, which calls only the clients) can use them without importing the providers.

* ``MachineError`` carries Slipway's own sentence for anything a hypervisor, Terraform or a VM got
  wrong. It never carries the upstream text: that may hold a token, a path or a stack trace, and it
  is rarely something a person can act on. The API answers 502 when ``unreachable`` is set (the
  hypervisor couldn't be reached at all) and 409 otherwise.
* ``AccountInvalid`` is a refused account field, answered 422 with ``{detail, field}``.
* ``Check`` is one line of an account's Test (stored in ``provider_accounts.checks``).
* ``Blocker`` is one reason a VM can't be removed yet; ``forgettable`` says whether a retry with
  ``forget_vms`` may get past it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any


class MachineError(RuntimeError):
    """A provider step failed; ``text`` is the sentence the person reads."""

    def __init__(self, text: str, *, unreachable: bool = False) -> None:
        super().__init__(text)
        self.text = text
        self.unreachable = unreachable


class AccountInvalid(ValueError):
    """A provider account (or one of its networks) has a field Slipway refuses."""

    def __init__(self, field: str, text: str) -> None:
        super().__init__(text)
        self.field = field
        self.text = text


# A check's level. "ok" and "note" pass; "warning" passes but the account's status says so;
# "error" fails, and the account can't be used until the next Test passes.
CHECK_LEVELS = ("ok", "note", "warning", "error")


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    level: str
    text: str

    def __post_init__(self) -> None:
        if self.level not in CHECK_LEVELS:
            raise ValueError(f"Unknown check level {self.level!r}")
        if self.ok != (self.level in ("ok", "note")):
            raise ValueError(f"A {self.level} check can't have ok={self.ok}")

    @classmethod
    def passed(cls, name: str, text: str) -> Check:
        return cls(name, True, "ok", text)

    @classmethod
    def note(cls, name: str, text: str) -> Check:
        return cls(name, True, "note", text)

    @classmethod
    def warning(cls, name: str, text: str) -> Check:
        return cls(name, False, "warning", text)

    @classmethod
    def failed(cls, name: str, text: str) -> Check:
        return cls(name, False, "error", text)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> Check:
        return cls(str(value["name"]), bool(value["ok"]), str(value["level"]), str(value["text"]))


def status_of(checks: Iterable[Check]) -> str:
    """The account's ``status`` after a Test: ``error``, ``warning`` or ``ok`` (``unknown`` with no checks)."""
    levels = {check.level for check in checks}
    if not levels:
        return "unknown"
    if "error" in levels:
        return "error"
    if "warning" in levels:
        return "warning"
    return "ok"


@dataclass(frozen=True)
class Blocker:
    text: str
    forgettable: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
