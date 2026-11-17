"""The VM providers the machines core drives (phase 5 §6.1): Proxmox and ESXi.

Each provider lives in its own module (``providers/proxmox.py``, ``providers/esxi.py``) and is imported only when
it is first asked for, so Slipway runs without pyvmomi (ESXi support is an optional extra) and without a
provider that isn't built yet. ``provider_for(kind)`` gives the one instance of each; ``PROVIDERS`` holds the
ones made so far (tests put a stand-in there).

This package doesn't import the machines core: the providers import it, and the core imports this package.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from slipway.services.vmtypes import MachineError

if TYPE_CHECKING:
    from slipway.services.machines import MachineProvider

# What each kind resolves to, and the name a person reads.
PATHS = {
    "proxmox": ("slipway.services.providers.proxmox", "ProxmoxProvider"),
    "esxi": ("slipway.services.providers.esxi", "EsxiProvider"),
}
LABELS = {"proxmox": "Proxmox", "esxi": "ESXi"}
ESXI_MISSING = "Slipway was installed without ESXi support (the pyvmomi package)"

# The providers made so far, by kind. ``provider_for`` fills it; tests may put a stand-in in it.
PROVIDERS: dict[str, MachineProvider] = {}


def label(kind: str) -> str:
    """``Proxmox`` or ``ESXi`` (the kind itself for anything else)."""
    return LABELS.get(kind, kind)


def provider_for(kind: str) -> MachineProvider:
    """The provider for ``kind`` (``proxmox`` or ``esxi``), made on first use.

    Raises ``MachineError`` for another kind, for a provider this Slipway doesn't have yet, and for ESXi when
    pyvmomi isn't installed.
    """
    if kind in PROVIDERS:
        return PROVIDERS[kind]
    if kind not in PATHS:
        raise MachineError(f"{kind!r} isn't a VM provider: Slipway makes VMs on Proxmox and ESXi")
    module_name, class_name = PATHS[kind]
    try:
        module: Any = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name == module_name:
            raise MachineError(f"This Slipway has no {label(kind)} provider yet") from None
        if exc.name and exc.name.split(".")[0].lower() == "pyvmomi":
            raise MachineError(ESXI_MISSING) from None
        raise
    provider = getattr(module, class_name, None)
    if provider is None:
        raise MachineError(f"This Slipway has no {label(kind)} provider yet")
    PROVIDERS[kind] = provider()
    return PROVIDERS[kind]
