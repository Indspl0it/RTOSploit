"""Scanner module registry — singleton that discovers and stores all scanner modules."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Optional, Type

from rtosploit.scanners.base import ScannerModule

logger = logging.getLogger(__name__)


class ScannerRegistry:
    """Singleton registry for vulnerability scanner modules.

    Discovers modules by scanning the scanners/ subdirectory tree and
    registering any ScannerModule subclasses found.
    """

    _instance: Optional["ScannerRegistry"] = None

    def __init__(self):
        self._modules: dict[str, Type[ScannerModule]] = {}
        self._load_errors: dict[str, str] = {}

    @classmethod
    def instance(cls) -> "ScannerRegistry":
        if cls._instance is None:
            cls._instance = cls()
            cls._instance.discover()
        return cls._instance

    def register(self, module_class: Type[ScannerModule]) -> None:
        """Register a scanner module class."""
        path = f"{module_class.rtos}/{module_class.name}" if module_class.rtos else module_class.name
        self._modules[path] = module_class
        logger.debug(f"Registered scanner: {path}")

    def get(self, module_path: str) -> Optional[Type[ScannerModule]]:
        """Look up module by path like 'freertos/heap_overflow'."""
        return self._modules.get(module_path)

    def list_all(self) -> list[tuple]:
        """Return list of (path, name, rtos, category, reliability) tuples."""
        result = []
        for path, cls in sorted(self._modules.items()):
            result.append((path, cls.name, cls.rtos, cls.category, cls.reliability))
        return result

    def search(self, term: str) -> list[tuple]:
        """Search modules by term (name, description, CVE, category, rtos)."""
        term_lower = term.lower()
        results = []
        for path, cls in self._modules.items():
            searchable = " ".join([
                cls.name,
                cls.description,
                cls.rtos,
                cls.category,
                cls.reliability,
                cls.cve or "",
                " ".join(cls.references),
            ]).lower()
            if term_lower in searchable:
                results.append((path, cls.name, cls.rtos, cls.category, cls.reliability))
        return results

    def discover(self) -> int:
        """Auto-discover scanner modules in rtosploit/scanners/ subdirectories."""
        import rtosploit.scanners as scanners_pkg
        scanners_dir = Path(scanners_pkg.__file__).parent
        count = 0
        for subdir in ["freertos", "threadx", "zephyr", "rtems"]:
            subdir_path = scanners_dir / subdir
            if not subdir_path.exists():
                continue
            for py_file in subdir_path.glob("*.py"):
                if py_file.stem == "__init__":
                    continue
                module_name = f"rtosploit.scanners.{subdir}.{py_file.stem}"
                try:
                    mod = importlib.import_module(module_name)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (isinstance(attr, type) and
                                issubclass(attr, ScannerModule) and
                                attr is not ScannerModule and
                                attr.name):
                            self.register(attr)
                            count += 1
                except Exception as e:
                    self._load_errors[module_name] = str(e)
                    logger.warning(f"Failed to load scanner module {module_name}: {e}")
        return count

    def get_modules_for_cve(self, cve_id: str) -> list[tuple]:
        """Find scanner modules that target a specific CVE.

        Returns a list of ``(path, name, rtos, category)`` tuples for every
        registered module whose ``cve`` attribute matches *cve_id*
        (case-insensitive).
        """
        results = []
        for path, cls in self._modules.items():
            if cls.cve and cls.cve.upper() == cve_id.upper():
                results.append((path, cls.name, cls.rtos, cls.category))
        return results

    @property
    def load_errors(self) -> dict[str, str]:
        """Return any errors encountered during module discovery."""
        return dict(self._load_errors)


def get_registry() -> ScannerRegistry:
    """Return the global ScannerRegistry singleton."""
    return ScannerRegistry.instance()
