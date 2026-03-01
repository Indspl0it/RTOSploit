"""Crash triage pipeline — classify and optionally minimize crash inputs."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rtosploit.triage.classifier import ExploitabilityClassifier, TriageResult
from rtosploit.triage.minimizer import CrashMinimizer

logger = logging.getLogger(__name__)


@dataclass
class TriagedCrash:
    """A single crash after triage (classification + optional minimization)."""

    crash_id: str
    original_input: str  # path
    minimized_input: Optional[str]  # path if minimized
    triage_result: TriageResult
    original_size: int
    minimized_size: Optional[int]
    crash_data: dict


class TriagePipeline:
    """Load crash JSONs, classify exploitability, and optionally minimize inputs."""

    def __init__(
        self,
        firmware_path: str,
        machine: str = "mps2-an385",
        minimize: bool = True,
    ) -> None:
        self.firmware_path = firmware_path
        self.machine = machine
        self.do_minimize = minimize
        self.classifier = ExploitabilityClassifier()
        self.minimizer = CrashMinimizer(
            firmware_path=firmware_path,
            machine=machine,
        )

    def run(self, crash_dir: str) -> list[TriagedCrash]:
        """Process all crash JSON files in *crash_dir*.

        Each JSON file is expected to follow the Rust CrashReport schema with
        fields like crash_id, fault_type, registers, fault_address, etc.

        Returns a list of TriagedCrash results sorted by exploitability
        (most exploitable first).
        """
        crash_path = Path(crash_dir)
        json_files = sorted(crash_path.glob("*.json"))

        if not json_files:
            logger.warning("No JSON crash files found in %s", crash_dir)
            return []

        results: list[TriagedCrash] = []

        for jf in json_files:
            try:
                with open(jf) as fh:
                    crash_data = json.load(fh)
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Skipping %s: %s", jf.name, exc)
                continue

            triaged = self._process_crash(crash_data, jf)
            if triaged is not None:
                results.append(triaged)

        # Sort: EXPLOITABLE first, UNKNOWN last
        _ORDER = {
            "exploitable": 0,
            "probably_exploitable": 1,
            "unknown": 2,
            "probably_not_exploitable": 3,
        }
        results.sort(
            key=lambda t: _ORDER.get(t.triage_result.exploitability.value, 99)
        )

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _process_crash(
        self, crash_data: dict, json_path: Path
    ) -> Optional[TriagedCrash]:
        """Classify and optionally minimize a single crash."""
        crash_id = crash_data.get("crash_id", json_path.stem)

        # Normalise Rust CrashReport fields to classifier expectations
        classifier_input = self._normalise(crash_data)
        triage_result = self.classifier.classify(classifier_input)

        # Resolve the input file path (relative to the JSON file)
        input_file = crash_data.get("input_file", "")
        if input_file and not os.path.isabs(input_file):
            input_file = str(json_path.parent / input_file)

        original_size = crash_data.get("input_size", 0)
        minimized_input: Optional[str] = None
        minimized_size: Optional[int] = None

        if self.do_minimize and input_file and os.path.isfile(input_file):
            min_path = input_file + ".min"
            try:
                saved = self.minimizer.minimize_file(input_file, min_path)
                minimized_input = min_path
                minimized_size = original_size - saved
            except Exception as exc:
                logger.warning(
                    "Minimization failed for %s: %s", crash_id, exc
                )

        return TriagedCrash(
            crash_id=crash_id,
            original_input=input_file,
            minimized_input=minimized_input,
            triage_result=triage_result,
            original_size=original_size,
            minimized_size=minimized_size,
            crash_data=crash_data,
        )

    @staticmethod
    def _normalise(crash_data: dict) -> dict:
        """Map Rust CrashReport fields to the classifier's expected schema."""
        registers = crash_data.get("registers", {})

        # The Rust side uses 'fault_type' as a string; classifier wants 'crash_type'
        crash_type = crash_data.get("fault_type", crash_data.get("crash_type", "unknown"))

        # CFSR may be stored in registers or as a top-level field
        cfsr = crash_data.get("cfsr", registers.get("cfsr", 0))

        pc = crash_data.get("pc", registers.get("pc", registers.get("r15", 0)))
        fault_address = crash_data.get("fault_address", 0)

        return {
            "crash_type": crash_type,
            "cfsr": cfsr,
            "pc": pc,
            "fault_address": fault_address,
            "registers": registers,
            "stack_trace": crash_data.get("backtrace", []),
            "pre_crash_events": crash_data.get("pre_crash_events", []),
        }
