"""SVD XML parser — converts CMSIS-SVD files into SVDDevice data model.

Handles:
- Standard peripheral/register/field extraction
- derivedFrom peripheral inheritance (clone registers from base)
- <dim>, <dimIncrement>, <dimIndex> register arrays
- <interrupt> elements for IRQ numbers
- Hex (0x), decimal, and binary (#) number formats
- <cluster> elements (flattened into registers with cluster prefix)
- <bitRange> format [MSB:LSB] as alternative to bitOffset/bitWidth
"""

from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from rtosploit.peripherals.svd_model import (
    SVDDevice,
    SVDField,
    SVDPeripheral,
    SVDRegister,
)


def parse_svd(path: Path) -> SVDDevice:
    """Parse an SVD XML file into an SVDDevice."""
    tree = ET.parse(path)
    return _parse_root(tree.getroot())


def parse_svd_string(xml_content: str) -> SVDDevice:
    """Parse SVD XML from a string (for testing)."""
    root = ET.fromstring(xml_content)
    return _parse_root(root)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_root(root: ET.Element) -> SVDDevice:
    """Parse the root <device> element."""
    device = SVDDevice(
        name=_text(root, "name", "unknown"),
        version=_text(root, "version", ""),
        description=_text(root, "description", ""),
        cpu_name=_text(root, "cpu/name", ""),
        address_unit_bits=_int_text(root, "addressUnitBits", 8),
        width=_int_text(root, "width", 32),
    )

    # First pass: parse all peripherals (some may have derivedFrom)
    periph_map: dict[str, SVDPeripheral] = {}
    deferred: list[tuple[ET.Element, str]] = []  # (element, derived_from_name)

    peripherals_el = root.find("peripherals")
    if peripherals_el is None:
        return device

    for periph_el in peripherals_el.findall("peripheral"):
        derived_from = periph_el.get("derivedFrom")
        if derived_from and derived_from not in periph_map:
            deferred.append((periph_el, derived_from))
        else:
            p = _parse_peripheral(periph_el, periph_map)
            periph_map[p.name] = p

    # Second pass: resolve deferred derivedFrom
    for periph_el, derived_from in deferred:
        p = _parse_peripheral(periph_el, periph_map)
        periph_map[p.name] = p

    device.peripherals = list(periph_map.values())
    return device


def _parse_peripheral(
    el: ET.Element,
    periph_map: dict[str, SVDPeripheral],
) -> SVDPeripheral:
    """Parse a single <peripheral> element."""
    derived_from = el.get("derivedFrom")
    name = _text(el, "name", "?")

    # Start with derived base if applicable
    if derived_from and derived_from in periph_map:
        base = periph_map[derived_from]
        periph = SVDPeripheral(
            name=name,
            base_address=_int_text(el, "baseAddress", base.base_address),
            description=_text(el, "description", base.description),
            registers=copy.deepcopy(base.registers),
            group_name=_text(el, "groupName", base.group_name),
            irq_numbers=list(base.irq_numbers),
            derived_from=derived_from,
        )
    else:
        periph = SVDPeripheral(
            name=name,
            base_address=_int_text(el, "baseAddress", 0),
            description=_text(el, "description", ""),
            group_name=_text(el, "groupName", ""),
        )

    # Parse registers (override derived ones if present)
    registers_el = el.find("registers")
    if registers_el is not None:
        periph.registers = _parse_registers(registers_el, prefix="")

    # Parse interrupts
    for irq_el in el.findall("interrupt"):
        value = _int_text(irq_el, "value", None)
        if value is not None:
            periph.irq_numbers.append(value)

    return periph


def _parse_registers(
    container: ET.Element,
    prefix: str,
) -> list[SVDRegister]:
    """Parse <register> and <cluster> elements from a container."""
    registers: list[SVDRegister] = []

    for child in container:
        tag = _strip_ns(child.tag)

        if tag == "register":
            registers.extend(_parse_register(child, prefix))

        elif tag == "cluster":
            cluster_name = _text(child, "name", "")
            cluster_offset = _int_text(child, "addressOffset", 0)
            cluster_prefix = f"{prefix}{cluster_name}_" if cluster_name else prefix

            # Handle dim expansion on clusters
            dim = _int_text(child, "dim", None)
            if dim is not None:
                dim_increment = _int_text(child, "dimIncrement", 0)
                dim_index = _parse_dim_index(child, dim)
                for i, idx in enumerate(dim_index):
                    expanded_prefix = cluster_prefix.replace("%s", idx)
                    sub_offset = cluster_offset + i * dim_increment
                    sub_regs = _parse_registers(child, expanded_prefix)
                    for r in sub_regs:
                        r.offset += sub_offset
                    registers.extend(sub_regs)
            else:
                sub_regs = _parse_registers(child, cluster_prefix)
                for r in sub_regs:
                    r.offset += cluster_offset
                registers.extend(sub_regs)

    return registers


def _parse_register(
    el: ET.Element,
    prefix: str,
) -> list[SVDRegister]:
    """Parse a single <register>, expanding dim arrays if present."""
    raw_name = _text(el, "name", "?")
    offset = _int_text(el, "addressOffset", 0)
    size = _int_text(el, "size", 32)
    reset_value = _int_text(el, "resetValue", 0)
    access = _text(el, "access", "read-write")
    description = _text(el, "description", "")

    fields = _parse_fields(el)

    dim = _int_text(el, "dim", None)
    if dim is not None:
        dim_increment = _int_text(el, "dimIncrement", 0)
        dim_index = _parse_dim_index(el, dim)
        result = []
        for i, idx in enumerate(dim_index):
            reg_name = f"{prefix}{raw_name}".replace("%s", idx)
            result.append(SVDRegister(
                name=reg_name,
                offset=offset + i * dim_increment,
                size=size,
                reset_value=reset_value,
                access=access,
                fields=copy.deepcopy(fields),
                description=description,
            ))
        return result

    return [SVDRegister(
        name=f"{prefix}{raw_name}",
        offset=offset,
        size=size,
        reset_value=reset_value,
        access=access,
        fields=fields,
        description=description,
    )]


def _parse_fields(register_el: ET.Element) -> list[SVDField]:
    """Parse <field> elements from a register."""
    fields_el = register_el.find("fields")
    if fields_el is None:
        return []

    result: list[SVDField] = []
    for field_el in fields_el.findall("field"):
        name = _text(field_el, "name", "?")
        access = _text(field_el, "access", "read-write")
        description = _text(field_el, "description", "")

        # Try bitRange [MSB:LSB] format first
        bit_range = _text(field_el, "bitRange", "")
        if bit_range:
            m = re.match(r"\[(\d+):(\d+)\]", bit_range)
            if m:
                msb = int(m.group(1))
                lsb = int(m.group(2))
                bit_offset = lsb
                bit_width = msb - lsb + 1
            else:
                bit_offset = 0
                bit_width = 1
        else:
            bit_offset = _int_text(field_el, "bitOffset", 0)
            bit_width = _int_text(field_el, "bitWidth", 1)

        result.append(SVDField(
            name=name,
            bit_offset=bit_offset,
            bit_width=bit_width,
            access=access,
            description=description,
        ))

    return result


def _parse_dim_index(el: ET.Element, dim: int) -> list[str]:
    """Parse <dimIndex> or generate default 0..dim-1 index list."""
    dim_index_text = _text(el, "dimIndex", "")
    if dim_index_text:
        # Could be "0-3" range or "A,B,C,D" list
        if "," in dim_index_text:
            return dim_index_text.split(",")
        m = re.match(r"(\d+)-(\d+)", dim_index_text)
        if m:
            start, end = int(m.group(1)), int(m.group(2))
            return [str(i) for i in range(start, end + 1)]
    return [str(i) for i in range(dim)]


# ---------------------------------------------------------------------------
# XML text helpers
# ---------------------------------------------------------------------------

def _strip_ns(tag: str) -> str:
    """Strip XML namespace prefix from a tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _text(el: ET.Element, path: str, default: str = "") -> str:
    """Get text content of a child element."""
    child = el.find(path)
    if child is not None and child.text:
        return child.text.strip()
    return default


def _int_text(
    el: ET.Element,
    path: str,
    default: Optional[int] = 0,
) -> Optional[int]:
    """Get integer text of a child element, handling hex/decimal/binary."""
    text = _text(el, path, "")
    if not text:
        return default
    return _parse_int(text)


def _parse_int(text: str) -> int:
    """Parse an integer from SVD text (hex 0x, binary #, or decimal)."""
    text = text.strip()
    if text.startswith("0x") or text.startswith("0X"):
        return int(text, 16)
    if text.startswith("#"):
        # Binary format used in some SVDs
        return int(text[1:], 2)
    return int(text, 0)
