"""Unit tests for rtosploit.peripherals.svd_parser."""

from __future__ import annotations


from rtosploit.peripherals.svd_parser import parse_svd_string


# ---------------------------------------------------------------------------
# Minimal SVD parsing
# ---------------------------------------------------------------------------

_MINIMAL_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestDevice</name>
  <version>1.0</version>
  <description>A test device</description>
  <addressUnitBits>8</addressUnitBits>
  <width>32</width>
  <cpu><name>CM4</name></cpu>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <baseAddress>0x40002000</baseAddress>
      <description>UART peripheral</description>
      <groupName>UART</groupName>
      <registers>
        <register>
          <name>CR1</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <resetValue>0x00000000</resetValue>
          <access>read-write</access>
          <fields>
            <field>
              <name>EN</name>
              <bitOffset>0</bitOffset>
              <bitWidth>1</bitWidth>
              <access>read-write</access>
              <description>Enable</description>
            </field>
            <field>
              <name>RXNE</name>
              <bitOffset>5</bitOffset>
              <bitWidth>1</bitWidth>
              <access>read-only</access>
            </field>
          </fields>
        </register>
        <register>
          <name>DR</name>
          <addressOffset>0x04</addressOffset>
          <size>16</size>
          <resetValue>0x0000</resetValue>
          <access>read-write</access>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestMinimalParsing:
    def test_device_attributes(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        assert dev.name == "TestDevice"
        assert dev.version == "1.0"
        assert dev.description == "A test device"
        assert dev.cpu_name == "CM4"
        assert dev.address_unit_bits == 8
        assert dev.width == 32

    def test_peripheral_count(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        assert len(dev.peripherals) == 1

    def test_peripheral_attributes(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        assert uart is not None
        assert uart.base_address == 0x40002000
        assert uart.description == "UART peripheral"
        assert uart.group_name == "UART"

    def test_register_count(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        assert len(uart.registers) == 2

    def test_register_attributes(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        cr1 = uart.get_register_by_name("CR1")
        assert cr1 is not None
        assert cr1.offset == 0x00
        assert cr1.size == 32
        assert cr1.reset_value == 0
        assert cr1.access == "read-write"

    def test_register_16bit(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        dr = uart.get_register_by_name("DR")
        assert dr is not None
        assert dr.size == 16

    def test_field_attributes(self):
        dev = parse_svd_string(_MINIMAL_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        cr1 = uart.get_register_by_name("CR1")
        assert len(cr1.fields) == 2

        en = cr1.fields[0]
        assert en.name == "EN"
        assert en.bit_offset == 0
        assert en.bit_width == 1
        assert en.access == "read-write"
        assert en.description == "Enable"

        rxne = cr1.fields[1]
        assert rxne.name == "RXNE"
        assert rxne.access == "read-only"


# ---------------------------------------------------------------------------
# derivedFrom peripheral inheritance
# ---------------------------------------------------------------------------

_DERIVED_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>DerivedTest</name>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <baseAddress>0x40002000</baseAddress>
      <registers>
        <register>
          <name>CR1</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <resetValue>0x0</resetValue>
        </register>
        <register>
          <name>DR</name>
          <addressOffset>0x04</addressOffset>
          <size>32</size>
        </register>
      </registers>
    </peripheral>
    <peripheral derivedFrom="UART0">
      <name>UART1</name>
      <baseAddress>0x40003000</baseAddress>
    </peripheral>
  </peripherals>
</device>
"""


class TestDerivedFrom:
    def test_derived_peripheral_exists(self):
        dev = parse_svd_string(_DERIVED_SVD)
        uart1 = dev.get_peripheral_by_name("UART1")
        assert uart1 is not None

    def test_derived_inherits_registers(self):
        dev = parse_svd_string(_DERIVED_SVD)
        uart1 = dev.get_peripheral_by_name("UART1")
        assert len(uart1.registers) == 2
        assert uart1.get_register_by_name("CR1") is not None
        assert uart1.get_register_by_name("DR") is not None

    def test_derived_has_own_base_address(self):
        dev = parse_svd_string(_DERIVED_SVD)
        uart0 = dev.get_peripheral_by_name("UART0")
        uart1 = dev.get_peripheral_by_name("UART1")
        assert uart0.base_address == 0x40002000
        assert uart1.base_address == 0x40003000

    def test_derived_from_field_set(self):
        dev = parse_svd_string(_DERIVED_SVD)
        uart1 = dev.get_peripheral_by_name("UART1")
        assert uart1.derived_from == "UART0"

    def test_derived_registers_are_independent(self):
        """Modifying derived registers should not affect base."""
        dev = parse_svd_string(_DERIVED_SVD)
        uart0 = dev.get_peripheral_by_name("UART0")
        uart1 = dev.get_peripheral_by_name("UART1")
        # They should be separate objects (deep copy)
        assert uart0.registers[0] is not uart1.registers[0]


# ---------------------------------------------------------------------------
# dim / dimIncrement / dimIndex register arrays
# ---------------------------------------------------------------------------

_DIM_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>DimTest</name>
  <peripherals>
    <peripheral>
      <name>GPIO</name>
      <baseAddress>0x50000000</baseAddress>
      <registers>
        <register>
          <name>PIN%s</name>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <dim>4</dim>
          <dimIncrement>4</dimIncrement>
          <dimIndex>0-3</dimIndex>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestDimArrays:
    def test_dim_expands_registers(self):
        dev = parse_svd_string(_DIM_SVD)
        gpio = dev.get_peripheral_by_name("GPIO")
        assert len(gpio.registers) == 4

    def test_dim_names(self):
        dev = parse_svd_string(_DIM_SVD)
        gpio = dev.get_peripheral_by_name("GPIO")
        names = [r.name for r in gpio.registers]
        assert names == ["PIN0", "PIN1", "PIN2", "PIN3"]

    def test_dim_offsets(self):
        dev = parse_svd_string(_DIM_SVD)
        gpio = dev.get_peripheral_by_name("GPIO")
        offsets = [r.offset for r in gpio.registers]
        assert offsets == [0x00, 0x04, 0x08, 0x0C]


_DIM_COMMA_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>DimCommaTest</name>
  <peripherals>
    <peripheral>
      <name>TIMER</name>
      <baseAddress>0x40000000</baseAddress>
      <registers>
        <register>
          <name>CC%s</name>
          <addressOffset>0x40</addressOffset>
          <size>32</size>
          <dim>3</dim>
          <dimIncrement>4</dimIncrement>
          <dimIndex>A,B,C</dimIndex>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestDimCommaIndex:
    def test_comma_index_names(self):
        dev = parse_svd_string(_DIM_COMMA_SVD)
        timer = dev.get_peripheral_by_name("TIMER")
        names = [r.name for r in timer.registers]
        assert names == ["CCA", "CCB", "CCC"]


# ---------------------------------------------------------------------------
# Interrupt elements
# ---------------------------------------------------------------------------

_INTERRUPT_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>IRQTest</name>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <baseAddress>0x40002000</baseAddress>
      <interrupt>
        <name>UART0_IRQ</name>
        <value>37</value>
      </interrupt>
      <interrupt>
        <name>UART0_ERR</name>
        <value>38</value>
      </interrupt>
      <registers>
        <register>
          <name>CR1</name>
          <addressOffset>0x00</addressOffset>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestInterrupts:
    def test_irq_numbers_parsed(self):
        dev = parse_svd_string(_INTERRUPT_SVD)
        uart = dev.get_peripheral_by_name("UART0")
        assert uart.irq_numbers == [37, 38]


# ---------------------------------------------------------------------------
# Number format handling
# ---------------------------------------------------------------------------

_HEX_DECIMAL_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>NumTest</name>
  <peripherals>
    <peripheral>
      <name>TEST</name>
      <baseAddress>0x40000000</baseAddress>
      <registers>
        <register>
          <name>HEX_REG</name>
          <addressOffset>0x10</addressOffset>
          <resetValue>0xDEAD</resetValue>
        </register>
        <register>
          <name>DEC_REG</name>
          <addressOffset>20</addressOffset>
          <resetValue>255</resetValue>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestNumberFormats:
    def test_hex_values(self):
        dev = parse_svd_string(_HEX_DECIMAL_SVD)
        t = dev.get_peripheral_by_name("TEST")
        r = t.get_register_by_name("HEX_REG")
        assert r.offset == 0x10
        assert r.reset_value == 0xDEAD

    def test_decimal_values(self):
        dev = parse_svd_string(_HEX_DECIMAL_SVD)
        t = dev.get_peripheral_by_name("TEST")
        r = t.get_register_by_name("DEC_REG")
        assert r.offset == 20
        assert r.reset_value == 255


# ---------------------------------------------------------------------------
# Cluster elements
# ---------------------------------------------------------------------------

_CLUSTER_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>ClusterTest</name>
  <peripherals>
    <peripheral>
      <name>DMA</name>
      <baseAddress>0x40026000</baseAddress>
      <registers>
        <cluster>
          <name>CH0</name>
          <addressOffset>0x10</addressOffset>
          <register>
            <name>CR</name>
            <addressOffset>0x00</addressOffset>
            <size>32</size>
          </register>
          <register>
            <name>NDTR</name>
            <addressOffset>0x04</addressOffset>
            <size>32</size>
          </register>
        </cluster>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestClusters:
    def test_cluster_flattened(self):
        dev = parse_svd_string(_CLUSTER_SVD)
        dma = dev.get_peripheral_by_name("DMA")
        assert len(dma.registers) == 2

    def test_cluster_prefixed_names(self):
        dev = parse_svd_string(_CLUSTER_SVD)
        dma = dev.get_peripheral_by_name("DMA")
        names = [r.name for r in dma.registers]
        assert "CH0_CR" in names
        assert "CH0_NDTR" in names

    def test_cluster_offset_added(self):
        dev = parse_svd_string(_CLUSTER_SVD)
        dma = dev.get_peripheral_by_name("DMA")
        cr = dma.get_register_by_name("CH0_CR")
        ndtr = dma.get_register_by_name("CH0_NDTR")
        assert cr.offset == 0x10  # cluster offset + register offset
        assert ndtr.offset == 0x14


# ---------------------------------------------------------------------------
# bitRange format [MSB:LSB]
# ---------------------------------------------------------------------------

_BITRANGE_SVD = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>BitRangeTest</name>
  <peripherals>
    <peripheral>
      <name>PERIPH</name>
      <baseAddress>0x40000000</baseAddress>
      <registers>
        <register>
          <name>REG</name>
          <addressOffset>0x00</addressOffset>
          <fields>
            <field>
              <name>FIELD_A</name>
              <bitRange>[7:4]</bitRange>
            </field>
            <field>
              <name>FIELD_B</name>
              <bitOffset>0</bitOffset>
              <bitWidth>4</bitWidth>
            </field>
          </fields>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>
"""


class TestBitRange:
    def test_bitrange_format(self):
        dev = parse_svd_string(_BITRANGE_SVD)
        periph = dev.get_peripheral_by_name("PERIPH")
        reg = periph.get_register_by_name("REG")
        field_a = reg.fields[0]
        assert field_a.name == "FIELD_A"
        assert field_a.bit_offset == 4
        assert field_a.bit_width == 4

    def test_bitoffset_bitwidth_still_works(self):
        dev = parse_svd_string(_BITRANGE_SVD)
        periph = dev.get_peripheral_by_name("PERIPH")
        reg = periph.get_register_by_name("REG")
        field_b = reg.fields[1]
        assert field_b.bit_offset == 0
        assert field_b.bit_width == 4


# ---------------------------------------------------------------------------
# Empty / edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_peripherals(self):
        xml = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>Empty</name>
  <peripherals/>
</device>
"""
        dev = parse_svd_string(xml)
        assert dev.name == "Empty"
        assert len(dev.peripherals) == 0

    def test_peripheral_no_registers(self):
        xml = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>NoRegs</name>
  <peripherals>
    <peripheral>
      <name>STUB</name>
      <baseAddress>0x40000000</baseAddress>
    </peripheral>
  </peripherals>
</device>
"""
        dev = parse_svd_string(xml)
        stub = dev.get_peripheral_by_name("STUB")
        assert stub is not None
        assert len(stub.registers) == 0

    def test_no_peripherals_element(self):
        xml = """\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>NoPeriph</name>
</device>
"""
        dev = parse_svd_string(xml)
        assert len(dev.peripherals) == 0
