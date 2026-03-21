//! ARM CMSIS SVD XML parser.
//!
//! Parses SVD files into Rust structs representing peripherals and registers.

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use std::collections::HashMap;
use std::path::Path;

/// Access type for a register or field.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    ReadOnly,
    WriteOnly,
    #[default]
    ReadWrite,
    WriteOnce,
    ReadWriteOnce,
}

impl Access {
    pub fn parse(s: &str) -> Self {
        match s.trim() {
            "read-only" => Access::ReadOnly,
            "write-only" => Access::WriteOnly,
            "read-write" => Access::ReadWrite,
            "writeOnce" => Access::WriteOnce,
            "read-writeOnce" => Access::ReadWriteOnce,
            _ => Access::ReadWrite,
        }
    }

    pub fn readable(&self) -> bool {
        matches!(
            self,
            Access::ReadOnly | Access::ReadWrite | Access::ReadWriteOnce
        )
    }

    pub fn writable(&self) -> bool {
        matches!(
            self,
            Access::WriteOnly | Access::ReadWrite | Access::WriteOnce | Access::ReadWriteOnce
        )
    }
}

/// A single bit-field within a register.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Field {
    pub name: String,
    pub description: String,
    pub bit_offset: u32,
    pub bit_width: u32,
    pub access: Option<Access>,
}

impl Field {
    pub fn bit_mask(&self) -> u64 {
        ((1u64 << self.bit_width) - 1) << self.bit_offset
    }
}

/// A memory-mapped register within a peripheral.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Register {
    pub name: String,
    pub description: String,
    pub address_offset: u64,
    /// Width in bits (typically 32).
    pub size: u32,
    pub reset_value: u64,
    pub access: Access,
    pub fields: Vec<Field>,
}

impl Register {
    /// Byte size of this register (size / 8).
    pub fn byte_size(&self) -> u64 {
        (self.size as u64).div_ceil(8)
    }
}

/// A peripheral (UART, GPIO, SPI, etc.) with its registers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Peripheral {
    pub name: String,
    pub description: String,
    pub base_address: u64,
    /// Byte span of the peripheral's register map.
    pub size: u64,
    pub registers: Vec<Register>,
    /// Name of peripheral this was derived from, if any.
    pub derived_from: Option<String>,
    /// Priority for stub generation (lower = higher priority).
    pub priority: u32,
}

impl Peripheral {
    /// Compute peripheral byte size from register map.
    fn compute_size(registers: &[Register]) -> u64 {
        registers
            .iter()
            .map(|r| r.address_offset + r.byte_size())
            .max()
            .unwrap_or(0x400) // Default 1KB if no registers
    }
}

/// Top-level SVD device descriptor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Device {
    pub name: String,
    pub version: String,
    pub description: String,
    pub peripherals: Vec<Peripheral>,
}

// ─── Parser ──────────────────────────────────────────────────────────────────

/// Parse a SVD XML file into a [Device].
pub fn parse_svd(path: &Path) -> Result<Device> {
    let xml = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read SVD file: {}", path.display()))?;
    parse_svd_str(&xml)
}

/// Parse SVD XML from a string.
pub fn parse_svd_str(xml: &str) -> Result<Device> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut device = Device {
        name: String::new(),
        version: String::new(),
        description: String::new(),
        peripherals: Vec::new(),
    };

    let mut buf = Vec::new();
    // State machine: track whether we are inside <device> but not inside <peripherals>
    let mut in_device = false;
    let mut in_peripherals = false;
    // Track the current device-level field tag we are reading text for
    let mut current_device_field: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Eof => break,
            Event::Start(e) => {
                let tag_str = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();

                match tag_str.as_str() {
                    "device" => {
                        in_device = true;
                    }
                    "peripherals" if in_device => {
                        in_peripherals = true;
                    }
                    "peripheral" if in_peripherals => {
                        // Check for derivedFrom attribute
                        let mut derived_from: Option<String> = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"derivedFrom" {
                                derived_from =
                                    Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                        let periph = parse_peripheral(&mut reader, derived_from)?;
                        device.peripherals.push(periph);
                        buf.clear();
                        continue;
                    }
                    "name" | "version" | "description" if in_device && !in_peripherals => {
                        current_device_field = Some(tag_str);
                    }
                    _ => {}
                }
            }
            Event::End(e) => {
                let name_bytes = e.name();
                let tag_str = std::str::from_utf8(name_bytes.as_ref()).unwrap_or("");
                match tag_str {
                    "peripherals" => {
                        in_peripherals = false;
                    }
                    "device" => {
                        in_device = false;
                    }
                    "name" | "version" | "description" => {
                        current_device_field = None;
                    }
                    _ => {}
                }
            }
            Event::Text(e) => {
                if let Some(ref field) = current_device_field {
                    let text = e.unescape().unwrap_or_default().into_owned();
                    match field.as_str() {
                        "name" => device.name = text,
                        "version" => device.version = text,
                        "description" => device.description = text,
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }

    // Resolve derivedFrom
    resolve_derived_from(&mut device)?;

    // Compute peripheral sizes
    for p in &mut device.peripherals {
        if p.size == 0 {
            p.size = Peripheral::compute_size(&p.registers);
            if p.size == 0 {
                p.size = 0x400; // fallback 1KB
            }
        }
    }

    Ok(device)
}

fn read_text(reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>) -> Result<String> {
    match reader.read_event_into(buf)? {
        Event::Text(e) => Ok(e.unescape()?.into_owned()),
        Event::CData(e) => Ok(String::from_utf8_lossy(&e).to_string()),
        _ => Ok(String::new()),
    }
}

fn skip_element(reader: &mut Reader<&[u8]>, buf: &mut Vec<u8>, tag: &[u8]) -> Result<()> {
    let mut depth = 1u32;
    loop {
        match reader.read_event_into(buf)? {
            Event::Start(e) if e.name().as_ref() == tag => depth += 1,
            Event::End(e) if e.name().as_ref() == tag => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            Event::End(_) if depth == 1 => return Ok(()),
            Event::Eof => return Ok(()),
            _ => {}
        }
        buf.clear();
    }
}

fn parse_peripheral(
    reader: &mut Reader<&[u8]>,
    derived_from: Option<String>,
) -> Result<Peripheral> {
    let mut name = String::new();
    let mut description = String::new();
    let mut base_address: u64 = 0;
    let mut registers: Vec<Register> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();
                match tag.as_str() {
                    "name" => name = read_text(reader, &mut buf)?,
                    "description" => description = read_text(reader, &mut buf)?,
                    "baseAddress" => {
                        let s = read_text(reader, &mut buf)?;
                        base_address = parse_u64(&s);
                    }
                    "registers" => {
                        registers = parse_registers(reader)?;
                        buf.clear();
                        continue;
                    }
                    "addressBlock" | "interrupt" | "headerStructName" | "groupName" => {
                        let tag_bytes = tag.as_bytes().to_vec();
                        skip_element(reader, &mut buf, &tag_bytes)?;
                    }
                    _ => {}
                }
            }
            Event::End(e) if e.name().as_ref() == b"peripheral" => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    let size = Peripheral::compute_size(&registers);

    Ok(Peripheral {
        name,
        description,
        base_address,
        size,
        registers,
        derived_from,
        priority: 100, // default priority; override in registry
    })
}

fn parse_registers(reader: &mut Reader<&[u8]>) -> Result<Vec<Register>> {
    let mut registers = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();
                if tag == "register" {
                    let reg = parse_register(reader)?;
                    registers.push(reg);
                    buf.clear();
                    continue;
                }
                // Skip cluster and other elements
                let tag_bytes = tag.as_bytes().to_vec();
                skip_element(reader, &mut buf, &tag_bytes)?;
            }
            Event::End(e) if e.name().as_ref() == b"registers" => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(registers)
}

fn parse_register(reader: &mut Reader<&[u8]>) -> Result<Register> {
    let mut name = String::new();
    let mut description = String::new();
    let mut address_offset: u64 = 0;
    let mut size: u32 = 32;
    let mut reset_value: u64 = 0;
    let mut access = Access::ReadWrite;
    let mut fields: Vec<Field> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();
                match tag.as_str() {
                    "name" => name = read_text(reader, &mut buf)?,
                    "description" => description = read_text(reader, &mut buf)?,
                    "addressOffset" => {
                        let s = read_text(reader, &mut buf)?;
                        address_offset = parse_u64(&s);
                    }
                    "size" => {
                        let s = read_text(reader, &mut buf)?;
                        size = parse_u64(&s) as u32;
                    }
                    "resetValue" => {
                        let s = read_text(reader, &mut buf)?;
                        reset_value = parse_u64(&s);
                    }
                    "access" => {
                        let s = read_text(reader, &mut buf)?;
                        access = Access::parse(&s);
                    }
                    "fields" => {
                        fields = parse_fields(reader)?;
                        buf.clear();
                        continue;
                    }
                    other => {
                        let tag_bytes = other.as_bytes().to_vec();
                        skip_element(reader, &mut buf, &tag_bytes)?;
                    }
                }
            }
            Event::End(e) if e.name().as_ref() == b"register" => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(Register {
        name,
        description,
        address_offset,
        size,
        reset_value,
        access,
        fields,
    })
}

fn parse_fields(reader: &mut Reader<&[u8]>) -> Result<Vec<Field>> {
    let mut fields = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();
                if tag == "field" {
                    let f = parse_field(reader)?;
                    fields.push(f);
                    buf.clear();
                    continue;
                }
                let tag_bytes = tag.as_bytes().to_vec();
                skip_element(reader, &mut buf, &tag_bytes)?;
            }
            Event::End(e) if e.name().as_ref() == b"fields" => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(fields)
}

fn parse_field(reader: &mut Reader<&[u8]>) -> Result<Field> {
    let mut name = String::new();
    let mut description = String::new();
    let mut bit_offset: u32 = 0;
    let mut bit_width: u32 = 1;
    let mut access: Option<Access> = None;
    let mut lsb: Option<u32> = None;
    let mut msb: Option<u32> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(e) => {
                let tag = std::str::from_utf8(e.name().as_ref())
                    .unwrap_or("")
                    .to_owned();
                match tag.as_str() {
                    "name" => name = read_text(reader, &mut buf)?,
                    "description" => description = read_text(reader, &mut buf)?,
                    "bitOffset" => {
                        let s = read_text(reader, &mut buf)?;
                        bit_offset = parse_u64(&s) as u32;
                    }
                    "bitWidth" => {
                        let s = read_text(reader, &mut buf)?;
                        bit_width = parse_u64(&s) as u32;
                    }
                    "lsb" => {
                        let s = read_text(reader, &mut buf)?;
                        lsb = Some(parse_u64(&s) as u32);
                    }
                    "msb" => {
                        let s = read_text(reader, &mut buf)?;
                        msb = Some(parse_u64(&s) as u32);
                    }
                    "access" => {
                        let s = read_text(reader, &mut buf)?;
                        access = Some(Access::parse(&s));
                    }
                    other => {
                        let tag_bytes = other.as_bytes().to_vec();
                        skip_element(reader, &mut buf, &tag_bytes)?;
                    }
                }
            }
            Event::End(e) if e.name().as_ref() == b"field" => break,
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    // Handle lsb/msb alternative notation
    if let (Some(l), Some(m)) = (lsb, msb) {
        bit_offset = l;
        bit_width = m - l + 1;
    }

    Ok(Field {
        name,
        description,
        bit_offset,
        bit_width,
        access,
    })
}

/// Parse a hex or decimal integer string.
pub fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else if let Some(stripped) = s.strip_prefix('#') {
        u64::from_str_radix(stripped, 2).unwrap_or(0)
    } else {
        s.parse::<u64>().unwrap_or(0)
    }
}

/// Resolve `derivedFrom` references: clone base peripheral's registers if derived.
fn resolve_derived_from(device: &mut Device) -> Result<()> {
    // Build name → index map
    let name_map: HashMap<String, usize> = device
        .peripherals
        .iter()
        .enumerate()
        .map(|(i, p)| (p.name.clone(), i))
        .collect();

    // Collect derived peripherals that need resolution
    let mut to_update: Vec<(usize, usize)> = Vec::new(); // (derived_idx, base_idx)
    for (i, p) in device.peripherals.iter().enumerate() {
        if let Some(ref base_name) = p.derived_from {
            if let Some(&base_idx) = name_map.get(base_name) {
                to_update.push((i, base_idx));
            }
        }
    }

    for (derived_idx, base_idx) in to_update {
        if derived_idx == base_idx {
            continue;
        }
        // Clone registers from base if derived has none
        if device.peripherals[derived_idx].registers.is_empty() {
            let base_registers = device.peripherals[base_idx].registers.clone();
            device.peripherals[derived_idx].registers = base_registers;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_SVD: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>TestMCU</name>
  <version>1.0</version>
  <description>Test device</description>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <description>Universal Asynchronous Receiver/Transmitter</description>
      <baseAddress>0x40004000</baseAddress>
      <registers>
        <register>
          <name>DR</name>
          <description>Data Register</description>
          <addressOffset>0x00</addressOffset>
          <size>32</size>
          <resetValue>0x00000000</resetValue>
          <access>read-write</access>
          <fields>
            <field>
              <name>DATA</name>
              <description>Data bits</description>
              <bitOffset>0</bitOffset>
              <bitWidth>8</bitWidth>
            </field>
          </fields>
        </register>
        <register>
          <name>SR</name>
          <description>Status Register</description>
          <addressOffset>0x04</addressOffset>
          <size>32</size>
          <resetValue>0x00000020</resetValue>
          <access>read-only</access>
        </register>
        <register>
          <name>CR1</name>
          <description>Control Register 1</description>
          <addressOffset>0x0C</addressOffset>
          <size>32</size>
          <resetValue>0x00000000</resetValue>
          <access>read-write</access>
        </register>
      </registers>
    </peripheral>
  </peripherals>
</device>"#;

    #[test]
    fn test_parse_minimal_svd() {
        let device = parse_svd_str(MINIMAL_SVD).unwrap();
        assert_eq!(device.name, "TestMCU");
        assert_eq!(device.peripherals.len(), 1);

        let uart = &device.peripherals[0];
        assert_eq!(uart.name, "UART0");
        assert_eq!(uart.base_address, 0x40004000);
        assert_eq!(uart.registers.len(), 3);
    }

    #[test]
    fn test_register_details() {
        let device = parse_svd_str(MINIMAL_SVD).unwrap();
        let uart = &device.peripherals[0];

        let dr = &uart.registers[0];
        assert_eq!(dr.name, "DR");
        assert_eq!(dr.address_offset, 0);
        assert_eq!(dr.reset_value, 0);
        assert!(matches!(dr.access, Access::ReadWrite));
        assert_eq!(dr.fields.len(), 1);
        assert_eq!(dr.fields[0].name, "DATA");
        assert_eq!(dr.fields[0].bit_width, 8);

        let sr = &uart.registers[1];
        assert_eq!(sr.name, "SR");
        assert_eq!(sr.reset_value, 0x20);
        assert!(matches!(sr.access, Access::ReadOnly));
        assert!(!sr.access.writable());
        assert!(sr.access.readable());
    }

    #[test]
    fn test_peripheral_size_computed() {
        let device = parse_svd_str(MINIMAL_SVD).unwrap();
        let uart = &device.peripherals[0];
        // Last register CR1 at offset 0x0C + 4 bytes = 0x10
        assert!(uart.size >= 0x10);
    }

    #[test]
    fn test_parse_u64() {
        assert_eq!(parse_u64("0x40004000"), 0x40004000);
        assert_eq!(parse_u64("1073758208"), 1073758208);
        assert_eq!(parse_u64("0x00"), 0);
        assert_eq!(parse_u64("0xFF"), 255);
    }

    #[test]
    fn test_field_bit_mask() {
        let f = Field {
            name: "DATA".into(),
            description: "".into(),
            bit_offset: 0,
            bit_width: 8,
            access: None,
        };
        assert_eq!(f.bit_mask(), 0xFF);

        let f2 = Field {
            name: "EN".into(),
            description: "".into(),
            bit_offset: 13,
            bit_width: 1,
            access: None,
        };
        assert_eq!(f2.bit_mask(), 1 << 13);
    }
}
