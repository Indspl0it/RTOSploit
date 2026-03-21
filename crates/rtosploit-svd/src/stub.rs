//! QEMU peripheral C stub code generator.
//!
//! Generates minimal C source files compatible with QEMU's device model API.
//! Three modes: reset-value (simplest), read-write (stateful), fuzzer-driven.

use crate::parser::Peripheral;
use std::fmt::Write as FmtWrite;

/// Stub generation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubMode {
    /// Every register read returns its reset value; writes are ignored.
    ResetValue,
    /// Registers are backed by memory; reads return last written value.
    ReadWrite,
    /// Reads consume bytes from fuzzer input buffer.
    FuzzerDriven,
}

impl StubMode {
    pub fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "reset-value" | "reset_value" | "resetvalue" => StubMode::ResetValue,
            "read-write" | "read_write" | "readwrite" => StubMode::ReadWrite,
            "fuzzer-driven" | "fuzzer_driven" | "fuzzerdriven" => StubMode::FuzzerDriven,
            _ => StubMode::ResetValue,
        }
    }
}

/// Generate a QEMU peripheral stub C source file for one peripheral.
pub fn generate_peripheral_stub(peripheral: &Peripheral, mode: StubMode) -> String {
    let mut out = String::new();
    let pname = sanitize_name(&peripheral.name);
    let pname_upper = pname.to_uppercase();
    let pname_lower = pname.to_lowercase();

    // File header
    writeln!(out, "/*").unwrap();
    writeln!(out, " * RTOSploit-generated QEMU peripheral stub").unwrap();
    writeln!(out, " * Peripheral: {}", peripheral.name).unwrap();
    writeln!(
        out,
        " * Base: 0x{:08x}  Size: 0x{:x}",
        peripheral.base_address, peripheral.size
    )
    .unwrap();
    writeln!(out, " * Mode: {:?}", mode).unwrap();
    writeln!(out, " * AUTO-GENERATED — DO NOT EDIT MANUALLY").unwrap();
    writeln!(out, " */").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "#include \"qemu/osdep.h\"").unwrap();
    writeln!(out, "#include \"hw/sysbus.h\"").unwrap();
    writeln!(out, "#include \"hw/registerfields.h\"").unwrap();
    writeln!(out, "#include \"qemu/log.h\"").unwrap();
    writeln!(out).unwrap();

    // Type names
    let type_name = format!("TYPE_RTOSPLOIT_{}", pname_upper);
    let state_name = format!("RTOSploit{}State", pname);
    writeln!(out, "#define {} \"rtosploit-{}\"", type_name, pname_lower).unwrap();
    writeln!(
        out,
        "OBJECT_DECLARE_SIMPLE_TYPE({}, RTOSploit{})",
        state_name, pname
    )
    .unwrap();
    writeln!(out).unwrap();

    // State struct
    writeln!(out, "struct {} {{", state_name).unwrap();
    writeln!(out, "    SysBusDevice parent_obj;").unwrap();
    writeln!(out, "    MemoryRegion mmio;").unwrap();

    match mode {
        StubMode::ReadWrite | StubMode::FuzzerDriven => {
            // One uint32_t field per register
            for reg in &peripheral.registers {
                let rname = sanitize_name(&reg.name).to_lowercase();
                writeln!(
                    out,
                    "    uint32_t reg_{};  /* offset 0x{:x}, reset 0x{:x} */",
                    rname, reg.address_offset, reg.reset_value
                )
                .unwrap();
            }
            if matches!(mode, StubMode::FuzzerDriven) {
                writeln!(
                    out,
                    "    /* fuzzer input buffer pointer (set externally) */"
                )
                .unwrap();
                writeln!(out, "    uint8_t *fuzz_buf;").unwrap();
                writeln!(out, "    size_t fuzz_buf_pos;").unwrap();
                writeln!(out, "    size_t fuzz_buf_len;").unwrap();
            }
        }
        StubMode::ResetValue => {
            // No storage needed — reads return constants
            writeln!(out, "    /* reset-value mode: no register storage */").unwrap();
        }
    }
    writeln!(out, "}};").unwrap();
    writeln!(out).unwrap();

    // Read handler
    writeln!(
        out,
        "static uint64_t {}_read(void *opaque, hwaddr addr, unsigned size)",
        pname_lower
    )
    .unwrap();
    writeln!(out, "{{").unwrap();

    match mode {
        StubMode::ResetValue => {
            writeln!(out, "    switch (addr) {{").unwrap();
            for reg in &peripheral.registers {
                if reg.access.readable() {
                    writeln!(
                        out,
                        "    case 0x{:x}: /* {} */ return 0x{:x};",
                        reg.address_offset, reg.name, reg.reset_value
                    )
                    .unwrap();
                }
            }
            writeln!(out, "    default:").unwrap();
            writeln!(out, "        qemu_log_mask(LOG_UNIMP,").unwrap();
            writeln!(
                out,
                "            \"{}: unimplemented read at offset 0x%\" HWADDR_PRIx \"\\n\",",
                peripheral.name
            )
            .unwrap();
            writeln!(out, "            addr);").unwrap();
            writeln!(out, "        return 0;").unwrap();
            writeln!(out, "    }}").unwrap();
        }
        StubMode::ReadWrite => {
            writeln!(out, "    {} *s = opaque;", state_name).unwrap();
            writeln!(out, "    switch (addr) {{").unwrap();
            for reg in &peripheral.registers {
                if reg.access.readable() {
                    let rname = sanitize_name(&reg.name).to_lowercase();
                    writeln!(
                        out,
                        "    case 0x{:x}: return s->reg_{};",
                        reg.address_offset, rname
                    )
                    .unwrap();
                }
            }
            writeln!(out, "    default:").unwrap();
            writeln!(out, "        qemu_log_mask(LOG_UNIMP,").unwrap();
            writeln!(
                out,
                "            \"{}: unimplemented read at 0x%\" HWADDR_PRIx \"\\n\",",
                peripheral.name
            )
            .unwrap();
            writeln!(out, "            addr);").unwrap();
            writeln!(out, "        return 0;").unwrap();
            writeln!(out, "    }}").unwrap();
        }
        StubMode::FuzzerDriven => {
            writeln!(out, "    {} *s = opaque;", state_name).unwrap();
            writeln!(
                out,
                "    /* fuzzer-driven: consume bytes from fuzz input */"
            )
            .unwrap();
            writeln!(out, "    uint32_t val = 0;").unwrap();
            writeln!(
                out,
                "    if (s->fuzz_buf && s->fuzz_buf_pos + 4 <= s->fuzz_buf_len) {{"
            )
            .unwrap();
            writeln!(
                out,
                "        memcpy(&val, s->fuzz_buf + s->fuzz_buf_pos, 4);"
            )
            .unwrap();
            writeln!(out, "        s->fuzz_buf_pos += 4;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "    (void)addr;  /* address ignored in fuzzer mode */").unwrap();
            writeln!(out, "    return val;").unwrap();
        }
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Write handler
    writeln!(
        out,
        "static void {}_write(void *opaque, hwaddr addr, uint64_t val, unsigned size)",
        pname_lower
    )
    .unwrap();
    writeln!(out, "{{").unwrap();

    match mode {
        StubMode::ResetValue | StubMode::FuzzerDriven => {
            writeln!(out, "    /* writes silently accepted */").unwrap();
            writeln!(out, "    qemu_log_mask(LOG_UNIMP,").unwrap();
            writeln!(
                out,
                "        \"{}: write 0x%\" PRIx64 \" at 0x%\" HWADDR_PRIx \"\\n\",",
                peripheral.name
            )
            .unwrap();
            writeln!(out, "        val, addr);").unwrap();
        }
        StubMode::ReadWrite => {
            writeln!(out, "    {} *s = opaque;", state_name).unwrap();
            writeln!(out, "    switch (addr) {{").unwrap();
            for reg in &peripheral.registers {
                if reg.access.writable() {
                    let rname = sanitize_name(&reg.name).to_lowercase();
                    writeln!(
                        out,
                        "    case 0x{:x}: s->reg_{} = (uint32_t)val; break;",
                        reg.address_offset, rname
                    )
                    .unwrap();
                }
            }
            writeln!(out, "    default:").unwrap();
            writeln!(out, "        qemu_log_mask(LOG_UNIMP,").unwrap();
            writeln!(
                out,
                "            \"{}: unimplemented write at 0x%\" HWADDR_PRIx \"\\n\",",
                peripheral.name
            )
            .unwrap();
            writeln!(out, "            addr);").unwrap();
            writeln!(out, "    }}").unwrap();
        }
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // MemoryRegionOps
    writeln!(out, "static const MemoryRegionOps {}_ops = {{", pname_lower).unwrap();
    writeln!(out, "    .read = {}_read,", pname_lower).unwrap();
    writeln!(out, "    .write = {}_write,", pname_lower).unwrap();
    writeln!(out, "    .endianness = DEVICE_LITTLE_ENDIAN,").unwrap();
    writeln!(out, "    .valid.min_access_size = 4,").unwrap();
    writeln!(out, "    .valid.max_access_size = 4,").unwrap();
    writeln!(out, "}};").unwrap();
    writeln!(out).unwrap();

    // Reset function
    writeln!(out, "static void {}_reset(DeviceState *dev)", pname_lower).unwrap();
    writeln!(out, "{{").unwrap();
    match mode {
        StubMode::ReadWrite => {
            writeln!(out, "    {} *s = RTOSploit{}(dev);", state_name, pname).unwrap();
            for reg in &peripheral.registers {
                let rname = sanitize_name(&reg.name).to_lowercase();
                writeln!(
                    out,
                    "    s->reg_{} = 0x{:x};  /* {} reset value */",
                    rname, reg.reset_value, reg.name
                )
                .unwrap();
            }
        }
        _ => {
            writeln!(out, "    /* no state to reset */").unwrap();
        }
    }
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Realize function
    writeln!(
        out,
        "static void {}_realize(DeviceState *dev, Error **errp)",
        pname_lower
    )
    .unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    {} *s = RTOSploit{}(dev);", state_name, pname).unwrap();
    writeln!(
        out,
        "    memory_region_init_io(&s->mmio, OBJECT(s), &{}_ops, s,",
        pname_lower
    )
    .unwrap();
    writeln!(
        out,
        "        \"{}\", 0x{:x});",
        peripheral.name,
        peripheral.size.max(0x400)
    )
    .unwrap();
    writeln!(out, "    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // class_init and type_init
    writeln!(
        out,
        "static void {}_class_init(ObjectClass *klass, void *data)",
        pname_lower
    )
    .unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    DeviceClass *dc = DEVICE_CLASS(klass);").unwrap();
    writeln!(out, "    dc->realize = {}_realize;", pname_lower).unwrap();
    writeln!(out, "    dc->reset = {}_reset;", pname_lower).unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "static const TypeInfo {}_info = {{", pname_lower).unwrap();
    writeln!(out, "    .name = {},", type_name).unwrap();
    writeln!(out, "    .parent = TYPE_SYS_BUS_DEVICE,").unwrap();
    writeln!(out, "    .instance_size = sizeof({}),", state_name).unwrap();
    writeln!(out, "    .class_init = {}_class_init,", pname_lower).unwrap();
    writeln!(out, "}};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "static void {}_register_types(void)", pname_lower).unwrap();
    writeln!(out, "{{").unwrap();
    writeln!(out, "    type_register_static(&{}_info);", pname_lower).unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "type_init({}_register_types)", pname_lower).unwrap();

    out
}

/// Generate stubs for multiple peripherals and return (filename, content) pairs.
pub fn generate_all_stubs(
    peripherals: &[Peripheral],
    mcu_name: &str,
    mode: StubMode,
) -> Vec<(String, String)> {
    peripherals
        .iter()
        .map(|p| {
            let filename = format!(
                "{}_{}.c",
                mcu_name.to_lowercase(),
                sanitize_name(&p.name).to_lowercase()
            );
            let content = generate_peripheral_stub(p, mode);
            (filename, content)
        })
        .collect()
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Access, Register};

    fn make_uart() -> Peripheral {
        Peripheral {
            name: "UART0".to_string(),
            description: "Test UART".to_string(),
            base_address: 0x40004000,
            size: 0x1000,
            registers: vec![
                Register {
                    name: "DR".to_string(),
                    description: "Data".to_string(),
                    address_offset: 0,
                    size: 32,
                    reset_value: 0,
                    access: Access::ReadWrite,
                    fields: vec![],
                },
                Register {
                    name: "SR".to_string(),
                    description: "Status".to_string(),
                    address_offset: 4,
                    size: 32,
                    reset_value: 0x20,
                    access: Access::ReadOnly,
                    fields: vec![],
                },
            ],
            derived_from: None,
            priority: 1,
        }
    }

    #[test]
    fn test_reset_value_stub_contains_case() {
        let uart = make_uart();
        let stub = generate_peripheral_stub(&uart, StubMode::ResetValue);
        assert!(
            stub.contains("case 0x0:"),
            "Should have case for DR at offset 0"
        );
        assert!(stub.contains("0x20"), "SR reset value 0x20 should appear");
        assert!(stub.contains("UART0"));
    }

    #[test]
    fn test_read_write_stub_has_state() {
        let uart = make_uart();
        let stub = generate_peripheral_stub(&uart, StubMode::ReadWrite);
        assert!(stub.contains("reg_dr"), "Should have reg_dr field");
        assert!(stub.contains("reg_sr"), "Should have reg_sr field");
        assert!(
            stub.contains("s->reg_dr"),
            "Should access via state pointer"
        );
    }

    #[test]
    fn test_fuzzer_stub_has_fuzz_buf() {
        let uart = make_uart();
        let stub = generate_peripheral_stub(&uart, StubMode::FuzzerDriven);
        assert!(stub.contains("fuzz_buf"));
        assert!(stub.contains("fuzz_buf_pos"));
    }

    #[test]
    fn test_stub_mode_from_str() {
        assert_eq!(StubMode::from_str("reset-value"), StubMode::ResetValue);
        assert_eq!(StubMode::from_str("read-write"), StubMode::ReadWrite);
        assert_eq!(StubMode::from_str("fuzzer-driven"), StubMode::FuzzerDriven);
        assert_eq!(StubMode::from_str("invalid"), StubMode::ResetValue); // default
    }

    #[test]
    fn test_read_only_register_not_in_write_handler() {
        let uart = make_uart();
        let stub = generate_peripheral_stub(&uart, StubMode::ReadWrite);
        // SR is read-only, should not appear in write handler switch
        // The write handler should have case 0x0 (DR) but not case 0x4 (SR)
        let write_section = stub.split("_write").nth(1).unwrap_or("");
        assert!(
            !write_section.contains("case 0x4:"),
            "Read-only SR should not be in write handler"
        );
    }
}
