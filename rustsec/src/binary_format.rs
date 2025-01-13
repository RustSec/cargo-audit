//! A shim around `binfarce::Format` so that `binfarce` crate could be an optional dependency
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // May be unused when the "binary-scanning" feature is disabled
/// Various binary formats that influence the architecture of the binary
pub enum BinaryFormat {
    /// Executable and Linkable Format, 32-bit. Used on Unix systems.
    Elf32,
    /// Executable and Linkable Format, 64-bit. Used on Unix systems.
    Elf64,
    /// Mach object file format. Used on Apple systems.
    Macho,
    /// Portable Executable (PE) format. used on Windows.
    PE,
    /// WebAssembly
    Wasm,
    /// The format is not known
    Unknown,
}

#[cfg(feature = "binary-scanning")]
impl From<binfarce::Format> for BinaryFormat {
    fn from(value: binfarce::Format) -> Self {
        match value {
            binfarce::Format::Elf32 { byte_order: _ } => BinaryFormat::Elf32,
            binfarce::Format::Elf64 { byte_order: _ } => BinaryFormat::Elf64,
            binfarce::Format::Macho => BinaryFormat::Macho,
            binfarce::Format::PE => BinaryFormat::PE,
            binfarce::Format::Unknown => BinaryFormat::Unknown,
        }
    }
}
