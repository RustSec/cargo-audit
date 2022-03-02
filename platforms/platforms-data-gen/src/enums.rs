use std::collections::BTreeSet;

use crate::rustc_target_info::RustcTargetsInfo;

pub(crate) fn enum_variant_names(key: &str, info: &RustcTargetsInfo) -> Vec<String> {
    distinct_values(key, info)
        .iter()
        .map(|v| to_enum_variant_name(v))
        .collect()
}

fn distinct_values(key: &str, info: &RustcTargetsInfo) -> BTreeSet<String> {
    info.iter().map(|t| &t[key]).cloned().collect()
}

pub(crate) fn enumify_value(key: &str, value: &str) -> String {
    format!("{}::{}", to_enum_name(key), to_enum_variant_name(value))
}

pub(crate) fn to_enum_name(key: &str) -> &'static str {
    match key {
        "target_arch" => "Arch",
        "target_os" => "OS",
        "target_env" => "Env",
        "tier" => "Tier",
        "target_endian" => "Endian",
        "target_pointer_width" => "Bits",
        _ => unreachable!("unknown enum name: {}", key),
    }
}

fn to_enum_variant_name(value: &str) -> String {
    let mut name = value.to_ascii_lowercase();
    match name.as_str() {
        // list of exceptions to `Titlecase` enum naming from `platforms` v2.0, as gathered by
        // `rg --only-matching --no-filename --no-line-number '    [A-Z0-9][A-Za-z0-9]*,' | grep -v ' [A-Z][a-z0-9]\+,'`
        // with things ending with "BSD", "OS" removed
        "aarch64" => "AArch64".to_owned(),
        "asmjs" => "AsmJs".to_owned(),
        "powerpc" => "PowerPc".to_owned(),
        "powerpc64" => "PowerPc64".to_owned(),
        "riscv" => "RiscV".to_owned(),
        "s390x" => "S390X".to_owned(),
        "thumbv6" => "ThumbV6".to_owned(),
        "thumbv7" => "ThumbV7".to_owned(),
        "uclibc" => "UClibc".to_owned(),
        "vxworks" => "VxWorks".to_owned(),
        _ => {
            // Convert to `Titlecase` as per the Rust enum value convention
            make_ascii_titlecase(&mut name);
            // Apply generalizable exceptions to `Titlecase`
            let len = name.len();
            if name.ends_with("os") {
                // exceptions in v2.0: `MacOS`, `TvOS`
                (&mut name[len-2..]).make_ascii_uppercase();
            } else if name.ends_with("bsd") {
                // exceptions in v2.0: `FreeBSD`, `NetBSD`, `OpenBSD`
                (&mut name[len-3..]).make_ascii_uppercase();
            }
            name
        }
    }
}

fn make_ascii_titlecase(s: &mut str) {
    s.make_ascii_lowercase();
    if let Some(r) = s.get_mut(0..1) {
        r.make_ascii_uppercase();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variant_naming() {
        assert_eq!(&to_enum_variant_name("foobar"), "Foobar");
        assert_eq!(&to_enum_variant_name("fooBar"), "Foobar");
        assert_eq!(&to_enum_variant_name("FOOBAR"), "Foobar");
        assert_eq!(&to_enum_variant_name("freebsd"), "FreeBSD");
        assert_eq!(&to_enum_variant_name("nonexistentbsd"), "NonexistentBSD");
        assert_eq!(&to_enum_variant_name("macos"), "MacOS");
        assert_eq!(&to_enum_variant_name("nonexistentos"), "NonexistentOS");
        assert_eq!(&to_enum_variant_name("riscv"), "RiscV");
        assert_eq!(&to_enum_variant_name("PoWeRpC"), "PowerPc");
    }
}