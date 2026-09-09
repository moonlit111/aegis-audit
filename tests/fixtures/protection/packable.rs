//! Benign protection-mechanism fixture.
//!
//! It only proves that the UPX processing chain runs a real tool, preserves the
//! original, and records before/after evidence. It is NOT a course acceptance
//! object and cannot substitute for a real closed-source packed sample.

/// Compressible payload: the binary must be large enough for UPX to accept it.
const BLOB: [u8; 65_536] = make_blob();
const PATTERN: &[u8] = b"AegisAudit benign protection fixture line\n";

const fn make_blob() -> [u8; 65_536] {
    let mut data = [0u8; 65_536];
    let mut i = 0;
    while i < data.len() {
        data[i] = PATTERN[i % PATTERN.len()];
        i += 1;
    }
    data
}

fn checksum(data: &[u8]) -> u32 {
    let mut hash = 2_166_136_261u32;
    for &byte in data {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| "fixture".into());
    println!("{name}: {}", checksum(&BLOB));
}
