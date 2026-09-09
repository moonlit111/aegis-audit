//! Benign deobfuscation-mechanism fixture.
//!
//! It only proves that the B06 recovery chain finds and decodes a single-byte
//! XOR string table, a repeating-key XOR table and a base64 text table. It is
//! NOT a course acceptance object and cannot substitute for a real obfuscated
//! sample.
//!
//! Built with scalar loops (`-C no-vectorize-loops -C no-vectorize-slp`) so the
//! decode pattern stays visible to instruction/P-code analysis.

const KEY: u8 = 0x5A;
const PLAIN: &str = "AegisAudit deobfuscation fixture string table. This benign payload only proves the static recovery mechanism. It is not a course acceptance case. The hidden message mentions a connection string and password handling so the recovered text is meaningful to an auditor.";
const OBFUSCATED: [u8; PLAIN.len()] = encode();

const RK_KEY: [u8; 4] = [0x37, 0x13, 0x9B, 0x42];
const RK_PLAIN: &str = "AegisAudit repeating key fixture. This table is long enough that a full window lies inside it, so the recovery step can derive the repeating key from column frequency. connection host=beacon.example.invalid port=4444 user=operator password=fixture-only token=not-a-real-secret fallback server=backup.example.invalid port=5555 user=service password=also-fixture-only retry interval=30 timeout=15 message=the hidden configuration is only meaningful to an auditor and not a real credential at all";
const RK_OBFUSCATED: [u8; RK_PLAIN.len()] = encode_repeating();

const BASE64_TABLE: &str = "QWVnaXNBdWRpdCBiYXNlNjQgZml4dHVyZSBzdHJpbmcgdGFibGUuIGhvc3Q9ZGIuaW50ZXJuYWwgcG9ydD01NDMyIHVzZXI9YXVkaXQgcGFzc3dvcmQ9Zml4dHVyZS1vbmx5";

const fn encode() -> [u8; PLAIN.len()] {
    let bytes = PLAIN.as_bytes();
    let mut out = [0u8; PLAIN.len()];
    let mut index = 0;
    while index < bytes.len() {
        out[index] = bytes[index] ^ KEY;
        index += 1;
    }
    out
}

const fn encode_repeating() -> [u8; RK_PLAIN.len()] {
    let bytes = RK_PLAIN.as_bytes();
    let mut out = [0u8; RK_PLAIN.len()];
    let mut index = 0;
    while index < bytes.len() {
        out[index] = bytes[index] ^ RK_KEY[index % RK_KEY.len()];
        index += 1;
    }
    out
}

#[inline(never)]
fn decode_repeating(input: &[u8], key: &[u8], out: &mut [u8]) {
    for (index, &byte) in input.iter().enumerate() {
        out[index] = byte ^ key[index % key.len()];
    }
}

fn main() {
    // Single-byte XOR stays inline with a constant table base and an opaque length:
    // the compiler cannot unroll or constant-fold it away, and instruction/P-code
    // analysis can trace the load back to the .rdata table address.
    let source: &[u8] = &OBFUSCATED;
    let length = std::hint::black_box(source.len());
    let mut buffer = vec![0u8; length];
    let mut index = 0;
    while index < length {
        buffer[index] = source[index] ^ KEY;
        index += 1;
    }
    let text = String::from_utf8_lossy(&buffer);
    println!("{}", &text[..text.len().min(40)]);

    let mut repeating = vec![0u8; RK_OBFUSCATED.len()];
    decode_repeating(&RK_OBFUSCATED, &RK_KEY, &mut repeating);
    let text = String::from_utf8_lossy(&repeating);
    println!("{}", &text[..text.len().min(40)]);

    // Touch the table content so the base64 payload stays in the binary.
    println!("{}", &BASE64_TABLE[..16]);
}
