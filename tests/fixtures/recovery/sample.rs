//! Small benign PE for tool integration; never executed by the regression suite.
#![no_std]
#![no_main]

const MESSAGE: &[u8] = b"AegisAudit recovered test string\0";
const fn encoded() -> [u8; MESSAGE.len()] {
    let mut bytes = [0; MESSAGE.len()];
    let mut i = 0;
    while i < bytes.len() { bytes[i] = MESSAGE[i] ^ 0x5a; i += 1; }
    bytes
}
static ENCODED: [u8; MESSAGE.len()] = encoded();
static mut OUTPUT: [u8; MESSAGE.len()] = [0; MESSAGE.len()];

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OutputDebugStringA(text: *const u8);
    fn GetTickCount() -> u32;
    fn ExitProcess(code: u32) -> !;
}

#[unsafe(no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn decode_table(input: *const u8, output: *mut u8, length: usize, key: u8) {
    let mut i = 0;
    while i < length {
        unsafe { output.add(i).write(input.add(i).read() ^ key); }
        i += 1;
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn mba_add(a: u32, b: u32) -> u32 {
    (a ^ b).wrapping_add((a & b).wrapping_mul(2))
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn mba_add64(a: u64, b: u64) -> u64 {
    (a ^ b).wrapping_add((a & b).wrapping_mul(2))
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn mainCRTStartup() -> ! {
    unsafe {
        decode_table(ENCODED.as_ptr(), core::ptr::addr_of_mut!(OUTPUT).cast(), MESSAGE.len(), 0x5a);
        OutputDebugStringA(core::ptr::addr_of!(OUTPUT).cast());
        ExitProcess(mba_add(GetTickCount(), 7).wrapping_add(mba_add64(GetTickCount() as u64, 9) as u32));
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! { loop { core::hint::spin_loop(); } }
