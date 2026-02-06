#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;
use sha2::{Digest, Sha256};

const LEN_PREFIX_BYTES: usize = 4;
const INPUT_CAPACITY: usize = 4096;
const MAX_MSG_LEN: usize = INPUT_CAPACITY - LEN_PREFIX_BYTES;
const DIGEST_LEN: usize = 32;
static mut INPUT_BUF: [u8; MAX_MSG_LEN] = [0u8; MAX_MSG_LEN];

unsafe extern "C" {
    static __input_start: u8;
    static __input_end: u8;
    static __halt_flag: u8;
    static __output_len: u8;
    static __output_data: u8;
    static __output_end: u8;
}

global_asm!(
    r#"
    .section .text._start
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop

    la sp, __stack_top
    call __zkvm_start
"#
);

#[unsafe(no_mangle)]
pub extern "C" fn __zkvm_start() -> ! {
    let input_start = ptr::addr_of!(__input_start) as usize;
    let input_end = ptr::addr_of!(__input_end) as usize;
    let input_size = input_end.saturating_sub(input_start);

    if input_size < LEN_PREFIX_BYTES {
        return fail_and_halt();
    }

    // Input format: [len:u32][data:len bytes]
    let requested_len = unsafe { ptr::read_volatile(input_start as *const u32) as usize };
    let max_available = input_size - LEN_PREFIX_BYTES;

    // Reject malformed length headers instead of silently truncating.
    if requested_len > max_available || requested_len > MAX_MSG_LEN {
        return fail_and_halt();
    }

    let data_len = requested_len;

    let data = unsafe {
        let buf_ptr = core::ptr::addr_of_mut!(INPUT_BUF) as *mut u8;
        let buf = core::slice::from_raw_parts_mut(buf_ptr, MAX_MSG_LEN);
        for (i, byte) in buf.iter_mut().take(data_len).enumerate() {
            let addr = input_start + LEN_PREFIX_BYTES + i;
            *byte = ptr::read_volatile(addr as *const u8);
        }
        &buf[..data_len]
    };

    let digest: [u8; DIGEST_LEN] = Sha256::digest(data).into();
    write_output_and_halt(&digest)
}

fn write_output_and_halt(data: &[u8]) -> ! {
    unsafe {
        let data_start = ptr::addr_of!(__output_data) as usize;
        let data_end = ptr::addr_of!(__output_end) as usize;
        let max_size = data_end.saturating_sub(data_start);
        if max_size < data.len() {
            return fail_and_halt();
        }

        let len_addr = ptr::addr_of!(__output_len) as *mut u32;
        ptr::write_volatile(len_addr, data.len() as u32);

        for (i, byte) in data.iter().enumerate() {
            let addr = data_start + i;
            ptr::write_volatile(addr as *mut u8, *byte);
        }
    }

    halt()
}

fn fail_and_halt() -> ! {
    unsafe {
        let len_addr = ptr::addr_of!(__output_len) as *mut u32;
        ptr::write_volatile(len_addr, 0);
    }
    halt()
}

fn halt() -> ! {
    unsafe {
        let halt_addr = ptr::addr_of!(__halt_flag) as *mut u32;
        ptr::write_volatile(halt_addr, 1);
    }
    #[allow(clippy::empty_loop)]
    loop {}
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    fail_and_halt()
}
